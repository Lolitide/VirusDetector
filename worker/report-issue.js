/**
 * Virus Detector — 用户上报 → GitHub Issue 代理 + 版本查询代理
 *
 * Cloudflare Worker：
 *   1. 接收扩展的用户上报请求，代理创建 GitHub Issue。
 *   2. 代理查询 GitHub 最新 Release，供扩展做更新检测。
 * GitHub PAT 仅存储在 Worker 环境变量中，不进入扩展代码。
 *
 * 部署方式：
 *   1. npm install -g wrangler
 *   2. wrangler secret put GITHUB_TOKEN   # 填入 GitHub PAT（需要 repo scope）
 *   3. wrangler deploy
 *
 * API：
 *   POST /api/report
 *   Content-Type: application/json
 *   Body: { reportType, domain, score, version, timestamp, note, ruleResults, url }
 *   Response: { success: true, issueUrl: "https://github.com/.../issues/123" }
 *
 *   GET /api/version
 *   Response: { version, releaseUrl, releaseNotes, publishedAt, checkedAt }
 *   说明：边缘缓存 1 小时 + ETag 条件请求，规避 api.github.com 按来源 IP
 *         60次/小时 的未认证限额（扩展用户常处于共享出口 IP 下，直连极易 403）。
 *
 * @module report-issue
 */

// ---- 配置 ----
const GITHUB_REPO_OWNER = 'Lolitide';
const GITHUB_REPO_NAME = 'VirusDetector';
const GITHUB_RELEASES_API = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/releases/latest`;

// /api/version 边缘缓存：固定 key + 1 小时 TTL（上游请求量与用户规模无关）
const VERSION_CACHE_KEY = 'https://virus-detector.internal/cache/api-version';
const VERSION_CACHE_TTL_MS = 60 * 60 * 1000;

// ---- Label 映射 ----
const LABEL_MAP = {
  'false_positive': ['false-positive', '用户上报'],
  'confirmed_phish': ['confirmed-phish', '用户上报']
};

// ---- 环境变量校验 ----
function getGitHubToken() {
  const token = globalThis.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN 环境变量未设置。请运行: wrangler secret put GITHUB_TOKEN');
  }
  return token;
}

// ---- CORS 预检 ----
function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400'
    }
  });
}

// ---- GET /api/version：最新 Release 版本信息 ----

/** 构造版本信息响应；stale=true 表示这是上游失败后的过期缓存兜底 */
function versionResponse(body, stale) {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
      ...(stale ? { 'x-stale': '1' } : {})
    }
  });
}

function versionErrorResponse(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/** 写入边缘缓存（记录抓取时间与 GitHub ETag）并返回响应 */
function cacheAndRespond(ctx, cache, body, etag) {
  // 注意：存入 Cache API 的响应不能带 Cache-Control: no-store（Cloudflare 会拒绝写入），
  // 因此缓存副本与返回给客户端的响应分别构造。
  const cacheHeaders = {
    'Content-Type': 'application/json',
    'x-cached-at': String(Date.now())
  };
  if (etag) cacheHeaders['x-gh-etag'] = etag;
  ctx.waitUntil(cache.put(VERSION_CACHE_KEY, new Response(body, { status: 200, headers: cacheHeaders })));

  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store'
    }
  });
}

/**
 * GET /api/version — 返回最新 Release 的归一化版本信息。
 *
 * 稳定性设计：
 * - 边缘缓存 1 小时：GitHub 上游请求量与用户规模无关
 * - ETag 条件请求：内容未变时 GitHub 返回 304，不占用速率限额
 * - 上游失败时回退到过期缓存（stale）：宁可返回稍旧的数据也不报错
 * - 若配置了 GITHUB_TOKEN 则带认证请求（5000次/小时），无 token 也可工作
 */
async function handleVersion(ctx) {
  const cache = caches.default;

  // 读取缓存（body 只能消费一次，先取出文本与元数据）
  let cachedBody = null;
  let cachedEtag = null;
  let cachedAt = 0;
  const cached = await cache.match(VERSION_CACHE_KEY);
  if (cached) {
    cachedBody = await cached.text();
    cachedEtag = cached.headers.get('x-gh-etag') || null;
    cachedAt = Number(cached.headers.get('x-cached-at') || 0);
    if (Date.now() - cachedAt < VERSION_CACHE_TTL_MS) {
      return versionResponse(cachedBody, false);
    }
  }

  // 缓存过期或不存在，刷新上游
  const headers = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'VirusDetector-Version-Check/1.0'
  };
  const token = globalThis.GITHUB_TOKEN;
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (cachedEtag) headers['If-None-Match'] = cachedEtag;

  let resp;
  try {
    resp = await fetch(GITHUB_RELEASES_API, { headers });
  } catch (e) {
    console.error(`[Version] GitHub 请求异常: ${e.message}`);
    if (cachedBody) return versionResponse(cachedBody, true);
    return versionErrorResponse(502, `GitHub 请求失败: ${e.message}`);
  }

  // 内容未变：仅刷新缓存时间戳
  if (resp.status === 304 && cachedBody) {
    return cacheAndRespond(ctx, cache, cachedBody, cachedEtag);
  }

  if (!resp.ok) {
    console.error(`[Version] GitHub 返回 ${resp.status}`);
    if (cachedBody) return versionResponse(cachedBody, true);
    return versionErrorResponse(502, `GitHub API 返回 ${resp.status}`);
  }

  try {
    const release = await resp.json();
    const version = String(release.tag_name || '').replace(/^v/i, '');
    if (!version) throw new Error('Release 缺少 tag_name');
    const body = JSON.stringify({
      version,
      releaseUrl: release.html_url || `https://github.com/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/releases`,
      releaseNotes: String(release.body || '').substring(0, 2000),
      publishedAt: release.published_at || null,
      checkedAt: new Date().toISOString()
    });
    return cacheAndRespond(ctx, cache, body, resp.headers.get('ETag'));
  } catch (e) {
    console.error(`[Version] Release 数据解析失败: ${e.message}`);
    if (cachedBody) return versionResponse(cachedBody, true);
    return versionErrorResponse(502, `Release 数据解析失败: ${e.message}`);
  }
}

// ---- 域名校验 ----
function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  // 基本域名格式校验
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(domain);
}

// ---- 构建 Issue 标题 ----
function buildTitle(reportType, domain) {
  const prefix = reportType === 'false_positive' ? '[误报]' : '[确认钓鱼]';
  return `${prefix} ${domain}`;
}

// ---- 构建 Issue Body ----
function buildBody(data) {
  const {
    reportType, domain, score, version, timestamp, note, ruleResults, url
  } = data;

  const typeLabel = reportType === 'false_positive' ? '误报' : '确认钓鱼';
  const timeStr = timestamp
    ? new Date(timestamp).toISOString().replace('T', ' ').substring(0, 19)
    : '未知';

  let body = '## 上报信息\n\n';
  body += `| 字段 | 值 |\n|------|----|\n`;
  body += `| 类型 | ${typeLabel} |\n`;
  body += `| 域名 | \`${domain}\` |\n`;
  if (url) body += `| 页面URL | ${url} |\n`;
  body += `| 风险评分 | ${score ?? '未知'} |\n`;
  body += `| 版本 | ${version ?? '未知'} |\n`;
  body += `| 时间 | ${timeStr} |\n`;

  // 检测详情
  if (ruleResults) {
    body += '\n## 检测详情\n\n';
    body += '| 规则 | 结果 | 得分 |\n|------|------|------|\n';
    const ruleNames = {
      rule1: '域名仿冒', rule2: '下载检测', rule3: 'ICP备案',
      rule4: '链接分析', rule5: '代码工程化',
      domainAge: '域名年龄', ageBonus: '域名减分', downloadLink: '下载链接'
    };
    for (const [key, label] of Object.entries(ruleNames)) {
      const rule = ruleResults[key];
      if (!rule) continue;
      const result = rule.detailCN || rule.detail || '-';
      const score = rule.score != null ? (rule.score > 0 ? `+${rule.score}` : rule.score) : '-';
      body += `| ${label} | ${result} | ${score} |\n`;
    }
  }

  // 用户备注
  if (note) {
    body += `\n## 用户备注\n\n${note}\n`;
  }

  body += `\n---\n`;
  body += `<sub>🤖 由 Virus Detector 扩展自动上报 | v${version || '?'}</sub>\n`;

  return body;
}

// ---- 调用 GitHub Issues API ----
async function createGitHubIssue(token, title, body, labels) {
  const url = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/issues`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'VirusDetector-Report-Bot/1.0'
    },
    body: JSON.stringify({
      title,
      body,
      labels
    })
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(`GitHub API 返回 ${response.status}: ${errorBody.substring(0, 200)}`);
  }

  const issue = await response.json();
  return issue.html_url;
}

// ---- 主处理 ----
async function handleReport(request) {
  // 仅接受 POST
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ success: false, error: '仅支持 POST 请求' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  // 解析 body
  let data;
  try {
    data = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: '请求 body 格式错误，需要 JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  // 校验必填字段
  const { reportType, domain } = data;
  if (!reportType || !['false_positive', 'confirmed_phish'].includes(reportType)) {
    return new Response(JSON.stringify({ success: false, error: 'reportType 无效' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
  if (!isValidDomain(domain)) {
    return new Response(JSON.stringify({ success: false, error: 'domain 无效' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  // 限制 body 大小（防止滥用）
  if (request.headers.get('content-length')) {
    const len = parseInt(request.headers.get('content-length'));
    if (len > 50000) {
      return new Response(JSON.stringify({ success: false, error: '请求过大' }), {
        status: 413,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }

  try {
    const token = getGitHubToken();
    const title = buildTitle(reportType, domain);
    const body = buildBody(data);
    const labels = LABEL_MAP[reportType] || ['用户上报'];

    console.log(`[Report] 创建 Issue: ${title}`);
    const issueUrl = await createGitHubIssue(token, title, body, labels);
    console.log(`[Report] 成功: ${issueUrl}`);

    return new Response(JSON.stringify({ success: true, issueUrl }), {
      status: 201,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  } catch (e) {
    console.error(`[Report] 失败: ${e.message}`);
    return new Response(JSON.stringify({ success: false, error: e.message }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

// ---- Worker 入口 ----
export default {
  async fetch(request, env, ctx) {
    // 注入环境变量到全局
    globalThis.GITHUB_TOKEN = env.GITHUB_TOKEN;

    const url = new URL(request.url);

    // CORS 预检
    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    // 路由
    if (url.pathname === '/api/report') {
      return handleReport(request);
    }
    if (url.pathname === '/api/version') {
      if (request.method !== 'GET') {
        return versionErrorResponse(405, '仅支持 GET 请求');
      }
      return handleVersion(ctx);
    }

    // 404
    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
};
