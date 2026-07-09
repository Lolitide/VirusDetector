/**
 * Virus Detector — 用户上报 → GitHub Issue 代理
 *
 * Cloudflare Worker：接收扩展的用户上报请求，代理创建 GitHub Issue。
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
 * @module report-issue
 */

// ---- 配置 ----
const GITHUB_REPO_OWNER = 'Lolitide';
const GITHUB_REPO_NAME = 'VirusDetector';

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
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400'
    }
  });
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

    // 404
    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
};
