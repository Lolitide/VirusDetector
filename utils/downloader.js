/**
 * Virus Detector — 下载器调度模块
 *
 *   - native  : 浏览器原生下载  → chrome.downloads.download
 *   - thunder : 迅雷            → 构造 thunder:// 协议 URL，唤起本地迅雷
 *
 * @module downloader
 */
/**
 * 将普通 http/https URL 编码为迅雷 thunder:// 协议 URL
 * 编码规则：Base64( "AA" + 原始URL + "ZZ" )，按 UTF-8 字节编码
 * @param {string} url
 * @returns {string} 形如 thunder://QUFodHRw...Wg==
 */
export function toThunderUrl(url) {
  const wrapped = "AA" + url + "ZZ";
  const bytes = new TextEncoder().encode(wrapped);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return "thunder://" + base64;
}

/**
 * 浏览器原生下载
 * @param {{url:string, filename?:string, saveAs?:boolean}} opts
 */
async function nativeDownload(opts) {
  await chrome.downloads.download({
    url: opts.url,
    filename: opts.filename || undefined,
    saveAs: opts.saveAs || false
  });
  return { engine: 'native', ok: true, url: opts.url };
}

/**
 * 迅雷下载：通过 thunder:// 协议唤起本地迅雷。
 *
 * 浏览器不能直接调用外部程序，因此用 chrome.tabs.create 打开 thunder:// URL，
 * 触发操作系统协议处理器启动迅雷；随后关闭这个占位标签页。
 * 若迅雷未安装，Chrome 会提示无法打开该协议，占位标签页可安全关闭。
 *
 */
async function thunderDownload(opts) {
  const thunderUrl = toThunderUrl(opts.url);

  if (chrome.tabs && typeof chrome.tabs.create === 'function') {
    const tab = await chrome.tabs
      .create({ url: thunderUrl, active: false })
      .catch(() => null);
    if (tab && tab.id) {
      chrome.tabs.remove(tab.id).catch(() => {});
    }
  }
  return { engine: 'thunder', ok: true, thunderUrl };
}

/**
 * 统一入口：按分发一次下载
 * @param {string} engine - 'native' | 'thunder'
 * @param {{url:string, filename?:string, referrer?:string, userAgent?:string, saveAs?:boolean}} opts
 * @returns {Promise<{engine:string, ok:boolean, [key:string]:any}>}
 */
export async function downloadWithEngine(engine, opts) {
  switch (engine) {
    case 'thunder':
      return thunderDownload(opts);
    default:
      return nativeDownload(opts);
  }
}
