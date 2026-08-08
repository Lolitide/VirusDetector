import { defineConfig } from 'wxt';
import { fileURLToPath } from 'node:url';

// wxt configuration for Virus Detector.
//
// 源码布局（尽量保持与原始仓库接近，以减少干扰）：
// - src/entrypoints/ wxt 入口点(background, content scripts, popup,
//options, warning/download-confirm HTML pages)
// - public/ 静态资源复制到扩展根目录 (icons, _locales)
// - background/ service-worker + scoring/analysis modules（未更改）
// - utils/ 共享常量/辅助函数（未更改）
// - content/ content-script （未更改）
// - worker/ Cloudflare Worker 用于报告采集（未更改）
// - tests/ node: 测试套件（导入路径未更改）
//
// 跨文件夹导入使用下面的别名，以便原始目录布局
// 能保持在仓库根目录。

// 当git tag（例如 `v2.5.3`）触发构建时，从中派生扩展版本，
// 这样每次商店上传都会使用最新、单调递增的版本（商店拒绝重新上传已有版本）。
// 在本地构建时回退到硬编码的基线。
// version (商店会拒绝重新上传已存在的版本)。在本地构建时会回退到硬编码的基线。
const tagVersion = (process.env.GITHUB_REF_NAME || '').replace(/^v/, '');
const extensionVersion = /^\d+\.\d+\.\d+$/.test(tagVersion) ? tagVersion : '2.5.2';

export default defineConfig({
  srcDir: 'src',

  alias: {
    '@background': fileURLToPath(new URL('./background', import.meta.url)),
    '@utils': fileURLToPath(new URL('./utils', import.meta.url)),
    '@content': fileURLToPath(new URL('./content', import.meta.url)),
  },

  // 清理 MV3 构建；
  mode: 'production',

  manifest: {
    name: '银狐木马检测 - Virus Detector',
    version: extensionVersion,
    version_name: extensionVersion,
    default_locale: 'zh_CN',
    description:
      '检测银狐木马钓鱼网站，通过域名分析、ICP备案检查、下载检测、链接分析和代码工程化检测保护您的数字安全',

    permissions: [
      'activeTab',
      'storage',
      'downloads',
      'scripting',
      'alarms',
      'notifications',
      'webNavigation',
    ],
    host_permissions: ['http://*/*', 'https://*/*'],

    icons: {
      16: 'icons/icon16.png',
      32: 'icons/icon32.png',
      48: 'icons/icon48.png',
      128: 'icons/icon128.png',
    },

    action: {
      default_icon: {
        16: 'icons/icon16.png',
        32: 'icons/icon32.png',
        48: 'icons/icon48.png',
        128: 'icons/icon128.png',
      },
    },

    // wxt 会自动为 HTML 入口点生成 web_accessible_resources，但我们
    // 明确声明它们，以确保通过 chrome.runtime.getURL(...) 打开的警告/下载确认页面
    // 在任何页面都可以访问
    web_accessible_resources: [
      {
        resources: ['warning.html', 'download-confirm.html'],
        matches: ['http://*/*', 'https://*/*'],
      },
    ],

    browser_specific_settings: {
      gecko: {
        id: 'virus-detector@example.com',
        strict_min_version: '140.0',
        data_collection_permissions: {
          required: ['none'],
          optional: ['technicalAndInteraction'],
        },
      },
    },
  },
});
