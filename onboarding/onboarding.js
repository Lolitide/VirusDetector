/**
 * 首次安装配置页控制器。
 * 负责加载和保存常用设置、同步主题、展开详细配置并展示版本检查结果。
 * @module onboarding
 */

import {
  SETTINGS_DEFAULTS,
  SENSITIVITY_PRESETS,
  SCHEMA_VERSION,
  validateSetting
} from '../utils/settings-schema.js';
import { STORAGE_KEYS, MSG_TYPES, UPDATE_CHANNEL } from '../utils/constants.js';

let settings = { ...SETTINGS_DEFAULTS };
let latestReleaseUrl = '';
const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');

/** 应用扩展当前主题，并更新首屏主题缓存。 */
function applyTheme() {
  const selected = settings.theme || SETTINGS_DEFAULTS.theme;
  const resolved = selected === 'auto'
    ? (systemTheme.matches ? 'dark' : 'light')
    : selected;

  document.documentElement.dataset.theme = resolved;
  try {
    localStorage.setItem('vt_theme', selected);
  } catch (error) {
    console.debug('[Onboarding] 无法缓存主题:', error);
  }
}

/** 将内存设置同步到页面控件。 */
function syncControls() {
  document.querySelectorAll('input[data-key]').forEach((input) => {
    input.checked = settings[input.dataset.key] !== false;
  });

  const preset = settings.sensitivityPreset || SETTINGS_DEFAULTS.sensitivityPreset;
  document.querySelectorAll('[data-preset]').forEach((button) => {
    const active = button.dataset.preset === preset;
    button.setAttribute('aria-checked', String(active));
  });

  const description = document.getElementById('strength-description');
  if (description) {
    description.textContent = SENSITIVITY_PRESETS[preset]?.description
      || SENSITIVITY_PRESETS.medium.description;
  }
}

/**
 * 保存一个设置项，保留设置页已经写入的其他配置。
 * @param {string} key 设置键
 * @param {*} value 新值
 * @returns {Promise<void>}
 */
async function saveSetting(key, value) {
  const checked = validateSetting(key, value);
  if (checked === undefined) return;

  settings[key] = checked;
  const next = {
    ...settings,
    _schemaVersion: SCHEMA_VERSION,
    _updatedAt: Date.now()
  };
  await chrome.storage.local.set({ [STORAGE_KEYS.GLOBAL_SETTINGS]: next });
}

/** 切换配置项的详细区域。 */
function toggleDetails(row) {
  const expanded = row.getAttribute('aria-expanded') === 'true';
  row.setAttribute('aria-expanded', String(!expanded));
}

function bindSettings() {
  document.querySelector('.settings-list')?.addEventListener('click', async (event) => {
    const presetButton = event.target.closest('button[data-preset]');
    if (!presetButton) return;

    await saveSetting('sensitivityPreset', presetButton.dataset.preset);
    syncControls();
  });

  document.querySelectorAll('input[data-key]').forEach((input) => {
    input.addEventListener('change', () => {
      saveSetting(input.dataset.key, input.checked).catch((error) => {
        console.error('[Onboarding] 保存设置失败:', error);
      });
    });
  });

  document.querySelectorAll('.setting-row').forEach((row) => {
    row.addEventListener('contextmenu', (event) => {
      event.preventDefault();
      toggleDetails(row);
    });
    row.addEventListener('keydown', (event) => {
      if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
        event.preventDefault();
        toggleDetails(row);
      }
    });
  });
}

function getUpdateChannel() {
  if (UPDATE_CHANNEL === 'store' || UPDATE_CHANNEL === 'manual') return UPDATE_CHANNEL;
  return chrome.runtime.getManifest().update_url ? 'store' : 'manual';
}

/** @param {Object} info 后台返回的版本检查结果 */
function renderVersion(info) {
  const status = document.getElementById('version-status');
  if (!status) return;

  const current = chrome.runtime.getManifest().version;
  latestReleaseUrl = info?.hasUpdate ? (info.releaseUrl || '') : '';

  if (info?.hasUpdate) {
    status.textContent = `发现 v${info.latestVersion}`;
    return;
  }
  if (info?.error && !info.latestVersion) {
    status.textContent = '检查失败，点击重试';
    return;
  }
  status.textContent = `v${current} 已是最新`;
}

/** 自动执行与设置页相同的后台版本检查。 */
async function checkVersion() {
  const status = document.getElementById('version-status');
  if (status) status.textContent = '正在检查';

  if (getUpdateChannel() === 'store') {
    if (status) status.textContent = '由扩展商店自动更新';
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: MSG_TYPES.CHECK_UPDATE,
      payload: {}
    });
    if (!response?.success) throw new Error(response?.error || '检查失败');
    renderVersion(response.data);
  } catch (error) {
    const stored = await chrome.storage.local.get(STORAGE_KEYS.UPDATE_INFO);
    if (stored[STORAGE_KEYS.UPDATE_INFO]) {
      renderVersion(stored[STORAGE_KEYS.UPDATE_INFO]);
    } else if (status) {
      status.textContent = '检查失败，点击重试';
    }
  }
}

function bindNavigation() {
  document.getElementById('open-options')?.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  document.querySelectorAll('[data-url]').forEach((button) => {
    button.addEventListener('click', () => {
      chrome.tabs.create({ url: button.dataset.url });
    });
  });

  document.getElementById('version-link')?.addEventListener('click', () => {
    if (latestReleaseUrl) {
      chrome.tabs.create({ url: latestReleaseUrl });
    } else {
      checkVersion();
    }
  });
}

/** 加载首启页所需状态并绑定交互。 */
async function init() {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.GLOBAL_SETTINGS);
  settings = {
    ...SETTINGS_DEFAULTS,
    ...(stored[STORAGE_KEYS.GLOBAL_SETTINGS] || {})
  };

  applyTheme();
  syncControls();
  bindSettings();
  bindNavigation();
  checkVersion();
}

systemTheme.addEventListener('change', () => {
  if (settings.theme === 'auto') applyTheme();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes[STORAGE_KEYS.GLOBAL_SETTINGS]) return;
  settings = {
    ...SETTINGS_DEFAULTS,
    ...(changes[STORAGE_KEYS.GLOBAL_SETTINGS].newValue || {})
  };
  applyTheme();
  syncControls();
});

init().catch((error) => {
  console.error('[Onboarding] 初始化失败:', error);
});
