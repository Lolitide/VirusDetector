(function () {
  'use strict';

  const STORAGE_KEYS = {
    WHITELIST: 'whitelist',
    AI_SETTINGS: 'ai_settings'
  };

  // ==================== Tab 切换 ====================
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // ==================== 白名单管理 ====================
  let whitelistCache = [];

  async function loadWhitelist() {
    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.WHITELIST);
      whitelistCache = r[STORAGE_KEYS.WHITELIST] || [];
    } catch (e) {
      whitelistCache = [];
    }
    renderWhitelist();
  }

  async function saveWhitelist() {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelistCache });
    } catch (e) { /* ignore */ }
    renderWhitelist();
  }

  function renderWhitelist() {
    const list = document.getElementById('wl-list');
    if (whitelistCache.length === 0) {
      list.innerHTML = '<li id="wl-empty">暂无白名单域名</li>';
      return;
    }
    list.innerHTML = whitelistCache.map(d =>
      `<li><span>${escapeHtml(d)}</span><button class="remove-btn" data-domain="${escapeHtml(d)}">移除</button></li>`
    ).join('');

    list.querySelectorAll('.remove-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        whitelistCache = whitelistCache.filter(d => d !== btn.dataset.domain);
        saveWhitelist();
      });
    });
  }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  document.getElementById('wl-add-btn').addEventListener('click', () => {
    const input = document.getElementById('wl-input');
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    if (!domain) return;
    if (!whitelistCache.includes(domain)) {
      whitelistCache.push(domain);
      saveWhitelist();
    }
    input.value = '';
  });

  document.getElementById('wl-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('wl-add-btn').click();
  });

  // ==================== AI 设置 ====================
  const elements = {
    enabled: document.getElementById('ai-enabled'),
    provider: document.getElementById('ai-provider'),
    endpoint: document.getElementById('ai-endpoint'),
    apiKey: document.getElementById('ai-key'),
    model: document.getElementById('ai-model'),
    ollamaUrl: document.getElementById('ai-ollama-url'),
    ollamaModel: document.getElementById('ai-ollama-model'),
    privacyDomain: document.getElementById('privacy-domain'),
    privacyScreenshot: document.getElementById('privacy-screenshot'),
    privacyWhois: document.getElementById('privacy-whois'),
    privacyIcp: document.getElementById('privacy-icp'),
    openaiSettings: document.getElementById('openai-settings'),
    ollamaSettings: document.getElementById('ollama-settings'),
    testBtn: document.getElementById('ai-test-btn'),
    saveBtn: document.getElementById('ai-save-btn'),
    statusMsg: document.getElementById('ai-status-msg'),
    keyToggle: document.getElementById('ai-key-toggle')
  };

  // Provider 切换
  elements.provider.addEventListener('change', () => {
    const isOpenAI = elements.provider.value === 'openai';
    elements.openaiSettings.style.display = isOpenAI ? 'block' : 'none';
    elements.ollamaSettings.style.display = isOpenAI ? 'none' : 'block';
  });

  // API Key 显示/隐藏
  let keyVisible = false;
  elements.keyToggle.addEventListener('click', () => {
    keyVisible = !keyVisible;
    elements.apiKey.type = keyVisible ? 'text' : 'password';
    elements.keyToggle.textContent = keyVisible ? '隐藏' : '显示';
  });

  async function loadAISettings() {
    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.AI_SETTINGS);
      const s = r[STORAGE_KEYS.AI_SETTINGS];
      if (!s) return;

      elements.enabled.checked = s.provider && s.provider !== 'disabled';
      elements.provider.value = s.provider === 'ollama' ? 'ollama' : 'openai';
      elements.provider.dispatchEvent(new Event('change'));

      elements.endpoint.value = s.endpoint || '';
      elements.apiKey.value = s.apiKey || '';
      elements.model.value = s.model || 'gpt-4o-mini';
      elements.ollamaUrl.value = s.ollamaUrl || 'http://localhost:11434';
      elements.ollamaModel.value = s.ollamaModel || 'llama3.2-vision:11b';

      const p = s.privacy || {};
      elements.privacyDomain.checked = p.sendDomain !== false;
      elements.privacyScreenshot.checked = p.sendScreenshot === true;
      elements.privacyWhois.checked = p.sendWhois !== false;
      elements.privacyIcp.checked = p.sendIcp !== false;
    } catch (e) { /* ignore */ }
  }

  function getAISettings() {
    const enabled = elements.enabled.checked;
    return {
      provider: enabled ? elements.provider.value : 'disabled',
      endpoint: elements.endpoint.value.trim() || 'https://api.openai.com/v1',
      apiKey: elements.apiKey.value.trim(),
      model: elements.model.value.trim() || 'gpt-4o-mini',
      ollamaUrl: elements.ollamaUrl.value.trim() || 'http://localhost:11434',
      ollamaModel: elements.ollamaModel.value.trim() || 'llama3.2-vision:11b',
      privacy: {
        sendDomain: elements.privacyDomain.checked,
        sendScreenshot: elements.privacyScreenshot.checked,
        sendWhois: elements.privacyWhois.checked,
        sendIcp: elements.privacyIcp.checked
      }
    };
  }

  function showStatus(msg, type) {
    const el = elements.statusMsg;
    el.textContent = msg;
    el.className = 'status-msg ' + type;
    setTimeout(() => { el.className = 'status-msg'; }, 5000);
  }

  elements.saveBtn.addEventListener('click', async () => {
    const settings = getAISettings();
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.AI_SETTINGS]: settings });
      showStatus('设置已保存', 'success');
    } catch (e) {
      showStatus('保存失败: ' + e.message, 'error');
    }
  });

  elements.testBtn.addEventListener('click', async () => {
    const settings = getAISettings();
    if (settings.provider === 'openai' && !settings.apiKey) {
      showStatus('请先填写 API Key', 'error');
      return;
    }

    elements.testBtn.disabled = true;
    elements.testBtn.textContent = '测试中...';
    showStatus('正在测试连接...', '');

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'TEST_AI_CONNECTION',
        payload: { settings }
      });

      if (result && result.success) {
        showStatus('连接成功！', 'success');
      } else {
        showStatus('连接失败: ' + (result?.error || '未知错误'), 'error');
      }
    } catch (e) {
      showStatus('连接失败: ' + e.message, 'error');
    } finally {
      elements.testBtn.disabled = false;
      elements.testBtn.textContent = '测试连接';
    }
  });

  // ==================== 初始化 ====================
  loadWhitelist();
  loadAISettings();

})();
