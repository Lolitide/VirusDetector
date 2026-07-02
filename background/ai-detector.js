export class AiDetector {
  static async analyze(domain, context, tabId) {
    const settings = await this._getSettings();
    if (!settings || settings.provider === 'disabled') return null;

    const { provider, apiKey, endpoint, model, ollamaUrl, ollamaModel } = settings;
    const privacy = settings.privacy || {};
    const sendDomain = privacy.sendDomain !== false;
    const sendScreenshot = privacy.sendScreenshot === true;
    const sendWhois = privacy.sendWhois !== false;
    const sendIcp = privacy.sendIcp !== false;

    const parts = [];
    if (sendDomain) parts.push(`域名: ${domain}`);
    if (sendWhois && context.whois) {
      parts.push(`WHOIS: 注册 ${context.whois.creationDays || '未知'} 天, 剩余 ${context.whois.validDays || '未知'} 天`);
    }
    if (sendIcp && context.icpStatus) parts.push(`ICP备案: ${context.icpStatus}`);
    if (context.ruleSummary) parts.push(`规则评分: ${context.ruleSummary}`);

    const textData = parts.join('\n');

    let screenshot = null;
    if (sendScreenshot && tabId) {
      screenshot = await this._captureScreenshot(tabId);
    }

    const prompt = this._buildPrompt(textData);
    const messages = this._buildMessages(prompt, screenshot);

    try {
      let raw;
      if (provider === 'openai') {
        raw = await this._callOpenAI(messages, { apiKey, endpoint, model });
      } else if (provider === 'ollama') {
        raw = await this._callOllama(messages, { baseUrl: ollamaUrl, model: ollamaModel });
      } else {
        return null;
      }
      return this._parseResponse(raw);
    } catch (err) {
      console.error('[AiDetector] API 调用失败:', err);
      return { isPhishing: null, confidence: 0, impersonatingBrand: null, reasoning: `AI 分析不可用: ${err.message}`, scoreAdjustment: 0 };
    }
  }

  static async _captureScreenshot(tabId) {
    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tabId, { format: 'jpeg', quality: 60 });
      return dataUrl;
    } catch (e) {
      console.warn('[AiDetector] 截图失败:', e.message);
      return null;
    }
  }

  static _buildPrompt(textData) {
    return `你是一个网络安全专家，专门检测针对中国用户的钓鱼网站（银狐木马）。请根据提供的信息判断目标网站是否为钓鱼/仿冒页面。

${textData}

请分析并返回 JSON 格式（不要包含其他文字）：
{
  "isPhishing": true/false,
  "confidence": 0-100,
  "impersonatingBrand": "冒充的品牌名称，没有则为 null",
  "reasoning": "判断理由（中文，50-200字）",
  "scoreAdjustment": -20 到 40 之间的整数（负数为减分，正数为加分）
}`;
  }

  static _buildMessages(prompt, screenshot) {
    if (screenshot) {
      return [
        { role: 'system', content: '你是一个网络安全专家，专门检测针对中国用户的钓鱼网站。请返回 JSON 格式。' },
        { role: 'user', content: [
          { type: 'text', text: prompt },
          { type: 'image_url', image_url: { url: screenshot, detail: 'low' } }
        ]}
      ];
    }
    return [
      { role: 'system', content: '你是一个网络安全专家，专门检测针对中国用户的钓鱼网站。请返回 JSON 格式。' },
      { role: 'user', content: prompt + '\n\n注意：无法获取页面截图，请仅基于文本信息判断。' }
    ];
  }

  static async _callOpenAI(messages, { apiKey, endpoint, model }) {
    const url = endpoint ? endpoint.replace(/\/+$/, '') + '/chat/completions' : 'https://api.openai.com/v1/chat/completions';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: model || 'gpt-4o-mini',
          messages,
          response_format: { type: 'json_object' },
          max_tokens: 1000
        }),
        signal: controller.signal
      });

      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`HTTP ${resp.status}: ${body.substring(0, 200)}`);
      }

      const json = await resp.json();
      return json.choices?.[0]?.message?.content || '';
    } finally {
      clearTimeout(timeout);
    }
  }

  static async _callOllama(messages, { baseUrl, model }) {
    const url = (baseUrl || 'http://localhost:11434').replace(/\/+$/, '') + '/api/chat';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: model || 'llama3.2-vision:11b',
          messages,
          stream: false,
          format: 'json',
          options: { num_predict: 1000 }
        }),
        signal: controller.signal
      });

      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`Ollama HTTP ${resp.status}: ${body.substring(0, 200)}`);
      }

      const json = await resp.json();
      return json.message?.content || '';
    } finally {
      clearTimeout(timeout);
    }
  }

  static _parseResponse(raw) {
    if (!raw || typeof raw !== 'string') {
      return { isPhishing: null, confidence: 0, impersonatingBrand: null, reasoning: 'AI 响应为空', scoreAdjustment: 0 };
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      const match = raw.match(/\{[\s\S]*\}/);
      if (match) {
        try { parsed = JSON.parse(match[0]); } catch (e2) { parsed = null; }
      } else {
        parsed = null;
      }
    }

    if (!parsed || typeof parsed !== 'object') {
      return { isPhishing: null, confidence: 0, impersonatingBrand: null, reasoning: 'AI 响应解析失败', scoreAdjustment: 0 };
    }

    let adj = typeof parsed.scoreAdjustment === 'number' ? Math.round(parsed.scoreAdjustment) : 0;
    adj = Math.max(-20, Math.min(40, adj));

    return {
      isPhishing: parsed.isPhishing === true ? true : (parsed.isPhishing === false ? false : null),
      confidence: typeof parsed.confidence === 'number' ? Math.max(0, Math.min(100, parsed.confidence)) : 0,
      impersonatingBrand: typeof parsed.impersonatingBrand === 'string' ? parsed.impersonatingBrand : null,
      reasoning: typeof parsed.reasoning === 'string' ? parsed.reasoning.substring(0, 500) : '',
      scoreAdjustment: adj
    };
  }

  static testConnection(settings) {
    const { provider, apiKey, endpoint, model, ollamaUrl, ollamaModel } = settings;
    const messages = [
      { role: 'user', content: '回复 OK 表示连接正常。只回复 OK 两个字。' }
    ];

    if (provider === 'openai') {
      if (!apiKey) return Promise.resolve({ success: false, error: '未配置 API Key' });
      return this._callOpenAI(messages, { apiKey, endpoint, model })
        .then(() => ({ success: true }))
        .catch(err => ({ success: false, error: err.message }));
    }

    if (provider === 'ollama') {
      const url = (ollamaUrl || 'http://localhost:11434').replace(/\/+$/, '') + '/api/chat';
      return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: ollamaModel || 'llama3.2-vision:11b', messages, stream: false })
      })
        .then(r => r.ok ? { success: true } : { success: false, error: `HTTP ${r.status}` })
        .catch(err => ({ success: false, error: err.message }));
    }

    return Promise.resolve({ success: false, error: '未选择 Provider' });
  }

  static async getSettings() {
    return this._getSettings();
  }

  static async _getSettings() {
    try {
      const r = await chrome.storage.local.get('ai_settings');
      return r.ai_settings || null;
    } catch (e) {
      return null;
    }
  }

  static async saveSettings(settings) {
    try {
      await chrome.storage.local.set({ ai_settings: settings });
      return true;
    } catch (e) {
      console.error('[AiDetector] 保存设置失败:', e);
      return false;
    }
  }
}
