/**
 * Virus Detector — 设置页控制器
 *
 * 负责设置页的全部交互逻辑：加载/渲染/保存设置、基础/高级模式切换、
 * 灵敏度预设应用、导入/导出/恢复默认、Toast 通知等。
 *
 * @module options
 */

import { SETTINGS_DEFAULTS, SECTIONS, SENSITIVITY_PRESETS, SCHEMA_VERSION, validateSetting } from '../utils/settings-schema.js';
import { STORAGE_KEYS, MSG_TYPES, VERSION } from '../utils/constants.js';

class SettingsApp {
  constructor() {
    /** @type {Object} 当前设置（运行时状态） */
    this.settings = { ...SETTINGS_DEFAULTS };
    /** @type {string} 当前显示的 section ID */
    this._activeSection = localStorage.getItem('vt_activeSection') || 'general';
    /** @type {'basic'|'advanced'} 当前模式 */
    this._mode = localStorage.getItem('vt_mode') || 'basic';
    // 基本模式下不在高级专属分区
    if (this._mode === 'basic') {
      const advancedOnly = ['thresholds', 'download', 'blacklist'];
      if (advancedOnly.includes(this._activeSection)) {
        this._activeSection = 'general';
      }
    }
    /** @type {Object} 灵敏度预设应用时的覆盖层 */
    this._presetOverrides = {};
    /** @type {boolean} 灵敏度预设是否正在应用（防止循环更新） */
    this._applyingPreset = false;
  }

  // ==================== 初始化 ====================

  async init() {
    // 先同步修正侧栏 active（constructor 已从 localStorage 恢复 _activeSection），
    // 避免 HTML 中 hardcoded 的 general active 闪烁一帧后再跳转。
    this._renderSidebar();
    await this._loadSettings();
    this._applyTheme();
    this._renderSection(this._activeSection);
    this._bindEvents();
    this._applyModeToDom();

    console.log('[Settings] 设置页已初始化, schemaVersion:', SCHEMA_VERSION);
  }

  // ==================== 加载与保存 ====================

  async _loadSettings() {
    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.GLOBAL_SETTINGS);
      const stored = r[STORAGE_KEYS.GLOBAL_SETTINGS] || {};
      // 合并：新键用默认值，已存储的键覆盖默认值
      this.settings = { ...SETTINGS_DEFAULTS, ...stored };
      // 同步 localStorage 主题镜像（确保后续页面加载无闪烁）
      try { localStorage.setItem('vt_theme', this.settings.theme || 'dark'); } catch(e) {}
      // Schema 迁移检测
      if (stored._schemaVersion !== SCHEMA_VERSION) {
        console.log('[Settings] Schema 版本变更:', stored._schemaVersion, '→', SCHEMA_VERSION);
        // 未来在此处添加迁移逻辑
      }
    } catch (e) {
      console.error('[Settings] 加载设置失败:', e);
      this.settings = { ...SETTINGS_DEFAULTS };
    }
  }

  async _saveSettings() {
    const toStore = {
      ...this.settings,
      _schemaVersion: SCHEMA_VERSION,
      _updatedAt: Date.now()
    };
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.GLOBAL_SETTINGS]: toStore });
      // 同步写入 localStorage 以便页面加载时无闪烁读取主题
      try { localStorage.setItem('vt_theme', this.settings.theme || 'dark'); } catch(e) {}
      this._broadcastUpdate();
      console.log('[Settings] 已自动保存');
    } catch (e) {
      console.error('[Settings] 保存失败:', e);
      this._showToast('保存失败: ' + e.message, 'error');
    }
  }

  async _broadcastUpdate() {
    try {
      await chrome.runtime.sendMessage({
        type: MSG_TYPES.SETTINGS_UPDATED,
        payload: { settings: this.settings }
      });
    } catch (e) {
      // Service Worker 可能不在运行状态，忽略
    }
  }

  // ==================== 渲染 ====================

  /** 判断给定 mode 的项在当前用户模式下是否可见 */
  _isVisible(itemMode) {
    if (itemMode === 'hidden') return false;
    if (this._mode === 'basic') return itemMode === 'basic';
    if (this._mode === 'advanced') return itemMode === 'basic' || itemMode === 'advanced';
    return true; // developer mode: 显示全部
  }

  /** 侧栏导航高亮（静态 HTML，仅更新 active 类） */
  _renderSidebar() {
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.section === this._activeSection);
    });
  }

  /** 渲染指定 section 的内容
   * @param {string} sectionId
   * @param {boolean} [skipAnimation] 跳过淡入动画（灵敏度变更等内部刷新时使用）
   */
  _renderSection(sectionId, skipAnimation) {
    const section = SECTIONS.find(s => s.id === sectionId);
    if (!section) return;

    const container = document.getElementById('section-container');
    if (!container) return;

    // 高亮侧栏
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.section === sectionId);
    });

    // 自定义渲染 Section（白名单、黑名单）
    if (section.type === 'custom' && typeof this[section.renderFn] === 'function') {
      this[section.renderFn](container, section);
      return;
    }

    // 关于页特殊处理
    if (section.noCard) {
      container.innerHTML = this._buildAboutHTML();
      // 异步加载更新信息
      this._loadUpdateInfo();
      this._loadStorageStats();
      return;
    }

    const animClass = skipAnimation ? ' section-no-anim' : '';
    let html = `
      <div class="section active${animClass}">
        <div class="section-header">
          <div class="section-title">${section.label}</div>
          <div class="section-desc">${section.description}</div>
        </div>
    `;

    for (const group of section.groups) {
      // 过滤模式
      if (!this._isVisible(group.mode)) continue;

      html += `<div class="settings-card" id="card-${group.id}">
        <div class="settings-card-title">${group.iconSVG ? '<span class="card-title-icon">' + group.iconSVG + '</span>' : ''}${group.label}</div>`;

      for (const setting of group.settings) {
        if (!this._isVisible(setting.mode)) continue;

        html += this._buildSettingRow(setting);
      }

      html += `</div>`;
    }

    html += `</div>`;
    container.innerHTML = html;

    // 渲染后同步控件值与当前 settings
    this._syncInputsWithSettings();
  }

  /** 构建单个设置行的 HTML */
  _buildSettingRow(setting) {
    const rowClass = setting.mode === 'advanced' ? ' setting-row-advanced' : '';
    const value = this._getEffectiveValue(setting.key);

    switch (setting.type) {
      case 'boolean':
        return `
          <div class="setting-row" data-key="${setting.key}" data-mode="${setting.mode || 'basic'}">
            <div class="setting-info">
              <div class="setting-label">${setting.label}</div>
              <div class="setting-desc">${setting.desc}</div>
            </div>
            <div class="setting-control">
              <label class="toggle">
                <input type="checkbox" class="setting-input" data-key="${setting.key}" data-type="boolean"
                  ${value ? 'checked' : ''}>
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>`;

      case 'theme':
        return `
          <div class="setting-row theme-setting-row" data-key="${setting.key}" data-mode="${setting.mode || 'basic'}">
            <div class="setting-info">
              <div class="setting-label">${setting.label}</div>
              <div class="setting-desc">${setting.desc}</div>
            </div>
            <div class="setting-control">
              <label class="toggle theme-toggle">
                <input type="checkbox" class="setting-input" data-key="${setting.key}" data-type="theme"
                  ${value === 'light' ? 'checked' : ''}>
                <span class="toggle-slider"></span>
                <span class="theme-icon theme-icon-sun">☀️</span>
                <span class="theme-icon theme-icon-moon">🌙</span>
              </label>
            </div>
          </div>`;

      case 'preset':
        const presetValue = value || 'medium';
        const steps = ['low', 'medium', 'high'];
        const labels = { low: '低', medium: '中', high: '高' };
        const descs = { low: '仅高风险', medium: '均衡检测', high: '最严格' };
        return `
          <div class="setting-row" data-key="${setting.key}" data-mode="${setting.mode || 'basic'}">
            <div class="setting-info">
              <div class="setting-label">${setting.label}</div>
              <div class="setting-desc">${setting.desc}</div>
            </div>
            <div class="setting-control" style="flex:1;max-width:260px;">
              <div class="preset-slider" data-key="${setting.key}" data-type="preset">
                <div class="preset-track">
                  <div class="preset-fill" style="width:${steps.indexOf(presetValue) / (steps.length - 1) * 100}%"></div>
                  <div class="preset-thumb" style="left:${steps.indexOf(presetValue) / (steps.length - 1) * 100}%" data-value="${presetValue}"></div>
                </div>
                <div class="preset-labels">
                  ${steps.map(s => `<button type="button" class="preset-label ${s === presetValue ? 'active' : ''}" data-step="${s}"><span class="preset-label-text">${labels[s]}</span><span class="preset-label-desc">${descs[s]}</span></button>`).join('')}
                </div>
              </div>
            </div>
          </div>`;

      case 'number':
        return `
          <div class="setting-row" data-key="${setting.key}" data-mode="${setting.mode || 'basic'}">
            <div class="setting-info">
              <div class="setting-label">${setting.label}</div>
              <div class="setting-desc">${setting.desc}</div>
            </div>
            <div class="setting-control">
              <input type="number" class="setting-input number-input${(setting.max || 0) > 999 ? ' step-wide' : ''}"
                data-key="${setting.key}" data-type="number"
                value="${value}" min="${setting.min ?? ''}" max="${setting.max ?? ''}" step="${setting.step ?? 1}"
                ${this._isInputDisabled(setting) ? 'disabled' : ''}>
            </div>
          </div>`;

      case 'select':
        const optionsHTML = (setting.options || []).map(opt =>
          `<option value="${opt.value}" ${value === opt.value ? 'selected' : ''}>${opt.label}</option>`
        ).join('');
        return `
          <div class="setting-row" data-key="${setting.key}" data-mode="${setting.mode || 'basic'}">
            <div class="setting-info">
              <div class="setting-label">${setting.label}</div>
              <div class="setting-desc">${setting.desc}</div>
            </div>
            <div class="setting-control">
              <select class="setting-input" data-key="${setting.key}" data-type="select">${optionsHTML}</select>
            </div>
          </div>`;

      case 'action':
        const actionClass = setting.key === '_clearAllData' ? ' danger' : '';
        return `
          <div class="setting-row" data-key="${setting.key}" data-mode="${setting.mode || 'basic'}">
            <div class="setting-info">
              <div class="setting-label">${setting.label}</div>
              <div class="setting-desc">${setting.desc}</div>
            </div>
            <div class="setting-control">
              <button class="setting-action-btn${actionClass}" data-action="${setting.key}">
                ${setting.label}
              </button>
            </div>
          </div>`;

      default:
        return '';
    }
  }

  /** 同步 DOM 输入控件与 settings 状态 */
  _syncInputsWithSettings() {
    const container = document.getElementById('section-container');
    if (!container) return;

    for (const input of container.querySelectorAll('.setting-input')) {
      const key = input.dataset.key;
      const type = input.dataset.type;
      const value = this._getEffectiveValue(key);

      if (type === 'boolean') {
        input.checked = !!value;
      } else if (type === 'theme') {
        input.checked = value === 'light';
      } else if (type === 'number') {
        input.value = value;
      } else if (type === 'select') {
        input.value = value;
      }
    }
  }

  // ==================== 获取有效值（含预设覆盖） ====================
  /** 返回当前有效值：预设覆盖 > 用户设置 > 默认值 */
  _getEffectiveValue(key) {
    if (this._presetOverrides[key] !== undefined) {
      return this._presetOverrides[key];
    }
    if (this.settings[key] !== undefined) {
      return this.settings[key];
    }
    return SETTINGS_DEFAULTS[key];
  }

  /** 判断 number 输入是否应禁用（被预设覆盖时禁用） */
  _isInputDisabled(setting) {
    if (setting.type !== 'number') return false;
    const preset = this.settings.sensitivityPreset || SETTINGS_DEFAULTS.sensitivityPreset;
    if (preset === 'medium') return false;
    // 检查此 key 是否在预设的 overrides 中
    const overrides = SENSITIVITY_PRESETS[preset]?.overrides || {};
    return setting.key in overrides;
  }

  // ==================== 事件处理 ====================

  _bindEvents() {
    const app = document.getElementById('app');
    if (!app) return;

    // change 事件：输入控件
    app.addEventListener('change', (e) => {
      const target = e.target;
      if (target.matches('.setting-input')) {
        this._onSettingChange(target);
      }
    });

    // click 事件委托
    app.addEventListener('click', (e) => {
      const target = e.target.closest('.nav-item, [data-section], [data-preset], #import-btn, #export-btn, #reset-btn, .mode-segment, [data-action], #modal-cancel-btn, #modal-confirm-btn, #check-update-btn, #download-update-btn');
      if (!target) return;

      if (target.matches('.nav-item') || target.dataset.section) {
        const sectionId = target.dataset.section || target.closest('.nav-item')?.dataset?.section;
        if (sectionId) this._switchSection(sectionId);
      } else if (target.matches('.preset-label')) {
        this._onPresetChange(target.dataset.step);
      } else if (target.dataset.preset) {
        this._onPresetChange(target.dataset.preset);
      } else if (target.id === 'import-btn') {
        document.getElementById('import-file')?.click();
      } else if (target.id === 'export-btn') {
        this._exportSettings();
      } else if (target.id === 'reset-btn') {
        this._showConfirm('确定要恢复所有设置为默认值吗？<br>此操作不可撤销。', () => this._resetSettings());
      } else if (target.matches('.mode-segment')) {
        this._setMode(target.dataset.mode);
      } else if (target.dataset.action === '_clearCache') {
        this._showConfirm('确定要清除所有检测缓存吗？<br>下次访问网站时将重新检测。', () => this._clearCache());
      } else if (target.dataset.action === '_clearAllData') {
        this._showConfirm('确定要清除全部本地数据吗？包括缓存、白名单、黑名单和上报记录。<br>此操作不可撤销！', () => this._clearAllData());
      } else if (target.id === 'check-update-btn') {
        this._onCheckUpdate();
      } else if (target.id === 'modal-cancel-btn') {
        this._hideModal();
      } else if (target.id === 'modal-confirm-btn') {
        this._executeConfirmAction();
      }
    });

    // 文件导入
    const fileInput = document.getElementById('import-file');
    if (fileInput) {
      fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) {
          this._importSettings(e.target.files[0]);
          e.target.value = '';
        }
      });
    }

    // 灵敏度预设滑块拖拽
    const STEPS = ['low', 'medium', 'high'];
    let dragging = false;

    const getRatioFromX = (clientX) => {
      const track = document.querySelector('.preset-track');
      if (!track) return null;
      const rect = track.getBoundingClientRect();
      return Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    };

    const getClosestStep = (ratio) => {
      const idx = Math.round(ratio * (STEPS.length - 1));
      return STEPS[idx];
    };

    const updateSliderUI = (ratio) => {
      const pct = ratio * 100;
      const thumb = document.querySelector('.preset-thumb');
      const fill = document.querySelector('.preset-fill');
      if (thumb) thumb.style.left = pct + '%';
      if (fill) fill.style.width = pct + '%';
    };

    const snapSliderUI = (step) => {
      const idx = STEPS.indexOf(step);
      const pct = (idx / (STEPS.length - 1)) * 100;
      const thumb = document.querySelector('.preset-thumb');
      const fill = document.querySelector('.preset-fill');
      const labels = document.querySelectorAll('.preset-label');
      if (thumb) { thumb.style.left = pct + '%'; thumb.dataset.value = step; }
      if (fill) fill.style.width = pct + '%';
      labels.forEach(l => l.classList.toggle('active', l.dataset.step === step));
    };

    const onDragStart = (e) => {
      const thumb = e.target.closest('.preset-thumb');
      if (!thumb) return;
      e.preventDefault();
      dragging = true;
      thumb.classList.add('dragging');
    };

    const onDragMove = (e) => {
      if (!dragging) return;
      const clientX = e.touches ? e.touches[0].clientX : e.clientX;
      const ratio = getRatioFromX(clientX);
      if (ratio !== null) updateSliderUI(ratio);
    };

    const onDragEnd = (e) => {
      if (!dragging) return;
      dragging = false;
      const thumb = document.querySelector('.preset-thumb');
      if (!thumb) return;
      thumb.classList.remove('dragging');
      const clientX = e.changedTouches ? e.changedTouches[0].clientX : e.clientX;
      const ratio = getRatioFromX(clientX);
      if (ratio === null) return;
      const step = getClosestStep(ratio);
      snapSliderUI(step);
      if (step !== this.settings.sensitivityPreset) {
        this._onPresetChange(step);
      }
    };

    app.addEventListener('mousedown', onDragStart);
    app.addEventListener('touchstart', onDragStart, { passive: false });
    document.addEventListener('mousemove', onDragMove);
    document.addEventListener('touchmove', onDragMove, { passive: false });
    document.addEventListener('mouseup', onDragEnd);
    document.addEventListener('touchend', onDragEnd);

    // 点击轨道直接跳转
    app.addEventListener('click', (e) => {
      if (e.target.closest('.preset-thumb') || e.target.closest('.preset-label')) return;
      if (!e.target.closest('.preset-track')) return;
      const step = getClosestStep(e.clientX);
      if (step && step !== this.settings.sensitivityPreset) {
        this._onPresetChange(step);
      }
    });

    // Drawer toggle (hamburger button)
    const drawerToggle = document.getElementById('drawer-toggle-btn');
    if (drawerToggle) {
      drawerToggle.addEventListener('click', () => this._toggleDrawer());
    }

    // Drawer close button (inside sidebar)
    const drawerClose = document.getElementById('drawer-close-btn');
    if (drawerClose) {
      drawerClose.addEventListener('click', () => this._closeDrawer());
    }

    // Overlay click to close drawer
    const drawerOverlay = document.getElementById('drawer-overlay');
    if (drawerOverlay) {
      drawerOverlay.addEventListener('click', () => this._closeDrawer());
    }

    // Auto-close drawer when resizing from narrow to wide
    window.addEventListener('resize', () => {
      if (window.innerWidth > 720) {
        this._closeDrawer();
      }
    });

  }

  // ==================== 设置变更 ====================

  _onSettingChange(input) {
    const key = input.dataset.key;
    const type = input.dataset.type;
    let value;

    switch (type) {
      case 'boolean':
        value = input.checked;
        break;
      case 'number':
        value = parseFloat(input.value);
        if (isNaN(value)) return;
        const min = parseFloat(input.min);
        const max = parseFloat(input.max);
        if (!isNaN(min)) value = Math.max(min, value);
        if (!isNaN(max)) value = Math.min(max, value);
        input.value = value;
        break;
      case 'select':
        value = input.value;
        break;
      case 'theme':
        value = input.checked ? 'light' : 'dark';
        break;
      case 'preset':
        value = input.value;
        break;
      default:
        value = input.value;
    }

    this.settings[key] = value;

    // 主题变更 → 立即生效
    if (key === 'theme') {
      this._applyTheme();
    }

    // 灵敏度预设变更
    if (key === 'sensitivityPreset') {
      this._applyPresetOverrides(value);
      // 重渲染当前 section（数值输入需要更新禁用状态），跳过淡入动画
      this._renderSection(this._activeSection, true);
      // 滑块视觉同步（重渲染后会重建 DOM，无需额外调用）
    }

    this._saveSettings();
  }

  _onPresetChange(preset) {
    this._onSettingChange({ dataset: { key: 'sensitivityPreset', type: 'preset' }, value: preset });
  }

  /** 应用灵敏度预设覆盖 */
  _applyPresetOverrides(preset) {
    const presetDef = SENSITIVITY_PRESETS[preset];
    if (!presetDef) return;
    this._presetOverrides = { ...presetDef.overrides };
  }

  /** 同步滑块视觉状态 */
  _syncPresetSlider(value) {
    const thumb = document.querySelector('.preset-thumb');
    const fill = document.querySelector('.preset-fill');
    const labels = document.querySelectorAll('.preset-label');
    if (!thumb || !fill) return;
    const steps = ['low', 'medium', 'high'];
    const idx = steps.indexOf(value);
    const pct = idx / (steps.length - 1) * 100;
    thumb.style.left = pct + '%';
    thumb.dataset.value = value;
    fill.style.width = pct + '%';
    labels.forEach(l => l.classList.toggle('active', l.dataset.step === value));
  }

  // ==================== 模式切换 ====================

  _setMode(mode) {
    if (this._mode === mode) return;
    this._mode = mode;
    try { localStorage.setItem('vt_mode', mode); } catch(e) {}
    // 切回基础模式时，若当前在高级专属分区则跳转到常规
    if (mode === 'basic') {
      const advancedOnly = ['thresholds', 'download', 'blacklist'];
      if (advancedOnly.includes(this._activeSection)) {
        this._activeSection = 'general';
        try { localStorage.setItem('vt_activeSection', 'general'); } catch(e) {}
      }
    }
    this._applyModeToDom();
    this._renderSidebar();
    this._renderSection(this._activeSection);
    const labels = { basic: '基础模式', advanced: '高级模式', developer: '开发者模式' };
    this._showToast('已切换到' + labels[this._mode], 'info');
  }

  _applyModeToDom() {
    document.documentElement.dataset.mode = this._mode;
    // 更新分段控件高亮
    document.querySelectorAll('.mode-segment').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.mode === this._mode);
    });
  }

  // ==================== 抽屉菜单 ====================

  /** 切换侧栏抽屉打开/关闭 */
  _toggleDrawer() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('drawer-overlay');
    if (!sidebar || !overlay) return;
    const isOpen = sidebar.classList.toggle('open');
    overlay.classList.toggle('open', isOpen);
    document.body.classList.toggle('drawer-active', isOpen);
  }

  /** 关闭侧栏抽屉 */
  _closeDrawer() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('drawer-overlay');
    if (!sidebar || !overlay) return;
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
    document.body.classList.remove('drawer-active');
  }

  // ==================== 分区切换 ====================

  _switchSection(sectionId) {
    this._closeDrawer();
    this._activeSection = sectionId;
    try { localStorage.setItem('vt_activeSection', sectionId); } catch(e) {}
    this._renderSection(sectionId);
    // 高亮侧栏
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.section === sectionId);
    });
  }

  // ==================== 导入/导出/重置 ====================

  _exportSettings() {
    const data = {
      _exportedAt: new Date().toISOString(),
      _schemaVersion: SCHEMA_VERSION,
      _extensionVersion: VERSION,
      settings: this.settings
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `virus-detector-settings-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    this._showToast('设置已导出为 JSON 文件', 'success');
  }

  async _importSettings(file) {
    try {
      const text = await file.text();
      const data = JSON.parse(text);

      if (!data.settings || typeof data.settings !== 'object') {
        throw new Error('无效的设置文件：缺少 settings 字段');
      }

      // 校验每个键
      const validated = {};
      let importedCount = 0;
      for (const [key, value] of Object.entries(data.settings)) {
        if (key in SETTINGS_DEFAULTS) {
          validated[key] = validateSetting(key, value);
          importedCount++;
        }
        // 跳过未知键（未来兼容）
      }

      if (importedCount === 0) {
        throw new Error('文件中没有找到任何可识别的设置项');
      }

      // 合并
      this.settings = { ...SETTINGS_DEFAULTS, ...validated };
      this._presetOverrides = {};
      this._saveSettings();
      this._renderSection(this._activeSection);
      this._showToast(`已导入 ${importedCount} 项设置`, 'success');

    } catch (e) {
      this._showToast(`导入失败: ${e.message}`, 'error');
    }
  }

  async _resetSettings() {
    this.settings = { ...SETTINGS_DEFAULTS };
    this._presetOverrides = {};
    this._saveSettings();
    this._renderSection(this._activeSection);
    this._showToast('已恢复默认设置', 'success');
  }

  // ==================== 数据管理 ====================

  async _clearCache() {
    try {
      const all = await chrome.storage.local.get(null);
      const keysToRemove = Object.keys(all).filter(k =>
        k.startsWith('domain_cache_')
      );
      if (keysToRemove.length > 0) {
        await chrome.storage.local.remove(keysToRemove);
        this._showToast(`已清除 ${keysToRemove.length} 条缓存记录`, 'success');
      } else {
        this._showToast('没有需要清除的缓存', 'info');
      }
    } catch (e) {
      this._showToast('清除缓存失败: ' + e.message, 'error');
    }
  }

  async _clearAllData() {
    try {
      const all = await chrome.storage.local.get(null);
      // 保留 global_settings（将被重置）
      const keysToRemove = Object.keys(all).filter(k =>
        !k.startsWith('global_settings')  // 保留设置键，仅重置
      );
      if (keysToRemove.length > 0) {
        await chrome.storage.local.remove(keysToRemove);
      }
      await chrome.storage.local.remove(STORAGE_KEYS.GLOBAL_SETTINGS);
      this.settings = { ...SETTINGS_DEFAULTS };
      this._presetOverrides = {};
      this._renderSection(this._activeSection);
      this._showToast('已清除全部数据并恢复默认设置', 'success');
    } catch (e) {
      this._showToast('清除数据失败: ' + e.message, 'error');
    }
  }

  // ==================== 主题 ====================

  _applyTheme() {
    const theme = this.settings.theme || SETTINGS_DEFAULTS.theme;
    document.documentElement.dataset.theme = theme;
  }

  // ==================== 确认弹窗 ====================

  _confirmAction = null;

  _showConfirm(message, action) {
    this._confirmAction = action;
    const modal = document.getElementById('confirm-modal');
    const msg = document.getElementById('modal-message');
    if (modal && msg) {
      msg.innerHTML = message;
      modal.style.display = 'flex';
    }
  }

  _hideModal() {
    this._confirmAction = null;
    const modal = document.getElementById('confirm-modal');
    if (modal) modal.style.display = 'none';
  }

  _executeConfirmAction() {
    if (this._confirmAction) {
      this._confirmAction();
    }
    this._hideModal();
  }

  // ==================== Toast ====================

  _showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    // 3 秒后自动移除
    setTimeout(() => {
      toast.classList.add('removing');
      toast.addEventListener('animationend', () => toast.remove());
    }, 3000);
  }

  // ==================== 白名单编辑 ====================

  /**
   * 渲染白名单 Section：textarea 编辑器 + 导入/导出/保存按钮（同 Adguard 风格）
   */
  async _renderWhitelistSection(container, section) {
    container.innerHTML = `
      <div class="section active">
        <div class="section-header">
          <div class="section-title">${section.label}</div>
          <div class="section-desc">${section.description}</div>
        </div>
        <div class="settings-card">
          <div class="whitelist-hint">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-2px;margin-right:4px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
            提示：也可以通过弹窗中的星形按钮快速将当前网站加入白名单
          </div>
          <div class="list-editor-wrapper">
            <textarea id="whitelist-editor" class="list-editor" placeholder="每行输入一个域名，例如：&#10;example.com&#10;trusted-site.org" spellcheck="false"></textarea>
            <div class="list-editor-count" id="whitelist-count"></div>
          </div>
          <div class="list-actions">
            <button id="wl-import-btn" class="btn" title="从 .txt 文件导入域名（合并追加）">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              导入 .txt
            </button>
            <button id="wl-export-btn" class="btn" title="导出域名列表到 .txt 文件">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              导出 .txt
            </button>
            <input type="file" id="wl-import-file" accept=".txt,.text" class="file-input-hidden">
            <button id="wl-save-btn" class="btn btn-primary">保存更改</button>
          </div>
        </div>
      </div>`;

    await this._loadWhitelist();

    // 绑定事件
    document.getElementById('wl-import-btn')?.addEventListener('click', () => {
      document.getElementById('wl-import-file')?.click();
    });
    document.getElementById('wl-import-file')?.addEventListener('change', (e) => {
      if (e.target.files[0]) { this._importWhitelist(e.target.files[0]); e.target.value = ''; }
    });
    document.getElementById('wl-export-btn')?.addEventListener('click', () => this._exportWhitelist());
    document.getElementById('wl-save-btn')?.addEventListener('click', () => this._saveWhitelist());
  }

  /** 从 storage 读取白名单并填充 textarea */
  async _loadWhitelist() {
    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.WHITELIST);
      const whitelist = r[STORAGE_KEYS.WHITELIST] || [];
      const editor = document.getElementById('whitelist-editor');
      if (editor) editor.value = whitelist.join('\n');
      this._updateWhitelistCount(whitelist.length);
    } catch (e) {
      console.error('[Settings] 加载白名单失败:', e);
    }
  }

  _updateWhitelistCount(count) {
    const el = document.getElementById('whitelist-count');
    if (el) el.innerHTML = `共 <strong>${count}</strong> 个域名`;
  }

  /** 保存白名单：解析 textarea → 去重去空 → 批量写入 storage */
  async _saveWhitelist() {
    const editor = document.getElementById('whitelist-editor');
    if (!editor) return;
    const lines = editor.value.split(/[\n\r]+/).map(s => s.trim()).filter(Boolean);
    const domains = [...new Set(lines)]; // 去重
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: domains });
      // 通知 Service Worker 刷新内存缓存
      try {
        await chrome.runtime.sendMessage({
          type: 'BULK_UPDATE_WHITELIST',
          payload: { domains }
        });
      } catch (e) { /* SW 可能不在运行 */ }
      this._updateWhitelistCount(domains.length);
      this._showToast(`白名单已保存（${domains.length} 个域名）`, 'success');
    } catch (e) {
      this._showToast('保存失败: ' + e.message, 'error');
    }
  }

  /** 从 .txt 文件导入白名单（合并去重） */
  async _importWhitelist(file) {
    try {
      const text = await file.text();
      const newDomains = text.split(/[\n\r]+/).map(s => s.trim()).filter(Boolean).map(s => {
        // 尝试提取纯域名（去掉协议和路径）
        try { return new URL(s.startsWith('http') ? s : 'https://' + s).hostname; }
        catch { return s.replace(/^https?:\/\//, '').split('/')[0]; }
      });
      const editor = document.getElementById('whitelist-editor');
      if (!editor) return;
      const existing = editor.value.split(/[\n\r]+/).map(s => s.trim()).filter(Boolean);
      const merged = [...new Set([...existing, ...newDomains])];
      editor.value = merged.join('\n');
      this._updateWhitelistCount(merged.length);
      this._showToast(`已导入 ${newDomains.length} 个域名（合并后共 ${merged.length} 个），点击"保存更改"生效`, 'info');
    } catch (e) {
      this._showToast('导入失败: ' + e.message, 'error');
    }
  }

  /** 导出白名单为 .txt 文件 */
  _exportWhitelist() {
    const editor = document.getElementById('whitelist-editor');
    if (!editor) return;
    const content = editor.value.trim();
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `virus-detector-whitelist-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    this._showToast('白名单已导出', 'success');
  }

  // ==================== 下载黑名单管理 ====================

  /**
   * 渲染下载黑名单 Section：表格列表 + 展开详情 + 删除 + 清除全部
   */
  async _renderBlacklistSection(container, section) {
    container.innerHTML = `
      <div class="section active">
        <div class="section-header">
          <div class="section-title">${section.label}</div>
          <div class="section-desc">${section.description}</div>
        </div>
        <div class="settings-card">
          <div id="blacklist-content">
            <div class="list-empty">
              <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              <p>加载中...</p>
            </div>
          </div>
          <div class="list-actions" id="blacklist-actions" style="display:none;">
            <span class="list-editor-count" id="blacklist-count"></span>
            <button id="bl-clear-all-btn" class="list-clear-all">清除全部黑名单</button>
          </div>
        </div>
      </div>`;

    await this._loadBlacklist();

    // 绑定事件委托
    const card = container.querySelector('.settings-card');
    card?.addEventListener('click', (e) => {
      const delBtn = e.target.closest('.delete-btn');
      if (delBtn) {
        const domain = delBtn.dataset.domain;
        if (domain) this._removeBlacklistEntry(domain);
        return;
      }
      const row = e.target.closest('.bl-domain');
      if (row) {
        const domain = row.dataset.domain;
        if (domain) this._toggleBlacklistExpand(domain);
        return;
      }
    });

    document.getElementById('bl-clear-all-btn')?.addEventListener('click', () => {
      this._showConfirm('确定要清除全部下载黑名单吗？<br>这将删除所有已记录的黑名单域名。<br>此操作不可撤销！', () => this._clearBlacklist());
    });
  }

  /** 从 Service Worker 获取黑名单并渲染表格 */
  async _loadBlacklist() {
    const content = document.getElementById('blacklist-content');
    const actions = document.getElementById('blacklist-actions');
    if (!content || !actions) return;

    try {
      const resp = await chrome.runtime.sendMessage({
        type: MSG_TYPES.GET_DOWNLOAD_BLACKLIST,
        payload: {}
      });
      const blacklist = (resp && resp.data) ? resp.data : {};

      if (typeof blacklist !== 'object' || Object.keys(blacklist).length === 0) {
        content.innerHTML = `
          <div class="list-empty">
            <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 11l2 2 4-4"/></svg>
            <p>黑名单为空</p>
            <p style="font-size:12px;color:var(--text3);margin-top:4px;">当您在下载确认弹窗中选择"拉黑下载域名"时，域名将被自动添加到此列表</p>
          </div>`;
        actions.style.display = 'none';
        return;
      }

      const entries = Object.entries(blacklist);
      // 按 lastHit 降序排列
      entries.sort((a, b) => (b[1].lastHit || 0) - (a[1].lastHit || 0));

      let tableHTML = `
        <table class="blacklist-table">
          <thead>
            <tr>
              <th>域名</th>
              <th>命中次数</th>
              <th>最近命中</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>`;

      for (const [domain, entry] of entries) {
        const hitCount = entry.hitCount || 0;
        const lastHit = this._formatRelativeTime(entry.lastHit);
        tableHTML += `
            <tr class="blacklist-row">
              <td><span class="bl-domain" data-domain="${this._escapeHtml(domain)}">${this._escapeHtml(domain)}</span></td>
              <td class="bl-hits">${hitCount}</td>
              <td class="bl-last-hit">${lastHit}</td>
              <td class="bl-action">
                <button class="delete-btn" data-domain="${this._escapeHtml(domain)}" title="删除 ${this._escapeHtml(domain)}">
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                </button>
              </td>
            </tr>
            <tr class="bl-expanded-row" id="bl-expand-${this._escapeHtmlAttr(domain)}" style="display:none;">
              <td colspan="4">
                <div class="bl-expanded-detail">
                  <div class="detail-label">来源页面</div>
                  <ul class="detail-sources">
                    ${(entry.sourcePages || []).slice(0, 5).map(sp =>
                      `<li><a href="${this._escapeHtml(sp.pageUrl || '#')}" target="_blank" rel="noopener">${this._escapeHtml(sp.pageDomain || sp.pageUrl || '未知')}</a></li>`
                    ).join('')}
                    ${(entry.sourcePages || []).length > 5 ? `<li style="color:var(--text3)">...还有 ${entry.sourcePages.length - 5} 个来源</li>` : ''}
                  </ul>
                  ${entry.fileTypes && entry.fileTypes.length > 0 ? `
                  <div class="detail-label" style="margin-top:8px;">文件类型</div>
                  <div class="detail-filetypes">
                    ${entry.fileTypes.map(ft => `<span class="detail-filetype-tag">${this._escapeHtml(ft)}</span>`).join('')}
                  </div>` : ''}
                </div>
              </td>
            </tr>`;
      }

      tableHTML += `</tbody></table>`;
      content.innerHTML = tableHTML;

      document.getElementById('blacklist-count').innerHTML = `共 <strong>${entries.length}</strong> 条`;
      actions.style.display = 'flex';
    } catch (e) {
      content.innerHTML = `
        <div class="list-empty">
          <p>加载黑名单失败</p>
          <p style="font-size:12px;color:var(--text3);margin-top:4px;">${this._escapeHtml(e.message)}</p>
        </div>`;
      actions.style.display = 'none';
    }
  }

  /** 展开/收起黑名单行详情 */
  _toggleBlacklistExpand(domain) {
    const escapedId = 'bl-expand-' + this._escapeHtmlAttr(domain);
    const row = document.getElementById(escapedId);
    if (row) {
      row.style.display = row.style.display === 'none' ? '' : 'none';
    }
  }

  /** 删除单个黑名单条目 */
  async _removeBlacklistEntry(domain) {
    this._showConfirm(`确定要从黑名单中移除 <strong>${domain}</strong> 吗？`, async () => {
      try {
        await chrome.runtime.sendMessage({
          type: MSG_TYPES.REMOVE_DOWNLOAD_BLACKLIST,
          payload: { domain }
        });
        this._showToast(`已移除 ${domain}`, 'success');
        await this._loadBlacklist(); // 刷新表格
      } catch (e) {
        this._showToast('删除失败: ' + e.message, 'error');
      }
    });
  }

  /** 清除全部黑名单 */
  async _clearBlacklist() {
    try {
      // 获取所有条目并逐条删除
      const resp = await chrome.runtime.sendMessage({
        type: MSG_TYPES.GET_DOWNLOAD_BLACKLIST,
        payload: {}
      });
      const blacklist = (resp && resp.data) ? resp.data : {};
      const domains = Object.keys(blacklist);

      for (const domain of domains) {
        await chrome.runtime.sendMessage({
          type: MSG_TYPES.REMOVE_DOWNLOAD_BLACKLIST,
          payload: { domain }
        });
      }
      this._showToast(`已清除 ${domains.length} 条黑名单记录`, 'success');
      await this._loadBlacklist();
    } catch (e) {
      this._showToast('清除失败: ' + e.message, 'error');
    }
  }

  // ==================== 工具函数 ====================

  /** 格式化相对时间（刚刚 / X分钟前 / X小时前 / X天前） */
  _formatRelativeTime(timestamp) {
    if (!timestamp) return '未知';
    const now = Date.now();
    const diff = now - timestamp;
    const seconds = Math.floor(diff / 1000);
    if (seconds < 60) return '刚刚';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}分钟前`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}小时前`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}天前`;
    const months = Math.floor(days / 30);
    return `${months}个月前`;
  }

  /** HTML 转义 */
  _escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /** HTML 属性值转义（用于 data-attribute 和 id） */
  _escapeHtmlAttr(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ==================== 更新检测 ====================

  async _loadUpdateInfo() {
    const statusEl = document.getElementById('update-status');
    const downloadBtn = document.getElementById('download-update-btn');
    if (!statusEl) return;

    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.UPDATE_INFO);
      const info = r[STORAGE_KEYS.UPDATE_INFO];
      if (!info || !info.lastCheck) {
        statusEl.innerHTML = `<div class="update-status pending">等待首次检查...</div>`;
        return;
      }

      if (info.error) {
        statusEl.innerHTML = `
          <div class="update-status error">
            <span style="color:var(--red);">⚠️ 检查失败</span>
            <div style="font-size:12px;color:var(--text2);margin-top:4px;">${this._escapeHtml(info.error)}</div>
          </div>`;
        return;
      }

      const timeAgo = this._formatRelativeTime(info.lastCheck);
      if (info.hasUpdate) {
        statusEl.innerHTML = `
          <div class="update-status has-update">
            <div style="color:var(--green);font-weight:600;font-size:14px;">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="vertical-align:-3px;margin-right:4px;"><circle cx="12" cy="12" r="10"/><polyline points="16 10 11 15 8 12"/></svg>
              发现新版本！
            </div>
            <div class="about-row" style="margin-top:6px;"><span class="about-label">当前版本</span><span class="about-value">v${info.currentVersion}</span></div>
            <div class="about-row"><span class="about-label">最新版本</span><span class="about-value" style="color:var(--green);font-weight:700;">v${info.latestVersion}</span></div>
            ${info.publishedAt ? `<div class="about-row"><span class="about-label">发布日期</span><span class="about-value">${new Date(info.publishedAt).toLocaleDateString('zh-CN')}</span></div>` : ''}
            <div class="about-row"><span class="about-label">上次检查</span><span class="about-value">${timeAgo}</span></div>
          </div>`;
        if (downloadBtn && info.releaseUrl) {
          downloadBtn.href = info.releaseUrl;
          downloadBtn.style.display = 'inline-flex';
        }
      } else {
        statusEl.innerHTML = `
          <div class="update-status up-to-date">
            <div style="color:var(--green);font-weight:600;">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="vertical-align:-3px;margin-right:4px;"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              已是最新版本
            </div>
            <div class="about-row" style="margin-top:6px;"><span class="about-label">当前版本</span><span class="about-value">v${info.currentVersion}</span></div>
            <div class="about-row"><span class="about-label">最新版本</span><span class="about-value">v${info.latestVersion || info.currentVersion}</span></div>
            <div class="about-row"><span class="about-label">上次检查</span><span class="about-value">${timeAgo}</span></div>
          </div>`;
        if (downloadBtn) downloadBtn.style.display = 'none';
      }
    } catch (e) {
      statusEl.innerHTML = `<div class="update-status pending">无法加载更新信息</div>`;
    }
  }

  async _onCheckUpdate() {
    const statusEl = document.getElementById('update-status');
    const btn = document.getElementById('check-update-btn');
    if (statusEl) statusEl.innerHTML = `<div class="update-status pending">
      <div class="spinner" style="width:16px;height:16px;border-width:2px;margin:0 8px 0 0;display:inline-block;vertical-align:middle;"></div>
      正在检查更新...
    </div>`;
    if (btn) btn.disabled = true;

    try {
      const resp = await chrome.runtime.sendMessage({
        type: MSG_TYPES.CHECK_UPDATE,
        payload: {}
      });
      if (resp && resp.success) {
        await this._loadUpdateInfo();
      } else {
        throw new Error(resp?.error || '未知错误');
      }
    } catch (e) {
      if (statusEl) statusEl.innerHTML = `
        <div class="update-status error">
          <span style="color:var(--red);">⚠️ 检查失败</span>
          <div style="font-size:12px;color:var(--text2);margin-top:4px;">${this._escapeHtml(e.message)}</div>
        </div>`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // ==================== 关于页 ====================

  _buildAboutHTML() {
    const manifest = chrome.runtime.getManifest();
    return `
      <div class="section active">
        <div class="section-header">
          <div class="section-title">关于</div>
          <div class="section-desc">版本信息和项目链接</div>
        </div>
        <div class="about-content">
          <div class="about-card">
            <h3>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-3px;margin-right:4px;">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
              </svg>
              版本信息
            </h3>
            <div class="about-row"><span class="about-label">扩展版本</span><span class="about-value">v${manifest.version}</span></div>
            <div class="about-row"><span class="about-label">Manifest 版本</span><span class="about-value">v${manifest.manifest_version}</span></div>
            <div class="about-row"><span class="about-label">设置 Schema</span><span class="about-value">v${SCHEMA_VERSION}</span></div>
          </div>
          <div class="about-card" id="update-card">
          <div class="version-check-header">
            <h3>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-3px;margin-right:4px;">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
              </svg>
            版本检测
            </h3>
            <button id="check-update-btn" class="btn">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-2px;margin-right:3px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>
                检查更新
              </button>
           </div>
            <div id="update-status">加载中...</div>
            <div class="list-actions" style="margin-top:8px;">
              
              <a id="download-update-btn" class="btn btn-primary" style="display:none;" href="#" target="_blank" rel="noopener">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-2px;margin-right:3px;"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                前往下载
              </a>
            </div>
          </div>
          <div class="about-card">
            <h3>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-3px;margin-right:4px;">
                <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
              </svg>
              项目链接
            </h3>
            <div class="about-links">
              <a class="about-link" href="https://github.com/Lolitide/VirusDetector" target="_blank" rel="noopener">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" style="vertical-align:-2px;margin-right:3px;"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                GitHub 仓库
              </a>
              <a class="about-link" href="https://github.com/Lolitide/VirusDetector/issues/new/choose" target="_blank" rel="noopener">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-2px;margin-right:3px;"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                反馈问题
              </a>
              <a class="about-link" href="https://github.com/Lolitide/VirusDetector/releases" target="_blank" rel="noopener">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-2px;margin-right:3px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                更新日志
              </a>
            </div>
          </div>
         
          <div class="about-card" id="storage-stats-card">
            <h3>存储用量</h3>
            <div id="storage-stats"><span style="color:var(--text2)">加载中...</span></div>
          </div>
        </div>
      </div>`;
  }
}

// ==================== 启动 ====================
document.addEventListener('DOMContentLoaded', () => {
  const app = new SettingsApp();
  app.init().then(() => {
    // 异步加载存储统计
    app._loadStorageStats();
  }).catch(err => {
    console.error('[Settings] 初始化失败:', err);
  });
});

// 扩展 SettingsApp 以支持存储统计
SettingsApp.prototype._loadStorageStats = async function () {
  const statsEl = document.getElementById('storage-stats');
  if (!statsEl) return;
  try {
    const all = await chrome.storage.local.get(null);
    const totalBytes = new Blob([JSON.stringify(all)]).size;
    const bytesInUse = chrome.storage.local.QUOTA_BYTES ? await chrome.storage.local.getBytesInUse(null) : totalBytes;
    const quota = chrome.storage.local.QUOTA_BYTES || 10485760; // 10MB 默认
    const percent = ((bytesInUse / quota) * 100).toFixed(1);

    const cacheKeys = Object.keys(all).filter(k =>
      k.startsWith('domain_cache_')
    );
    const tabStateKeys = Object.keys(all).filter(k => k.startsWith('tab_state_'));
    const whitelist = all[STORAGE_KEYS.WHITELIST] || [];
    const blacklist = all[STORAGE_KEYS.DOWNLOAD_BLACKLIST] || [];
    const reports = all[STORAGE_KEYS.USER_REPORTS] || [];

    statsEl.innerHTML = `
      <div style="margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
          <span style="font-size:12px;color:var(--text2);">已使用</span>
          <span style="font-size:12px;color:var(--text);font-weight:600;">${(bytesInUse / 1024).toFixed(1)} KB / ${(quota / 1024 / 1024).toFixed(0)} MB (${percent}%)</span>
        </div>
        <div style="height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;">
          <div style="height:100%;width:${percent}%;background:${percent > 80 ? 'var(--red)' : percent > 50 ? 'var(--orange)' : 'var(--green)'};border-radius:3px;transition:width 0.5s;"></div>
        </div>
      </div>
      <div class="about-row"><span class="about-label">缓存记录</span><span class="about-value">${cacheKeys.length} 条</span></div>
      <div class="about-row"><span class="about-label">标签页状态</span><span class="about-value">${tabStateKeys.length} 个</span></div>
      <div class="about-row"><span class="about-label">白名单域名</span><span class="about-value">${Array.isArray(whitelist) ? whitelist.length : 0} 个</span></div>
      <div class="about-row"><span class="about-label">下载黑名单</span><span class="about-value">${typeof blacklist === 'object' ? Object.keys(blacklist).length : 0} 条</span></div>
      <div class="about-row"><span class="about-label">上报记录</span><span class="about-value">${Array.isArray(reports) ? reports.length : 0} 条</span></div>
    `;
  } catch (e) {
    statsEl.innerHTML = `<span style="color:var(--text3)">无法加载存储统计: ${e.message}</span>`;
  }
};
