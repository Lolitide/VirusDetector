import { MSG_TYPES } from './constants.js';

/**
 * Virus Detector — 消息通信封装
 *
 * 对 chrome.runtime.sendMessage / onMessage 的轻量封装，
 * 提供标准化的消息信封格式和类型安全的收发方法。
 *
 * @module messaging
 * @version 2.2.4
 *
 * 消息信封结构：{ type: string, payload: any, tabId: number, timestamp: number }
 */
export class Messaging {
  /**
   * 创建标准消息信封
   * @param {string} type - 消息类型
   * @param {*} payload - 消息负载
   * @param {number} [tabId] - 关联的标签页ID
   * @returns {Object} 消息对象
   */
  static createMessage(type, payload = {}, tabId = null) {
    return {
      type,
      payload,
      tabId,
      timestamp: Date.now()
    };
  }

  /**
   * 向后台service worker发送消息
   * @param {string} type
   * @param {*} payload
   * @returns {Promise<*>}
   */
  static async sendToBackground(type, payload = {}) {
    try {
      const response = await chrome.runtime.sendMessage(
        this.createMessage(type, payload)
      );
      return response;
    } catch (error) {
      console.error('[Messaging] 向后台发送消息失败:', error);
      return null;
    }
  }

  /**
   * 向指定标签页发送消息
   * @param {number} tabId
   * @param {string} type
   * @param {*} payload
   * @returns {Promise<*>}
   */
  static async sendToTab(tabId, type, payload = {}) {
    try {
      const response = await chrome.tabs.sendMessage(
        tabId,
        this.createMessage(type, payload, tabId)
      );
      return response;
    } catch (error) {
      console.error(`[Messaging] 向标签页 ${tabId} 发送消息失败:`, error);
      return null;
    }
  }

  /**
   * 向当前活跃标签页发送消息
   * @param {string} type
   * @param {*} payload
   * @returns {Promise<*>}
   */
  static async sendToActiveTab(type, payload = {}) {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) return null;
      return await this.sendToTab(tabs[0].id, type, payload);
    } catch (error) {
      console.error('[Messaging] 向活跃标签页发送消息失败:', error);
      return null;
    }
  }

  /**
   * 添加消息监听器
   * @param {Function} handler - 处理函数 (message, sender) => response|Promise<response>
   * @returns {Function} 用于移除监听器的函数
   */
  static addListener(handler) {
    const wrapper = (message, sender, sendResponse) => {
      const result = handler(message, sender);
      if (result instanceof Promise) {
        result.then(response => {
          sendResponse(response);
        }).catch(error => {
          console.error('[Messaging] 消息处理出错:', error);
          sendResponse({ error: error.message });
        });
        return true; // 保持消息通道开放
      } else {
        sendResponse(result || {});
        return false;
      }
    };

    chrome.runtime.onMessage.addListener(wrapper);
    return () => chrome.runtime.onMessage.removeListener(wrapper);
  }

  /**
   * 验证消息是否是指定类型
   * @param {Object} message
   * @param {string} expectedType
   * @returns {boolean}
   */
  static isType(message, expectedType) {
    return message && message.type === expectedType;
  }
}
