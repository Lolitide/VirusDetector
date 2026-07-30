import { sanitizeDiagnosticText } from './diagnostics.js';

export const BUG_REPORT_URL = 'https://github.com/Lolitide/VirusDetector/issues/new';
const MAX_LOG_SECTION_LENGTH = 8000;
const MAX_ISSUE_URL_LENGTH = 12000;

const SAFE_SETTING_KEYS = [
  'sensitivityPreset',
  'desktopNotifications',
  'showWarningWindow',
  'showDetectionDetails',
  'allowAnonymousReporting',
  'rule1Enabled',
  'rule2Enabled',
  'rule3Enabled',
  'rule4Enabled',
  'rule5Enabled',
  'domainAgeEnabled',
  'detectNonArchiveFiles'
];

export function buildSettingsSummary(settings) {
  const summary = {};
  for (const key of SAFE_SETTING_KEYS) {
    const value = settings?.[key];
    if (typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
      summary[key] = value;
    }
  }
  return summary;
}

export function formatDiagnosticConfiguration(data) {
  const lines = [
    `Virus Detector: ${data.extensionVersion || 'unknown'}`,
    `Manifest: ${data.manifestVersion || 'unknown'}`,
    `Browser: ${sanitizeDiagnosticText(data.browser || 'unknown')}`,
    `OS: ${sanitizeDiagnosticText(data.os || 'unknown')}`,
    `Locale: ${sanitizeDiagnosticText(data.locale || 'unknown')}`,
    `Install type: ${sanitizeDiagnosticText(data.installType || 'unknown')}`,
    'settings:'
  ];

  const settings = buildSettingsSummary(data.settings);
  if (Object.keys(settings).length === 0) {
    lines.push('  [default or unavailable]');
  } else {
    for (const [key, value] of Object.entries(settings)) {
      lines.push(`  ${key}: ${sanitizeDiagnosticText(value)}`);
    }
  }

  lines.push('storage:');
  for (const [key, value] of Object.entries(data.storage || {})) {
    if (Number.isSafeInteger(value) && value >= 0) lines.push(`  ${key}: ${value}`);
  }

  lines.push('recentLogs:');
  const logs = Array.isArray(data.logs) ? data.logs.slice(-40) : [];
  if (logs.length === 0) {
    lines.push('  [none captured in this browser session]');
  } else {
    let logSectionLength = 0;
    for (const entry of logs) {
      const time = sanitizeDiagnosticText(entry.time || 'unknown');
      const level = entry.level === 'error' ? 'error' : 'warn';
      const message = sanitizeDiagnosticText(entry.message || '').substring(0, 350);
      const line = `  - ${time} [${level}] ${message}`;
      if (logSectionLength + line.length > MAX_LOG_SECTION_LENGTH) {
        lines.push('  [additional logs omitted to keep the report URL within limits]');
        break;
      }
      lines.push(line);
      logSectionLength += line.length;
    }
  }

  return `<details>\n<summary>自动收集的诊断信息（已自动脱敏，请在提交前进行二次检查）</summary>\n\n\`\`\`yaml\n${lines.join('\n')}\n\`\`\`\n</details>`;
}

export function buildBugReportUrl(data) {
  let logs = Array.isArray(data.logs) ? data.logs.slice(-40) : [];
  let omittedLogs = 0;

  while (true) {
    const reportData = omittedLogs > 0
      ? {
          ...data,
          logs: [{
            time: 'unknown',
            level: 'warn',
            message: `[${omittedLogs} older log entries omitted to keep the report URL within limits]`
          }, ...logs]
        }
      : { ...data, logs };
    const url = createBugReportUrl(reportData);
    if (url.length <= MAX_ISSUE_URL_LENGTH || logs.length === 0) return url;
    logs = logs.slice(1);
    omittedLogs++;
  }
}

function createBugReportUrl(data) {
  const params = new URLSearchParams({
    template: 'bug_report.yml',
    title: '[Bug] ',
    environment: data.extensionVersion || '',
    browser: data.browser || '',
    os: data.os || '',
    configuration: formatDiagnosticConfiguration(data)
  });
  return `${BUG_REPORT_URL}?${params.toString()}`;
}
