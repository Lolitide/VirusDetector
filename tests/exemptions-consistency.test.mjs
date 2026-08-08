/**
 * 豁免名单一致性测试
 *
 * 三份名单语义不同（各自负责一类跳过），不应合并：
 *   - TRUSTED_PLATFORMS          → 跳过规则一（域名仿冒检测）
 *   - ICP_EXEMPT_DOMAINS         → 跳过规则三（ICP 备案检测）
 *   - TRUSTED_DOWNLOAD_HOSTS     → 下载链接降权
 *   - FULLY_TRUSTED_DOMAIN_SUFFIXES → 完全信任（跳过全部检测）
 *
 * 强约束：FULLY_TRUSTED_DOMAIN_SUFFIXES 必须 ⊆ ICP_EXEMPT_DOMAINS（否则"完全信任"
 * 的站点会在规则三被误判无备案加分）。
 * 其余差异为设计允许，仅输出报告供人工核对，不失败。
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { ICP_EXEMPT_DOMAINS, TRUSTED_PLATFORMS } from '../utils/exemptions/index.js';
import { FULLY_TRUSTED_DOMAIN_SUFFIXES } from '../utils/exemptions/fully-trusted.js';
import { TrustedDownloadHosts } from '../utils/trusted-download-hosts.js';

test('FULLY_TRUSTED_DOMAIN_SUFFIXES 必须是 ICP 豁免名单的子集', () => {
  for (const suffix of FULLY_TRUSTED_DOMAIN_SUFFIXES) {
    assert.ok(
      ICP_EXEMPT_DOMAINS.has(suffix),
      `完全信任后缀 ${suffix} 不在 ICP 豁免名单中（会导致规则三误判）`
    );
  }
});

test('输出跨表差异报告（人工核对用，不失败）', () => {
  const downloadList = new Set(TrustedDownloadHosts.getList());
  const diffPlatforms = [...TRUSTED_PLATFORMS].filter((d) => !ICP_EXEMPT_DOMAINS.has(d));
  const diffDownloads = [...downloadList].filter((d) => !ICP_EXEMPT_DOMAINS.has(d));
  const overlap = [...downloadList].filter((d) => ICP_EXEMPT_DOMAINS.has(d));

  console.log('[豁免一致性] TRUSTED_PLATFORMS 独有（不在 ICP 豁免，规则三可能误判，需人工确认）:');
  console.log('  ', diffPlatforms.join(', ') || '（无）');
  console.log('[豁免一致性] TRUSTED_DOWNLOAD_HOSTS 独有（不在 ICP 豁免，规则三可能误判，需人工确认）:');
  console.log('  ', diffDownloads.join(', ') || '（无）');
  console.log('[豁免一致性] TRUSTED_DOWNLOAD_HOSTS ∩ ICP_EXEMPT_DOMAINS（重叠属预期）:');
  console.log('  ', overlap.join(', ') || '（无）');
});
