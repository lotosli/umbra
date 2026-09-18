import { describe, expect, it } from 'vitest';
import { validateLicenseReport } from './licenses-lib';

function entry(name: string, license: string, versions = ['1.0.0']) {
  return { name, license, versions };
}

describe('dependency license gate', () => {
  it('accepts declared reviewed licenses and counts all locked versions', () => {
    expect(validateLicenseReport({
      MIT: [entry('react', 'MIT', ['19.2.8']), entry('example', 'MIT', ['1.0.0', '1.1.0'])],
      'MIT OR Apache-2.0': [entry('wrangler', 'MIT OR Apache-2.0', ['4.132.0'])],
    })).toEqual({ packages: 3, versions: 4, licenses: ['MIT', 'MIT OR Apache-2.0'] });
  });

  it('allows only the documented package/version exceptions across build platforms', () => {
    expect(validateLicenseReport({
      'Python-2.0': [entry('argparse', 'Python-2.0', ['2.0.1'])],
      'CC-BY-4.0': [entry('caniuse-lite', 'CC-BY-4.0', ['1.0.30001810'])],
      'MPL-2.0': [entry('lightningcss', 'MPL-2.0', ['1.32.0', '1.33.0']), entry('lightningcss-linux-x64-gnu', 'MPL-2.0', ['1.33.0'])],
      'LGPL-3.0-or-later': [entry('@img/sharp-libvips-darwin-arm64', 'LGPL-3.0-or-later', ['1.3.3']), entry('@img/sharp-libvips-linux-x64', 'LGPL-3.0-or-later', ['1.3.3'])],
    }).packages).toBe(6);
  });

  it.each([
    ['other', 'Python-2.0', '2.0.1'], ['argparse', 'Python-2.0', '3.0.0'],
    ['other', 'CC-BY-4.0', '1.0.30001810'], ['caniuse-lite', 'CC-BY-4.0', '2.0.0'],
    ['unrelated', 'MPL-2.0', '1.33.0'], ['lightningcss', 'MPL-2.0', '2.0.0'],
    ['unrelated', 'LGPL-3.0-or-later', '1.3.3'], ['@img/sharp-libvips-linux-x64', 'LGPL-3.0-or-later', '2.0.0'],
    ['unknown', 'UNKNOWN', '1.0.0'], ['unreviewed', 'GPL-3.0-only', '1.0.0'],
  ])('rejects unreviewed %s / %s / %s', (name, license, version) => {
    expect(() => validateLicenseReport({ [license]: [entry(name, license, [version])] })).toThrow(`${name}@${version}: unreviewed license`);
  });

  it.each([
    ['@fortawesome/fontawesome-free', '(CC-BY-4.0 AND OFL-1.1 AND MIT)', '7.3.1'],
    ['dompurify', '(MPL-2.0 OR Apache-2.0)', '3.4.15'],
    ['elkjs', 'EPL-2.0', '0.9.3'], ['khroma', 'Unknown', '2.1.0'],
  ])('restricts Mermaid toolchain exception %s to its reviewed version and declaration', (name, license, version) => {
    expect(validateLicenseReport({ [license]: [entry(name, license, [version])] }).packages).toBe(1);
    expect(() => validateLicenseReport({ [license]: [entry(name, license, ['99.0.0'])] })).toThrow('unreviewed');
    expect(() => validateLicenseReport({ 'GPL-3.0-only': [entry(name, 'GPL-3.0-only', [version])] })).toThrow('unreviewed');
  });

  it('rejects missing, inconsistent and empty reports', () => {
    expect(() => validateLicenseReport({})).toThrow('License report is empty');
    expect(() => validateLicenseReport({ MIT: [{ name: 'missing-version', license: 'MIT' }] })).toThrow();
    expect(() => validateLicenseReport({ MIT: [entry('mismatch', 'GPL-3.0-only')] })).toThrow('inconsistent license report');
  });
});
