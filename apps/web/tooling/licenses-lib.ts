import { z } from 'zod';

const reportSchema = z.record(z.string(), z.array(z.object({
  name: z.string().min(1), versions: z.array(z.string().min(1)).nonempty(), license: z.string().min(1),
})));

/** Exact SPDX declarations reviewed for this site's locked dependency graph. */
const allowedLicenses = new Set([
  'MIT', 'ISC', 'Apache-2.0', 'MIT OR Apache-2.0', '(MIT OR Apache-2.0)',
  'MIT-0', 'CC0-1.0', 'BSD-3-Clause', 'BSD-2-Clause', 'Unlicense', 'BlueOak-1.0.0', '0BSD',
  'OFL-1.1',
]);

function reviewedException(name: string, version: string, license: string): boolean {
  // Explicit build-tool/data exceptions. See docs/website-dependencies.md before updating these.
  if (name === '@fortawesome/fontawesome-free' && version === '7.3.1') return license === '(CC-BY-4.0 AND OFL-1.1 AND MIT)';
  if (name === 'dompurify' && version === '3.4.15') return license === '(MPL-2.0 OR Apache-2.0)';
  if (name === 'elkjs' && version === '0.9.3') return license === 'EPL-2.0';
  if (name === 'khroma' && version === '2.1.0') return license === 'Unknown';
  if (license === 'Python-2.0') return name === 'argparse' && version === '2.0.1';
  if (license === 'CC-BY-4.0') return name === 'caniuse-lite' && version === '1.0.30001810';
  if (license === 'MPL-2.0') {
    return /^lightningcss(?:-(?:darwin|linux|freebsd|win32|android)-[a-z0-9-]+)?$/.test(name)
      && ['1.32.0', '1.33.0'].includes(version);
  }
  if (license === 'LGPL-3.0-or-later') {
    return /^@img\/sharp-libvips-(?:darwin|linux|linuxmusl)-[a-z0-9-]+$/.test(name) && version === '1.3.3';
  }
  return false;
}

/** Fail closed on unknown declarations and package/version changes to explicit exceptions. */
export function validateLicenseReport(value: unknown): { packages: number; versions: number; licenses: string[] } {
  const report = reportSchema.parse(value);
  const failures: string[] = [];
  let packages = 0;
  let versions = 0;
  for (const [license, entries] of Object.entries(report)) {
    for (const entry of entries) {
      packages += 1;
      versions += entry.versions.length;
      if (entry.license !== license) {
        failures.push(`${entry.name}: inconsistent license report`);
        continue;
      }
      for (const version of entry.versions) {
        if (!allowedLicenses.has(license) && !reviewedException(entry.name, version, license)) {
          failures.push(`${entry.name}@${version}: unreviewed license ${license}`);
        }
      }
    }
  }
  if (packages === 0) throw new Error('License report is empty');
  if (failures.length > 0) throw new Error(`Dependency license check failed:\n${failures.join('\n')}`);
  return { packages, versions, licenses: Object.keys(report).sort() };
}
