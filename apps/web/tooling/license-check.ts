import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateLicenseReport } from './licenses-lib';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const raw = execFileSync('pnpm', ['licenses', 'list', '--json'], {
  cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
});
const report = validateLicenseReport(JSON.parse(raw) as unknown);
console.log(`Validated licenses for ${report.packages} dependency packages (${report.versions} versions).`);
