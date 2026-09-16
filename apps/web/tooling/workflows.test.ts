import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { z } from 'zod';

const workflows = `${resolve(process.cwd(), '../../.github/workflows')}/`;
const workflowSchema = z.object({
  on: z.record(z.string(), z.unknown()),
  jobs: z.record(z.string(), z.object({
    uses: z.string().optional(),
    needs: z.string().optional(),
    steps: z.array(z.object({ run: z.string().optional(), uses: z.string().optional() })).optional(),
  })),
});

describe('independent website quality and deployment gates', () => {
  it('checks frozen installation, production build, coverage and browser behavior without publishing', async () => {
    const workflow = workflowSchema.parse(parse(await readFile(`${workflows}web.yml`, 'utf8')));
    const commands = workflow.jobs.verify?.steps?.flatMap((step) => step.run ?? []);
    expect(commands).toEqual(expect.arrayContaining(['pnpm install --frozen-lockfile', 'pnpm --filter @umbra/web run licenses', 'pnpm build', 'pnpm check', 'pnpm test', 'pnpm test:e2e']));
    expect(commands?.some((command) => command.includes('wrangler deploy'))).toBe(false);
    expect(workflow.on).toHaveProperty('workflow_call');
  });

  it('requires an explicit manual trigger and completed verification before publishing', async () => {
    const workflow = workflowSchema.parse(parse(await readFile(`${workflows}web-deploy.yml`, 'utf8')));
    expect(Object.keys(workflow.on)).toEqual(['workflow_dispatch']);
    expect(workflow.jobs.verify?.uses).toBe('./.github/workflows/web.yml');
    expect(workflow.jobs.deploy?.needs).toBe('verify');
    expect(workflow.jobs.deploy?.steps?.at(-1)?.run).toBe('pnpm --filter @umbra/web exec wrangler deploy');
  });

  it('preserves the independent Rust coverage gate', async () => {
    const rust = await readFile(`${workflows}ci.yml`, 'utf8');
    expect(rust).toContain('--fail-under-lines 90');
    expect(rust).toContain('cargo clippy --workspace --all-targets -- -D warnings');
    expect(rust).toContain('cargo deny check');
  });
});
