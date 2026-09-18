# Verification — 2026-09-18

## Local implementation

- Runtime: Node 24.18.1, pnpm 9.11.0; frozen-lockfile installation succeeded.
- `pnpm build`: passed; 126 seven-language articles validated.
- `pnpm check`: passed (content, TypeScript, ESLint).
- `pnpm test`: 13 files / 187 tests passed; line coverage 97.84% (454/464).
- `pnpm --filter @umbra/web run licenses`: passed; 559 packages / 580 versions.
- `pnpm test:e2e`: 35 passed, including 280 locale/width/page-template combinations.
- `git diff --check`: passed.
- Browser visual review: English desktop home, Chinese protocol, French mobile home, English documentation, light/dark download pages, full-page home screenshot. Preview: http://127.0.0.1:3000/en/ .
- Browser screenshots: ignored `apps/web/test-results/visual-system-desktop-hero-61a9c-contrast-and-reduced-motion-chromium/home-{light,dark}.png` and `website-mobile-navigation--0149c--layout-fit-their-viewports-chromium/{home-desktop,home-mobile,docs-mobile}.png`.

## Scenario mapping

| Scenario | Evidence |
| --- | --- |
| Consistent themes across page types | visual-system theme test, existing theme persistence test, browser download light/dark and documentation review |
| Desktop homepage and copy action | visual-system desktop bounding boxes and real-command assertions; marketing clipboard success/failure tests |
| Narrow and long-text layouts | seven parameterized visual-system tests, each 5 widths × 8 page templates |
| Keyboard and reduced-motion use | visual-system focus/contrast/reduced-motion test; existing documentation skip and search keyboard tests |
| Direct navigation and product facts | website SSR/metadata/404/all-URL tests; marketing factual content tests |

## Environment issues resolved

Initial browser run lacked Playwright Chromium; installed the pinned test browser, then reran successfully. Initial license command resolved a different global pnpm in its subprocess; enabled Corepack in the Node 24 installation and the license gate passed with pnpm 9.11.0. Preview was restarted after rebuilding so SSR and static hashes matched.

## Release status

- User explicitly authorized deployment and completed Cloudflare CLI authorization. Wrangler login succeeded; credentials use encrypted local storage with a macOS Keychain key.
- Implementation commit: `75eb77ce4b43c4dd4292bfc00b0ba820636bd08c`.
- PR https://github.com/lotosli/umbra/pull/10 merged as `7d9475a9774f6c320c8c4d788347c498a2a64a86`. The merge tree exactly matches the locally verified implementation tree.
- Remote Website checks https://github.com/lotosli/umbra/actions/runs/35300504996 passed, including content, build, licenses, types, lint, coverage and browser tests.
- Remote CI https://github.com/lotosli/umbra/actions/runs/35300504989 passed: OpenSpec, Rust fmt/clippy, nextest/fingerprint, cargo-deny and >=90% Rust line coverage.
- Published with the documented local `pnpm --filter @umbra/web exec wrangler deploy` path to the existing `umbra-web` Worker, after local and remote gates passed.
- Cloudflare production version: `b0291722-974f-4cb4-9aad-e67bfd7d26f8`; domains `umbra.cat` and `www.umbra.cat`.
- Previous version, available for rollback: `112bb8be-40b1-46a5-8f14-486dcd11bda0`.
- Production validation: `PLAYWRIGHT_BASE_URL=https://umbra.cat pnpm test:e2e` — **35 passed (48.0s)**. Includes all seven languages, published routes, 404/redirect/metadata, search, theme/language controls and the responsive matrix.
- Live browser inspection confirmed the new Chinese homepage; direct HTTPS inspection confirmed the new hero markup and matching CSS asset.
- Public entry: https://umbra.cat/zh-hans/ . No Rust runtime, user proxy configuration or external DNS changes were made.
