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

User explicitly authorized Cloudflare deployment. Local checks are complete. Wrangler authentication is pending; the GitHub repository/environment currently has no deployment secrets. No production publication is claimed until deployment and live checks complete. Existing source includes a manually triggered website workflow; local authenticated Wrangler deployment is also documented in `docs/website-development.md`.
