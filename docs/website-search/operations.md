# Website search discovery operations

Implementation scope: the user-approved SEO/GEO plan, including task-oriented comparisons, seven-language metadata, content freshness and baseline measurement. This file is operational documentation and is not part of the public MDX collection.

## Publication checks

Run using the repository Node/pnpm versions:

```sh
pnpm build
pnpm check
pnpm test
pnpm test:e2e
pnpm --filter @umbra/web run licenses
pnpm --filter @umbra/web audit:discovery
AUDIT_ORIGIN=https://umbra.cat pnpm --filter @umbra/web audit:discovery
```

The audit writes `/tmp/umbra-discovery-audit.json` unless `AUDIT_OUTPUT` is set. It checks every sitemap URL, title, description, language, canonical, alternate, SSR heading, structured identity and document dates. Production restrictions are checked separately from preview noindex. HTTP success is not proof of indexing or AI citation.

Keep a record of the deployed source/version and prior Cloudflare version. Check aliases, real 404, download destinations, search and no-JavaScript content. Structured metadata must not include invented reviews, authors, usage numbers or test results. Software source metadata and Google software rich-result eligibility are separate concerns.

## Content maintenance

`updatedAt` is the date of a substantive article edit. `reviewedAt` is the date the article was checked against its sources. Both are ISO calendar dates, validated at build time; neither uses build time. Update them only when the corresponding work happens. Seven language editions retain the same article ID and factual requirements, with natural language-specific phrasing.

For new or changed product facts, first verify Cargo/release data and actual runtime behavior. Write the Chinese master, align the English version, then translate remaining editions. Keep executable examples unchanged unless runtime behavior requires an update. Search titles live in `src/i18n/seo.ts` independently of visible slogans. Document titles remain specific to the task.

The comparison overview links each option to its setup guide. The detailed comparison is dated and links official sources. Compare complete tools and protocol combinations explicitly. Avoid unsupported performance claims, implied wire compatibility or vague advice such as “check compatibility” without saying what must match.

## Search platform setup

1. Verify the `umbra.cat` domain property in Google Search Console using DNS ownership. Submit `https://umbra.cat/sitemap.xml` and record both submission and processing states.
2. Verify `https://umbra.cat` in Bing Webmaster Tools. Prefer its site verification mechanisms; importing from Google requires reviewing the permissions requested by Microsoft before granting access. Submit the same sitemap.
3. Inspect homepage, download, quick-start, deployment and protocol URLs. Record crawler access, selected canonical and indexing state. A request to index does not mean the page is indexed.
4. Inspect any available Search generative AI inclusion controls and reports. Record the actual account UI; do not invent fields based on older/newer documentation. Google AI report availability and data can depend on account rollout and impressions.
5. In Cloudflare, inspect security events for real verified bots before adjusting any WAF/AI crawler rule. A successful request with a forged bot User-Agent cannot establish real bot access. Distinguish search bots from training crawlers; do not change training permissions as an SEO workaround.

IndexNow is a follow-up after ownership and policy are configured. If enabled, submit changed canonical URLs only, handle removal and retries, and retain receipts. It is not a Google indexing API and does not guarantee indexing. No IndexNow key or crawler-policy change is bundled with this release.

## Local measurement interface and privacy

The browser dispatches `umbra:measurement` CustomEvents for:

| event | trigger | approved context |
|---|---|---|
| download_click | Release-page link | locale, source category, version, optional platform |
| quickstart_open | Quick-start link | locale, source and destination categories, version |
| docs_next_step | Link to a different documentation path | locale, source and destination categories, version |

There is no collector, outbound analytics request, cookie or persistent identifier by default. Events deliberately omit full URLs, query strings, fragment identifiers, search terms and proxy configuration. This is a tested integration interface, not a claim that production conversion data is already being collected. Clicking a release link does not prove a completed download or installation.

Before adding a collector, choose the account/provider, define access and retention, and publish the applicable privacy disclosure. Recommended aggregate-only context is the schema above with a limited retention period; do not introduce proxy-runtime telemetry. A failed listener must not block navigation. Cloudflare request totals are separate from action events and cannot replace them.

## Baseline and follow-up

Record unavailable or processing data as `null` with a reason, not zero. Keep brand and non-brand queries separate. Report by locale, page and country; do not sum Google AI impressions and Bing citations as if they measured the same thing. AI referrals without usable referrers remain unknown.

The accompanying `geo-prompts.json` contains 12 tasks in Chinese and English. Sample these in search-enabled ChatGPT, Google AI Search, Bing/Copilot and Perplexity. Record product/mode, date, locale, region, whether an AI response appeared, citations, factual errors and official-site references. Repeated runs measure variation; they are not a census or market share. No API model response is presented as a consumer-product search result.

At 30, 60 and 90 days after publication, compare to the initial 14–28-day usable baseline. Review absolute non-brand clicks, relevant impressions, high-intent actions and citation pages. Use evidence to prioritize languages and tutorial gaps. These are an operating cadence, not automatic jobs or guaranteed growth targets.

For performance, retain lab device/network settings and repeated measurements. Real-user p75 targets are LCP <=2.5s, INP <=200ms, CLS <=0.1. If CrUX/GSC lacks sufficient samples, report that explicitly. Lab LCP/CLS/TTFB do not establish real-world CWV status.
