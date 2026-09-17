import { useState } from 'react';
import { useHydrated } from '@tanstack/react-router';
import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Check,
  CheckCheck,
  ChevronRight,
  CircleDot,
  Code2,
  Copy,
  Fingerprint,
  Globe2,
  KeyRound,
  Layers3,
  Monitor,
  Network,
  ShieldCheck,
  Terminal,
  X,
} from 'lucide-react';
import {
  marketingCopy,
  type MarketingCopy,
  type MarketingPageName,
} from '../i18n/marketing';
import { localePath, repositoryUrl, type Locale } from '../lib/locales';
import { releaseVersion, releaseUrl, platforms } from '../lib/releases';
import { EclipseMark } from './site-shell';

const sourceCommands =
  'git clone https://github.com/lotosli/umbra.git\ncd umbra\ncargo build --release\n./target/release/umbra keygen';

/** Clipboard feedback reports success only once the browser confirms the write. */
export function CommandBlock({ locale }: { locale: Locale }) {
  const ready = useHydrated();
  const copy = marketingCopy[locale];
  const [status, setStatus] = useState<'idle' | 'copied' | 'failed'>('idle');
  async function copyCommands() {
    try {
      await navigator.clipboard.writeText(sourceCommands);
      setStatus('copied');
    } catch {
      setStatus('failed');
    }
  }
  const statusLabel =
    status === 'copied'
      ? copy.ui.copied
      : status === 'failed'
        ? copy.ui.copyFailed
        : '';
  return (
    <div className="command-block">
      <div className="command-toolbar">
        <span>
          <Terminal size={15} aria-hidden="true" />
          {copy.start.terminal}
        </span>
        <button
          type="button"
          disabled={!ready}
          onClick={() => {
            void copyCommands();
          }}
          aria-label={copy.ui.copy}
        >
          {status === 'copied' ? <CheckCheck size={16} /> : <Copy size={16} />}
        </button>
      </div>
      <pre>
        <code>
          {sourceCommands.split('\n').map((line) => (
            <span className="command-line" key={line}>
              <span aria-hidden="true" className="command-prompt">
                $
              </span>
              {line}
            </span>
          ))}
        </code>
      </pre>
      <span
        role="status"
        className={`copy-status ${status === 'failed' ? 'copy-failed' : ''}`}
      >
        {statusLabel}
      </span>
      <div className="command-bottom">
        <span className="status-dot" /> Rust · Cargo
        <span className="command-shell">bash</span>
      </div>
    </div>
  );
}

function ProtocolDiagram({
  copy,
  compact = false,
}: {
  copy: MarketingCopy;
  compact?: boolean;
}) {
  return (
    <figure
      className={`protocol-diagram ${compact ? 'diagram-compact' : ''}`}
      aria-label={copy.diagram.caption}
    >
      <div className="diagram-grid" />
      <div className="diagram-topline">
        <span>
          <span className="status-dot" /> TLS 1.3 / QUIC
        </span>
        <span>01 — 03</span>
      </div>
      <div className="diagram-orbit orbit-outer" />
      <div className="diagram-orbit orbit-inner" />
      <div className="diagram-core">
        <EclipseMark centered />
        <span>umbra</span>
      </div>
      <div className="diagram-ray ray-left" />
      <div className="diagram-ray ray-right" />
      <div className="diagram-endpoint endpoint-client">
        <div>
          <Monitor size={20} />
        </div>
        <span>{copy.diagram.client}</span>
      </div>
      <div className="diagram-endpoint endpoint-internet">
        <div>
          <Globe2 size={20} />
        </div>
        <span>{copy.diagram.internet}</span>
      </div>
      <span className="diagram-transport">{copy.diagram.transport}</span>
      <span className="diagram-packet packet-one" />
      <span className="diagram-packet packet-two" />
      <div className="diagram-fallback">
        <span className="fallback-stem" />
        <span>
          <CircleDot size={12} />
          {copy.diagram.fallback}
        </span>
      </div>
      <figcaption>{copy.diagram.caption}</figcaption>
    </figure>
  );
}

function SectionTitle({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description?: string;
}) {
  return (
    <div className="section-heading">
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      {description && <p className="section-description">{description}</p>}
    </div>
  );
}

function HomePage({ locale }: { locale: Locale }) {
  const copy = marketingCopy[locale];
  const featureIcons = [Globe2, Fingerprint, KeyRound, Network];
  return (
    <>
      <section className="hero container">
        <div className="hero-copy">
          <a className="release-badge" href={localePath(locale, 'changelog')}>
            <span className="status-dot" />
            {copy.hero.badge.replace('1.0.0-alpha', releaseVersion)}
            <ChevronRight size={14} aria-hidden="true" />
          </a>
          <h1>
            {copy.hero.title}
            <br />
            <span>{copy.hero.accent}</span>
          </h1>
          <p className="hero-description">{copy.hero.description}</p>
          <div className="button-row">
            <a
              className="button button-primary"
              href={localePath(locale, 'docs/getting-started/quick-start')}
            >
              {copy.hero.start}
              <ArrowRight size={17} />
            </a>
            <a
              className="button button-quiet"
              href={localePath(locale, 'protocol')}
            >
              {copy.hero.explore}
              <ArrowUpRight size={16} />
            </a>
          </div>
          <p className="hero-footnote">
            <Code2 size={15} aria-hidden="true" />
            {copy.hero.footnote}
          </p>
        </div>
      </section>
      <div className="facts-strip">
        <div className="container facts-inner">
          {['REALITY', 'TCP + QUIC', 'SOCKS5', 'MIT'].map((value, index) => (
            <div className="fact" key={value}>
              <strong>{value}</strong>
              <span>{copy.facts[index]}</span>
            </div>
          ))}
        </div>
      </div>
      <section className="container section principles-section">
        <SectionTitle {...copy.principles} />
        <div className="feature-grid">
          {copy.principles.features.map((feature, index) => {
            const Icon = featureIcons[index]!;
            return (
              <article className="feature-card" key={feature.title}>
                <h3>
                  <span className="feature-icon">
                    <Icon size={21} strokeWidth={1.6} />
                  </span>
                  {feature.title}
                </h3>
                <p>{feature.description}</p>
                {index === 0 && (
                  <div className="fallback-flow">
                    <span>
                      <Check size={14} />
                      {copy.diagram.authenticated}
                    </span>
                    <ArrowRight size={14} />
                    <span>{copy.diagram.transport}</span>
                    <span>
                      <X size={14} />
                      {copy.diagram.fallback}
                    </span>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </section>
      <section className="quick-start-section">
        <div className="container quick-start-inner">
          <div>
            <SectionTitle {...copy.start} />
            <a
              className="text-link"
              href={localePath(locale, 'docs/getting-started/quick-start')}
            >
              {copy.start.link}
              <ArrowRight size={16} />
            </a>
          </div>
          <CommandBlock locale={locale} />
        </div>
      </section>
      <section className="container section docs-section">
        <SectionTitle {...copy.docs} />
        <div className="docs-card-grid">
          {copy.docs.cards.map((card, index) => (
            <a
              className="docs-card"
              href={localePath(
                locale,
                [
                  'docs/getting-started/introduction',
                  'docs/configuration/server',
                  'docs/reference/protocol',
                ][index]!,
              )}
              key={card.title}
            >
              <span className="docs-card-top">
                {index === 0 ? (
                  <BookOpen size={21} />
                ) : index === 1 ? (
                  <Terminal size={21} />
                ) : (
                  <Layers3 size={21} />
                )}
                <ArrowUpRight size={18} />
              </span>
              <h3>{card.title}</h3>
              <p>{card.description}</p>
            </a>
          ))}
        </div>
      </section>
      <section className="container closing-cta">
        <EclipseMark />
        <h2>{copy.cta.title}</h2>
        <p>{copy.cta.description}</p>
        <a className="button button-primary" href={localePath(locale, 'docs')}>
          {copy.hero.start}
          <ArrowRight size={17} />
        </a>
      </section>
    </>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <header className="page-heading">
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <p>{description}</p>
    </header>
  );
}

function DownloadPage({ locale }: { locale: Locale }) {
  const copy = marketingCopy[locale];
  const symbols: Record<string, string> = {
    macOS: '⌘',
    Linux: '>_',
    Windows: '⊞',
  };
  const groupedPlatforms = [...new Set(platforms.map(({ os }) => os))].map(
    (os) => ({
      name: os,
      architectures: platforms
        .filter((platform) => platform.os === os)
        .map(({ architecture }) => architecture)
        .join(' · '),
      symbol: symbols[os],
    }),
  );
  return (
    <div className="container inner-page">
      <PageHeading {...copy.download} />
      <div className="release-status">
        <span className="version-label">v{releaseVersion}</span>
        <p>{copy.download.alpha}</p>
      </div>
      <div className="download-grid">
        {groupedPlatforms.map((platform) => (
          <article className="download-card" key={platform.name}>
            <span className="platform-symbol" aria-hidden="true">
              {platform.symbol}
            </span>
            <h2>{platform.name}</h2>
            <p>{platform.architectures}</p>
            <a className="button button-secondary" href={releaseUrl}>
              {copy.download.releases}
              <ArrowDown size={15} />
            </a>
          </article>
        ))}
      </div>
      <aside className="information-note">
        <ShieldCheck size={23} />
        <div>
          <h2>{copy.download.verify}</h2>
          <p>{copy.download.verifyDescription}</p>
        </div>
      </aside>
      <section className="source-section">
        <div>
          <h2>{copy.download.source}</h2>
          <p>{copy.download.sourceDescription}</p>
          <p className="source-requirements">{copy.download.requirements}</p>
          <a
            className="text-link"
            href={localePath(locale, 'docs/getting-started/installation')}
          >
            {copy.nav.docs}
            <ArrowRight size={16} />
          </a>
        </div>
        <CommandBlock locale={locale} />
      </section>
    </div>
  );
}

function ProtocolPage({ locale }: { locale: Locale }) {
  const copy = marketingCopy[locale];
  return (
    <div className="container inner-page">
      <div className="protocol-intro">
        <PageHeading {...copy.protocol} />
        <ProtocolDiagram copy={copy} compact />
      </div>
      <div className="protocol-steps">
        {copy.protocol.steps.map((step, index) => (
          <article key={step.title}>
            <span className="step-number">0{index + 1}</span>
            <h2>{step.title}</h2>
            <p>{step.description}</p>
          </article>
        ))}
      </div>
      <section className="layers-section">
        <h2>{copy.protocol.implementation}</h2>
        <p>{copy.protocol.implementationDescription}</p>
        <div className="layer-list">
          {copy.protocol.layers.map((layer, index) => (
            <div className="layer-row" key={layer.title}>
              <span>0{index + 1}</span>
              <h3>{layer.title}</h3>
              <p>{layer.description}</p>
              <div className="layer-facts">
                <div>
                  <h4>{copy.protocol.strengthsLabel}</h4>
                  <ul>
                    {layer.strengths.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4>{copy.protocol.limitsLabel}</h4>
                  <ul>
                    {layer.limits.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
      <aside className="information-note">
        <Fingerprint size={24} />
        <p>{copy.protocol.caveat}</p>
      </aside>
      <a
        className="button button-primary"
        href={localePath(locale, 'docs/reference/protocol')}
      >
        {copy.nav.docs}
        <ArrowRight size={16} />
      </a>
    </div>
  );
}

function SecurityPage({ locale }: { locale: Locale }) {
  const copy = marketingCopy[locale];
  return (
    <div className="container inner-page">
      <PageHeading {...copy.security} />
      <div className="security-grid">
        {copy.security.principles.map((principle, index) => (
          <article key={principle.title}>
            <span className="feature-number">0{index + 1}</span>
            <ShieldCheck size={23} strokeWidth={1.5} />
            <h2>{principle.title}</h2>
            <p>{principle.description}</p>
          </article>
        ))}
      </div>
      <section className="security-limits">
        <div>
          <p className="eyebrow">{copy.nav.security}</p>
          <h2>{copy.security.limitsTitle}</h2>
          <a
            className="text-link"
            href={localePath(locale, 'docs/concepts/security-model')}
          >
            {copy.nav.docs}
            <ArrowRight size={16} />
          </a>
        </div>
        <ul>
          {copy.security.limits.map((limit) => (
            <li key={limit}>
              <span className="limit-dot" />
              {limit}
            </li>
          ))}
        </ul>
      </section>
      <section className="disclosure-panel">
        <h2>{copy.security.disclosure}</h2>
        <p>{copy.security.disclosureDescription}</p>
        <a className="text-link" href={repositoryUrl}>
          {copy.security.source}
          <ArrowUpRight size={16} />
        </a>
      </section>
    </div>
  );
}

function ChangelogPage({
  locale,
  releaseDetail = false,
}: {
  locale: Locale;
  releaseDetail?: boolean;
}) {
  const copy = marketingCopy[locale];
  return (
    <div className="container inner-page">
      <PageHeading {...copy.changelog} />
      <article className="release-entry">
        <div className="release-meta">
          <span className="version-label">v{releaseVersion}</span>
          <span className="prerelease-label">{copy.changelog.prerelease}</span>
        </div>
        <div className="release-body">
          <h2>{copy.changelog.heading}</h2>
          <p>{copy.changelog.summary}</p>
          {releaseDetail && (
            <ul>
              {copy.changelog.changes.map((change) => (
                <li key={change}>
                  <Check size={17} />
                  {change}
                </li>
              ))}
            </ul>
          )}
          <div className="information-note">
            <ArrowUpRight size={20} />
            <p>{copy.changelog.upgrade}</p>
          </div>
          <div className="button-row">
            <a
              className="button button-primary"
              href={
                releaseDetail
                  ? releaseUrl
                  : localePath(locale, `changelog/${releaseVersion}`)
              }
            >
              {copy.changelog.read}
              <ArrowUpRight size={16} />
            </a>
            <a
              className="text-link"
              href={localePath(locale, 'docs/guides/upgrade')}
            >
              {copy.nav.docs}
              <ArrowRight size={16} />
            </a>
          </div>
          {releaseDetail && (
            <section className="release-sources">
              <h3>{copy.footer.resources}</h3>
              <a
                className="text-link"
                href={`${repositoryUrl}/blob/main/README.md`}
              >
                README
                <ArrowUpRight size={14} />
              </a>
              <a
                className="text-link"
                href={`${repositoryUrl}/blob/main/docs/performance.md`}
              >
                docs/performance.md
                <ArrowUpRight size={14} />
              </a>
              <a className="text-link" href={localePath(locale, 'changelog')}>
                {copy.nav.changelog}
                <ArrowRight size={14} />
              </a>
            </section>
          )}
        </div>
      </article>
    </div>
  );
}

const pages = {
  home: HomePage,
  download: DownloadPage,
  protocol: ProtocolPage,
  security: SecurityPage,
  changelog: ChangelogPage,
};

export function MarketingPage({
  locale,
  page,
  releaseDetail,
}: {
  locale: Locale;
  page: MarketingPageName;
  releaseDetail?: boolean;
}) {
  if (page === 'changelog')
    return <ChangelogPage locale={locale} releaseDetail={releaseDetail} />;
  const Page = pages[page];
  return <Page locale={locale} />;
}
