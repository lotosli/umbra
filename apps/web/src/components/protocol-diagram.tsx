import diagrams from '../../../../docs/protocol-diagrams/labels.json';

type DiagramName = 'architecture' | 'server' | 'client';

/** Static images and native disclosure keep technical diagrams usable without JavaScript. */
export function ProtocolDiagram({ locale, name }: { locale: string; name: DiagramName }) {
  const key = `${locale}/${name}`;
  if (!(key in diagrams)) throw new Error(`Unknown protocol diagram: ${key}`);
  const diagram = diagrams[key as keyof typeof diagrams];
  return <figure className="reference-diagram">
    <div className="reference-diagram-viewport" tabIndex={0} role="region" aria-label={diagram.caption}>
      <a href={diagram.path} target="_blank" rel="noreferrer" aria-label={`${diagram.fullSize}: ${diagram.caption}`}>
        <img src={diagram.path} alt={diagram.caption} width={diagram.width} height={diagram.height} style={{ minWidth: Math.min(diagram.width, 760) }} loading="lazy" />
      </a>
    </div>
    <figcaption>{diagram.caption} <a href={diagram.path} target="_blank" rel="noreferrer">{diagram.fullSize}</a></figcaption>
    <details><summary>{diagram.viewSource}</summary><pre><code>{diagram.source}</code></pre></details>
  </figure>;
}
