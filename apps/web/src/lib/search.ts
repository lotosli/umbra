export interface SearchDocument {
  id: string;
  title: string;
  description: string;
  url: string;
  content: string;
}

export function normalizeSearch(value: string): string {
  return value.normalize('NFKD').replace(/\p{M}/gu, '').toLocaleLowerCase();
}

/** Unicode substring matching deliberately retains CJK phrases and configuration keys. */
export function searchDocuments(documents: SearchDocument[], query: string): SearchDocument[] {
  const terms = normalizeSearch(query).trim().split(/\s+/u).filter(Boolean);
  if (terms.length === 0) return [];
  return documents.map((document, index) => {
    const title = normalizeSearch(document.title);
    const summary = normalizeSearch(document.description);
    const body = normalizeSearch(document.content);
    let score = 0;
    for (const term of terms) {
      if (title.includes(term)) score += 12;
      else if (summary.includes(term)) score += 6;
      else if (body.includes(term)) score += 1;
      else return { document, score: 0, index };
    }
    return { document, score, index };
  }).filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .slice(0, 12)
    .map(({ document }) => document);
}

export function validateSearchIndex(value: unknown, locale: string): SearchDocument[] {
  if (!Array.isArray(value)) throw new Error('Invalid search index');
  return value.map((item: unknown) => {
    if (!item || typeof item !== 'object') throw new Error('Invalid search document');
    const doc = item as Record<string, unknown>;
    for (const key of ['id', 'title', 'description', 'url', 'content']) {
      if (typeof doc[key] !== 'string') throw new Error(`Invalid search field: ${key}`);
    }
    if (!/^[a-z0-9-]+(?:\/[a-z0-9-]+)*$/.test(doc.id as string) || doc.url !== `/${locale}/docs/${doc.id as string}/`) throw new Error('Invalid search destination');
    return doc as unknown as SearchDocument;
  });
}
