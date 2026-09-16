import { useEffect, useMemo, useState } from 'react';
import {
  SearchDialog as FumaSearchDialog,
  SearchDialogHeader, SearchDialogInput, SearchDialogContent, SearchDialogOverlay, SearchDialogClose, SearchDialogList,
} from 'fumadocs-ui/components/dialog/search';
import type { Locale } from '../lib/locales';
import { docsCopy } from '../i18n/docs';
import { searchDocuments, validateSearchIndex } from '../lib/search';
import type { SearchDocument } from '../lib/search';

export function SearchDialog({ open, onOpenChange, locale }: {
  open: boolean; onOpenChange: (open: boolean) => void; locale: Locale;
}) {
  const copy = docsCopy[locale];
  const [query, setQuery] = useState('');
  const [documents, setDocuments] = useState<SearchDocument[]>([]);
  const [status, setStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setStatus('loading');
    fetch(`/search/${locale}.json`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('Search unavailable');
        return validateSearchIndex(await response.json(), locale);
      })
      .then((index) => { setDocuments(index); setStatus('ready'); })
      .catch(() => { if (!controller.signal.aborted) setStatus('error'); });
    return () => controller.abort();
  }, [open, locale, attempt]);
  const results = useMemo(() => searchDocuments(documents, query), [documents, query]);
  return (
    <FumaSearchDialog open={open} onOpenChange={onOpenChange} search={query} onSearchChange={setQuery}>
      <SearchDialogOverlay />
      <SearchDialogContent>
        <SearchDialogHeader>
          <SearchDialogInput placeholder={copy.searchPlaceholder} aria-label={copy.search} />
          <SearchDialogClose aria-label={copy.close} />
        </SearchDialogHeader>
        <div className="umbra-search-results" aria-live="polite">
          {status === 'loading' && <p>{copy.loading}</p>}
          {status === 'error' && <div><p>{copy.searchError}</p><button onClick={() => setAttempt((value) => value + 1)}>{copy.retry}</button></div>}
          {status === 'ready' && !query.trim() && <p>{copy.searchPlaceholder}</p>}
          {status === 'ready' && query.trim() && results.length === 0 && <p>{copy.noResults}</p>}
          {status === 'ready' && results.length > 0 && <SearchDialogList items={results.map((result) => ({ id: result.id, type: 'page', content: result.title, url: result.url }))} />}
        </div>
      </SearchDialogContent>
    </FumaSearchDialog>
  );
}
