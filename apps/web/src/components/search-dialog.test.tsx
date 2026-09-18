import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { SearchDialog } from './search-dialog';

vi.mock('fumadocs-ui/components/dialog/search', async () => {
  const { createContext, useContext } = await import('react');
  const Context = createContext<{ search: string; onSearchChange: (value: string) => void; onOpenChange: (value: boolean) => void }>({ search: '', onSearchChange: () => {}, onOpenChange: () => {} });
  return {
    SearchDialog: ({ children, ...props }: { children: ReactNode; open: boolean; search: string; onSearchChange: (value: string) => void; onOpenChange: (value: boolean) => void }) => props.open ? <Context.Provider value={props}><div role="dialog">{children}</div></Context.Provider> : null,
    SearchDialogOverlay: () => null,
    SearchDialogHeader: ({ children }: { children: ReactNode }) => <header>{children}</header>,
    SearchDialogContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
    SearchDialogInput: (props: { 'aria-label': string }) => { const context = useContext(Context); return <input {...props} value={context.search} onChange={(event) => context.onSearchChange(event.target.value)} />; },
    SearchDialogClose: (props: { 'aria-label': string }) => { const context = useContext(Context); return <button {...props} onClick={() => context.onOpenChange(false)}>Close</button>; },
    SearchDialogList: ({ items }: { items: { id: string; content: string; url: string }[] }) => <ul>{items.map((item) => <li key={item.id}><a href={item.url}>{item.content}</a></li>)}</ul>,
  };
});

afterEach(() => vi.unstubAllGlobals());
const index = [{ id: 'reference/cli', title: 'CLI commands', description: 'Command reference', content: 'umbra server -c server.toml', url: '/en/docs/reference/cli/' }];

describe('local documentation search', () => {
  it('loads only the selected index on opening and returns canonical results', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => index });
    vi.stubGlobal('fetch', fetcher);
    const onOpenChange = vi.fn();
    const { rerender } = render(<SearchDialog locale="en" open={false} onOpenChange={onOpenChange} />);
    expect(fetcher).not.toHaveBeenCalled();
    rerender(<SearchDialog locale="en" open onOpenChange={onOpenChange} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/search/en.json', expect.objectContaining({ signal: expect.any(AbortSignal) })));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'server.toml' } });
    expect(await screen.findByRole('link', { name: 'CLI commands' })).toHaveAttribute('href', '/en/docs/reference/cli/');
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'zzzz' } });
    expect(await screen.findByText('No matching documents. Try another search.')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('shows loading, handles failures and retries without remote query writes', async () => {
    let reject: (reason: Error) => void = () => undefined;
    const fetcher = vi.fn().mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; })).mockResolvedValue({ ok: true, json: async () => index });
    vi.stubGlobal('fetch', fetcher);
    render(<SearchDialog locale="en" open onOpenChange={vi.fn()} />);
    expect(screen.getByText('Preparing search…')).toBeVisible();
    reject(new Error('offline'));
    expect(await screen.findByText('Search is unavailable. Please try again.')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(screen.queryByText('Preparing search…')).not.toBeInTheDocument());
    expect(screen.getByText('Search settings, commands or how-to guides…')).toBeVisible();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('rejects HTTP failures and malformed indexes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({ ok: false }).mockResolvedValueOnce({ ok: true, json: async () => ({ wrong: [] }) }));
    render(<SearchDialog locale="en" open onOpenChange={vi.fn()} />);
    expect(await screen.findByText('Search is unavailable. Please try again.')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Search is unavailable. Please try again.')).toBeVisible();
  });

  it('aborts an obsolete index request when closing', async () => {
    let signal: AbortSignal | undefined;
    vi.stubGlobal('fetch', vi.fn().mockImplementation((_url, options: { signal: AbortSignal }) => { signal = options.signal; return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')))); }));
    const { rerender } = render(<SearchDialog locale="en" open onOpenChange={vi.fn()} />);
    rerender(<SearchDialog locale="en" open={false} onOpenChange={vi.fn()} />);
    expect(signal?.aborted).toBe(true);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});
