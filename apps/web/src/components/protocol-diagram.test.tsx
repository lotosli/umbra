import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { ProtocolDiagram } from './protocol-diagram';

it('provides an accessible image, independent scrolling, full-size link and native source disclosure', () => {
  render(<ProtocolDiagram locale="en" name="architecture" />);
  expect(screen.getByRole('img', { name: 'Overall architecture' })).toHaveAttribute('src', '/diagrams/protocol-design/en/architecture.svg');
  expect(screen.getByRole('region')).toHaveAttribute('tabindex', '0');
  expect(screen.getByRole('link', { name: 'Open full-size diagram' })).toHaveAttribute('target', '_blank');
  expect(screen.getByText('View Mermaid source').closest('details')?.textContent).toContain('flowchart TB');
});
it('rejects unknown diagram references', () => {
  expect(() => ProtocolDiagram({ locale: 'unknown', name: 'server' })).toThrow('Unknown protocol diagram');
});
