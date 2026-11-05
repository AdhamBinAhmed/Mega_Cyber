/**
 * Render the dashboard against real scan output.
 *
 * The fixtures are genuine reports captured from the live API — one healthy
 * site and one where the page could not be fetched — so this exercises the
 * shapes the components actually have to survive, including error sections and
 * null section data.
 */

import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';

import type { ScanReport, SectionId } from '@/lib/types';
import { ReportView } from '../ReportView';
import { SectionCard } from '../SectionCard';

import healthy from './fixture-report.json';
import unreachable from './fixture-unreachable.json';

const SECTIONS: SectionId[] = ['headers', 'tls', 'dns', 'exposure', 'fingerprint'];

function render(report: ScanReport, polling = false): string {
  return renderToStaticMarkup(<ReportView report={report} pollingTls={polling} />);
}

/** React escapes text content, so expected strings have to be escaped too. */
function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

describe('ReportView with a healthy site', () => {
  const report = healthy as unknown as ScanReport;
  const html = render(report);

  it('shows the overall grade, score and headline', () => {
    expect(html).toContain(report.overall.grade);
    expect(html).toContain(`${report.overall.score} / 100`);
    expect(html).toContain(esc(report.overall.headline));
  });

  it('shows the scanned URL', () => {
    expect(html).toContain(esc(report.target.finalUrl ?? report.target.url));
  });

  it('renders a card for every section', () => {
    for (const id of SECTIONS) {
      expect(html, id).toContain(esc(report.sections[id].title));
      expect(html, id).toContain(esc(report.sections[id].summary));
    }
  });

  it('offers the JSON export controls', () => {
    expect(html).toContain('Copy JSON');
    expect(html).toContain('Download JSON');
    expect(html).toContain('View raw report');
  });

  it('lists the passive-scanning caveats', () => {
    expect(html).toContain('Scope and caveats');
    for (const note of report.meta.notes) expect(html).toContain(esc(note));
  });

  it('renders severity counts for the severities present', () => {
    if (report.overall.counts.low > 0) expect(html).toContain('Low');
    if (report.overall.counts.pass > 0) expect(html).toContain('Pass');
  });
});

describe('ReportView when the page could not be fetched', () => {
  const report = unreachable as unknown as ScanReport;

  it('renders without throwing on error sections and null data', () => {
    expect(() => render(report)).not.toThrow();
  });

  it('surfaces the reason the page could not be read', () => {
    const html = render(report);
    expect(html).toContain(esc(report.overall.headline));
    expect(html).toMatch(/not run|Not assessed/);
  });

  it('marks a provisional grade and shows the spinner while polling', () => {
    const html = render(report, true);
    expect(html).toContain('Provisional grade');
    expect(html).toContain('spinner');
  });
});

describe('SectionCard', () => {
  const report = healthy as unknown as ScanReport;

  it('hides the detail until opened', () => {
    const closed = renderToStaticMarkup(
      <SectionCard section={report.sections.headers} defaultOpen={false} />,
    );
    expect(closed).toContain(esc(report.sections.headers.title));
    expect(closed).not.toContain('Graded headers');

    const open = renderToStaticMarkup(
      <SectionCard section={report.sections.headers} defaultOpen />,
    );
    expect(open).toContain('Graded headers');
  });

  it('keeps passing checks behind a toggle', () => {
    const passes = report.sections.headers.findings.filter((f) => f.severity === 'pass');
    const open = renderToStaticMarkup(
      <SectionCard section={report.sections.headers} defaultOpen />,
    );
    if (passes.length > 0) {
      expect(open).toContain(`Show ${passes.length} passing check`);
      // The pass titles themselves are not rendered until the toggle is used.
      expect(open).not.toContain(esc(passes[0]!.title));
    }
  });

  it('renders every section type without throwing', () => {
    for (const id of SECTIONS) {
      expect(() =>
        renderToStaticMarkup(<SectionCard section={report.sections[id]} defaultOpen />),
        id,
      ).not.toThrow();
    }
  });

  it('shows the error text for a section that did not run', () => {
    const broken = (unreachable as unknown as ScanReport).sections.headers;
    const html = renderToStaticMarkup(<SectionCard section={broken} defaultOpen />);
    expect(html).toContain('not run');
    if (broken.error) expect(html).toContain(esc(broken.error));
  });
});

describe('backward compatibility with older reports', () => {
  // Captured before the content section existed. The "Load a report" tab is
  // there to render archived files, so a report missing a newer section must
  // render the sections it does have rather than crashing the dashboard.
  it('renders a schema 1.0 report that has no content section', async () => {
    const legacy = (await import('./fixture-legacy-v1.json')) as unknown as {
      default: ScanReport;
    };
    const report = (legacy.default ?? legacy) as ScanReport;

    expect(report.sections).not.toHaveProperty('content');
    expect(() => render(report)).not.toThrow();

    const html = render(report);
    expect(html).toContain('HTTP Security Headers');
    expect(html).toContain('SSL / TLS');
    // The absent section is simply omitted.
    expect(html).not.toContain('Page Content &amp; Supply Chain');
  });

  it('re-grades a legacy report without throwing', async () => {
    const legacy = (await import('./fixture-legacy-v1.json')) as unknown as {
      default: ScanReport;
    };
    const report = (legacy.default ?? legacy) as ScanReport;
    const { computeOverall } = await import('@/lib/scoring');
    expect(() => computeOverall(report.sections)).not.toThrow();
    expect(computeOverall(report.sections).grade).toBeTruthy();
  });
});

describe('the current schema renders the content section', () => {
  it('shows the page content card', () => {
    const report = healthy as unknown as ScanReport;
    if (!report.sections.content) return;
    const html = render(report);
    expect(html).toContain('Page Content &amp; Supply Chain');
  });
});
