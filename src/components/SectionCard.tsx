'use client';

import { useState } from 'react';

import type { SectionReport } from '@/lib/types';
import { GRADE_COLOR, tint } from '@/lib/ui';
import { FindingItem } from './FindingItem';
import { SectionDetails } from './SectionDetails';

export function SectionCard({
  section,
  defaultOpen = false,
}: {
  section: SectionReport<unknown>;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const color = GRADE_COLOR[section.grade];
  const unscored = section.status === 'error' || section.status === 'skipped';

  // Keep the loudest findings visible; passes sit behind a toggle.
  const [showPasses, setShowPasses] = useState(false);
  const issues = section.findings.filter((finding) => finding.severity !== 'pass');
  const passes = section.findings.filter((finding) => finding.severity === 'pass');
  const visible = showPasses ? [...issues, ...passes] : issues;

  return (
    <section className="section">
      <button
        type="button"
        className="section-head"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span
          className="section-grade"
          style={{
            color: unscored ? 'var(--text-faint)' : color,
            borderColor: unscored ? 'var(--border)' : tint(color, 40),
            background: unscored ? 'var(--surface)' : tint(color, 12),
          }}
        >
          {unscored ? '–' : section.grade}
        </span>

        <span className="section-info">
          <h3>
            {section.title}
            {section.status === 'pending' && <span className="badge badge-pending">in progress</span>}
            {section.status === 'error' && <span className="badge badge-error">not run</span>}
            {section.status === 'skipped' && <span className="badge badge-error">skipped</span>}
          </h3>
          <p>{section.summary}</p>
        </span>

        {!unscored && (
          <span className="section-meter">
            <span className="meter-track">
              <span
                className="meter-fill"
                style={{ width: `${section.score}%`, background: color }}
              />
            </span>
            <span className="meter-value">
              {section.score}/100 · {section.weight}% weight
            </span>
          </span>
        )}

        <svg
          className="caret"
          data-open={open}
          width="14"
          height="14"
          viewBox="0 0 16 16"
          fill="none"
          aria-hidden
        >
          <path d="M6 3l5 5-5 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      </button>

      {open && (
        <div className="section-body">
          {visible.length > 0 ? (
            visible.map((finding) => <FindingItem key={finding.id} finding={finding} />)
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: 13.5 }}>
              {passes.length > 0 ? 'No issues found in this section.' : 'Nothing to report.'}
            </p>
          )}

          {passes.length > 0 && (
            <button
              type="button"
              className="btn btn-ghost"
              style={{ marginTop: 12 }}
              onClick={() => setShowPasses((value) => !value)}
            >
              {showPasses ? 'Hide' : 'Show'} {passes.length} passing check
              {passes.length === 1 ? '' : 's'}
            </button>
          )}

          <SectionDetails section={section} />
        </div>
      )}
    </section>
  );
}
