'use client';

import { useMemo, useState } from 'react';

import type { ScanReport, SectionId, Severity } from '@/lib/types';
import { GRADE_COLOR, SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER, formatDuration } from '@/lib/ui';
import { SectionCard } from './SectionCard';

const SECTION_ORDER: SectionId[] = [
  'headers',
  'tls',
  'content',
  'exposure',
  'dns',
  'fingerprint',
];

function GradeRing({ grade, score }: { grade: string; score: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const dash = (Math.max(0, Math.min(100, score)) / 100) * circumference;
  const color = GRADE_COLOR[grade as keyof typeof GRADE_COLOR] ?? 'var(--grade-f)';

  return (
    <div className="ring">
      <svg width="126" height="126" viewBox="0 0 126 126" aria-hidden>
        <circle cx="63" cy="63" r={radius} fill="none" stroke="var(--border)" strokeWidth="9" />
        <circle
          cx="63"
          cy="63"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
        />
      </svg>
      <div className="ring-label">
        <div className="ring-grade" style={{ color }}>
          {grade}
        </div>
        <div className="ring-score">{score} / 100</div>
      </div>
    </div>
  );
}

export function ReportView({
  report,
  pollingTls,
}: {
  report: ScanReport;
  pollingTls: boolean;
}) {
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(false);

  const json = useMemo(() => JSON.stringify(report, null, 2), [report]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  const download = () => {
    const blob = new Blob([json], { type: 'application/json' });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.download = `scan-${report.target.hostname}-${report.scanId.slice(0, 8)}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
  };

  return (
    <div className="report">
      <div className="overall">
        <GradeRing grade={report.overall.grade} score={report.overall.score} />

        <div className="overall-main">
          <h2>{report.overall.headline}</h2>
          <p className="overall-target">{report.target.finalUrl ?? report.target.url}</p>

          <div className="counts">
            {SEVERITY_ORDER.map((severity) => {
              const count = report.overall.counts[severity as Severity];
              if (count === 0) return null;
              return (
                <span key={severity} className="count">
                  <span className="dot" style={{ background: SEVERITY_COLOR[severity] }} />
                  {count} {SEVERITY_LABEL[severity]}
                </span>
              );
            })}
          </div>

          {report.overall.capReason && <div className="cap-note">{report.overall.capReason}</div>}

          {report.overall.provisional && (
            <div className="provisional">
              {pollingTls && <span className="spinner" />}
              Provisional grade — the SSL Labs assessment is still running
              {pollingTls ? ' and will update here automatically.' : '.'}
            </div>
          )}
        </div>
      </div>

      {/*
        Sections are looked up defensively. A report saved before a new check
        existed simply has no entry for it, and the "Load a report" tab is
        there to render exactly those archived files — crashing on one would
        be worse than omitting a section.
      */}
      {SECTION_ORDER.filter((id) => report.sections?.[id]?.findings).map((id) => {
        const section = report.sections[id];
        return (
          <SectionCard
            key={id}
            section={section}
            defaultOpen={
              section.findings.some(
                (finding) => finding.severity === 'critical' || finding.severity === 'high',
              ) || section.status === 'error'
            }
          />
        );
      })}

      <div className="report-actions">
        <button type="button" className="btn btn-ghost" onClick={copy}>
          {copied ? 'Copied' : 'Copy JSON'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={download}>
          Download JSON
        </button>
        <button type="button" className="btn btn-ghost" onClick={() => setShowJson((v) => !v)}>
          {showJson ? 'Hide' : 'View'} raw report
        </button>
        <span className="meta">
          {formatDuration(report.durationMs)}
          {report.meta.requests ? ` · ${report.meta.requests.used} requests` : ''} · scan{' '}
          {report.scanId.slice(0, 8)}
        </span>
      </div>

      {showJson && <pre className="json-dump">{json}</pre>}

      {report.meta.notes.length > 0 && (
        <div className="notes">
          <strong>Scope and caveats</strong>
          <ul>
            {report.meta.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
