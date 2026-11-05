import type { Finding } from '@/lib/types';
import { SEVERITY_COLOR, SEVERITY_LABEL, tint } from '@/lib/ui';

export function FindingItem({ finding }: { finding: Finding }) {
  const color = SEVERITY_COLOR[finding.severity];

  return (
    <div className="finding">
      <span className="sev-dot" style={{ background: color }} aria-hidden />
      <div>
        <div className="finding-title">
          <span>{finding.title}</span>
          <span
            className="sev-tag"
            style={{ color, borderColor: tint(color, 40), background: tint(color, 12) }}
          >
            {SEVERITY_LABEL[finding.severity]}
          </span>
          {finding.scoreImpact !== 0 && (
            <span className="impact">
              {finding.scoreImpact > 0 ? '+' : ''}
              {finding.scoreImpact} pts
            </span>
          )}
        </div>

        <p>{finding.detail}</p>

        {finding.evidence && <div className="evidence">{finding.evidence}</div>}

        {finding.recommendation && (
          <div className="fix">
            <b>Fix:</b> {finding.recommendation}
          </div>
        )}

        {finding.references && finding.references.length > 0 && (
          <div className="refs">
            {finding.references.map((href) => (
              <a key={href} href={href} target="_blank" rel="noopener noreferrer nofollow">
                {hostOf(href)} ↗
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function hostOf(href: string): string {
  try {
    const url = new URL(href);
    const path = url.pathname.replace(/\/$/, '');
    const tail = path.split('/').filter(Boolean).pop();
    return tail ? `${url.hostname}/…/${tail}` : url.hostname;
  } catch {
    return href;
  }
}
