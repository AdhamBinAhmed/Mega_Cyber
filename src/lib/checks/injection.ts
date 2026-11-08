/**
 * Client-side injection surface: DOM XSS, reflected parameters, postMessage,
 * javascript: URIs and missing CSRF tokens.
 *
 * Still strictly passive. Nothing here sends a payload, probes a parameter or
 * executes a line of JavaScript — every judgement comes from reading the HTML
 * the scanner already fetched, plus the site's own same-origin script files,
 * which is where a bundled app keeps all of its code. That buys honesty at the
 * cost of certainty: a regex cannot prove that location.hash reaches innerHTML
 * through three function calls, and it cannot prove the opposite either.
 *
 * So the severity ladder encodes confidence as much as impact:
 *
 *   - a known sink with a URL-derived source in the same expression is graded
 *     as a real finding, worded as a lead to confirm by hand;
 *   - a sink elsewhere in the same script is a pointer, not an accusation;
 *   - a sink with no source anywhere is inventory, scored at zero.
 *
 * A strict CSP demotes the DOM findings one notch: it does not remove the bug,
 * but it removes most of the ways to reach it, and a report that ignores that
 * tells a site with a nonce-based policy the same thing it tells one without.
 */

import type {
  DomSinkObservation,
  Finding,
  InjectionData,
  ReflectedParamObservation,
  Severity,
} from '../types';

/* -------------------------------------------------------------------------- */
/* Sinks and sources                                                          */
/* -------------------------------------------------------------------------- */

type SinkKind = 'html' | 'exec' | 'navigate';

interface SinkSpec {
  id: string;
  label: string;
  kind: SinkKind;
  re: RegExp;
}

/**
 * Sinks worth naming. Deliberately short: each entry has to be a place where
 * attacker-controlled text becomes markup, code or a navigation target, and
 * has to be recognisable from source without a parser.
 */
const SINKS: SinkSpec[] = [
  { id: 'innerHTML', label: '.innerHTML assignment', kind: 'html', re: /\.innerHTML\s*=(?!=)/g },
  { id: 'outerHTML', label: '.outerHTML assignment', kind: 'html', re: /\.outerHTML\s*=(?!=)/g },
  {
    id: 'insertAdjacentHTML',
    label: 'insertAdjacentHTML()',
    kind: 'html',
    re: /\.insertAdjacentHTML\s*\(/g,
  },
  {
    id: 'documentWrite',
    label: 'document.write()',
    kind: 'html',
    re: /\bdocument\s*\.\s*write(?:ln)?\s*\(/g,
  },
  { id: 'jqueryHtml', label: 'jQuery .html()', kind: 'html', re: /\.html\s*\(\s*[^)\s]/g },
  { id: 'srcdoc', label: '.srcdoc assignment', kind: 'html', re: /\.srcdoc\s*=(?!=)/g },
  { id: 'eval', label: 'eval()', kind: 'exec', re: /(?<![.\w$])eval\s*\(/g },
  { id: 'newFunction', label: 'new Function()', kind: 'exec', re: /\bnew\s+Function\s*\(/g },
  {
    id: 'timerString',
    label: 'setTimeout/setInterval with a string',
    kind: 'exec',
    re: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/g,
  },
  {
    id: 'locationAssign',
    label: 'location assignment',
    kind: 'navigate',
    re: /\b(?:location\s*\.\s*(?:href\s*=(?!=)|assign\s*\(|replace\s*\()|(?:window|document|top|self|parent)\s*\.\s*location\s*=(?!=))/g,
  },
];

/**
 * Values an attacker controls without touching the server: everything derived
 * from the URL, the referrer, the frame name, or a cross-window message.
 */
const SOURCES: Array<{ label: string; re: RegExp }> = [
  { label: 'location.hash', re: /\blocation\s*(?:\.\s*hash|\[\s*['"]hash['"]\s*\])/i },
  { label: 'location.search', re: /\blocation\s*(?:\.\s*search|\[\s*['"]search['"]\s*\])/i },
  { label: 'location.href', re: /\blocation\s*\.\s*(?:href|pathname)\b/i },
  { label: 'document.URL', re: /\bdocument\s*\.\s*(?:URL|documentURI|baseURI)\b/i },
  { label: 'document.referrer', re: /\bdocument\s*\.\s*referrer\b/i },
  { label: 'window.name', re: /\bwindow\s*\.\s*name\b/i },
  { label: 'URLSearchParams', re: /\bnew\s+URLSearchParams\s*\(/i },
  { label: 'postMessage data', re: /\b(?:event|evt|e|msg|message)\s*\.\s*data\b/i },
];

/** How far around a sink we look for a source, in characters. */
const NEAR_BEFORE = 200;
const NEAR_AFTER = 300;

function sourceIn(text: string): string | null {
  for (const source of SOURCES) {
    if (source.re.test(text)) return source.label;
  }
  return null;
}

/** One-line excerpt around an offset, whitespace collapsed, for evidence. */
function snippet(text: string, index: number, length = 130): string {
  const start = Math.max(0, index - 40);
  const raw = text.slice(start, start + length).replace(/\s+/g, ' ').trim();
  return `${start > 0 ? '…' : ''}${raw}${start + length < text.length ? '…' : ''}`;
}

/* -------------------------------------------------------------------------- */
/* HTML slicing                                                               */
/* -------------------------------------------------------------------------- */

export interface InlineScript {
  /** Script body. */
  code: string;
  /** Offset of the body within the document, for line reporting. */
  offset: number;
}

/** A same-origin script file the scanner fetched, so its code can be read. */
export interface ExternalScript {
  /** Absolute URL, used as the evidence label. */
  url: string;
  code: string;
}

/** One body of JavaScript to scan, inline or from a file. */
interface ScriptUnit {
  code: string;
  /** Script URL, or null when the code is inline in the document. */
  file: string | null;
  /** Line number, within the containing document or file, of code[0]. */
  startLine: number;
}

/**
 * Minified code: a lot of it, packed into very few lines.
 *
 * Worth detecting because proximity is the whole basis of the confidence
 * ladder here, and minification destroys it — a build tool concatenates a
 * router, a scheduler and a UI library onto one line, after which "the same
 * script" means nothing.
 */
function isMinified(code: string): boolean {
  const lines = code.split('\n').length;
  return code.length > 20_000 && code.length / lines > 2_000;
}

/** Newlines in text before `end`. */
function lineOffset(text: string, end: number): number {
  let lines = 0;
  for (let i = 0; i < end && i < text.length; i += 1) if (text[i] === '\n') lines += 1;
  return lines;
}

/** Short label for a script file: its path, which is what a developer greps. */
function fileLabel(url: string): string {
  try {
    return new URL(url).pathname.split('/').filter(Boolean).pop() ?? url;
  } catch {
    return url;
  }
}

/** "line ~12" for inline code, "app.js line ~12" for a file. */
function locate(sink: DomSinkObservation): string {
  return sink.file ? `${fileLabel(sink.file)} line ~${sink.line}` : `line ~${sink.line}`;
}

/**
 * Same-origin `<script src>` URLs, in document order, deduplicated.
 *
 * Same-origin only, deliberately: a bundled app keeps its own code on its own
 * origin, and pulling third-party CDN files would mean spending the request
 * budget on hosts the operator did not ask us to touch.
 */
export function externalScriptUrls(html: string, base: URL): string[] {
  const out: string[] = [];
  for (const match of html.matchAll(/<script\b([^>]*)>/gi)) {
    const attrs = match[1] ?? '';
    const src = attrs.match(/\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const raw = src?.[2] ?? src?.[3] ?? src?.[4];
    if (!raw) continue;
    const type = attrs.match(/\btype\s*=\s*["']?([^"'\s>]+)/i)?.[1]?.toLowerCase();
    if (type && !/javascript|module/.test(type)) continue;
    let url: URL;
    try {
      url = new URL(raw, base);
    } catch {
      continue;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
    if (url.origin !== base.origin) continue;
    const key = url.toString();
    if (!out.includes(key)) out.push(key);
  }
  return out;
}

/** Inline script bodies, skipping src= tags and non-JavaScript types. */
export function inlineScripts(html: string): InlineScript[] {
  const out: InlineScript[] = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  for (const match of html.matchAll(re)) {
    const attrs = match[1] ?? '';
    const code = match[2] ?? '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    // JSON-LD, client templates and import maps are data, not executable code.
    const type = attrs.match(/\btype\s*=\s*["']?([^"'\s>]+)/i)?.[1]?.toLowerCase();
    if (type && !/javascript|module/.test(type)) continue;
    if (code.trim().length === 0) continue;
    out.push({ code, offset: (match.index ?? 0) + match[0].indexOf(code) });
  }
  return out;
}

function tagsOf(html: string, tagName: string): string[] {
  return html.match(new RegExp(`<${tagName}\\b[^>]*>`, 'gi')) ?? [];
}

function attr(tag: string, name: string): string | null {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return match?.[2] ?? match?.[3] ?? match?.[4] ?? null;
}

/** The document with inline script bodies blanked out, preserving offsets. */
function withoutScripts(html: string): string {
  return html.replace(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi, (whole, body: string) =>
    whole.replace(body, ' '.repeat(body.length)),
  );
}

/* -------------------------------------------------------------------------- */
/* CSP posture                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Does the policy actually stop injected script from running?
 *
 * Only a nonce or hash with no unsafe-inline fallback counts, and
 * strict-dynamic cancels the credit a host allowlist would otherwise get,
 * since its whole purpose is to let trusted script load more script.
 */
export function cspBlocksInjectedScript(csp: string | null): boolean {
  if (!csp) return false;
  const directives = new Map<string, string>();
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1).join(' ').toLowerCase());
  }
  const scriptSrc = directives.get('script-src') ?? directives.get('default-src');
  if (!scriptSrc) return false;
  const pinned = /'nonce-|'sha(?:256|384|512)-/.test(scriptSrc);
  const inlineAllowed =
    scriptSrc.includes("'unsafe-inline'") && !scriptSrc.includes("'strict-dynamic'");
  return pinned && !inlineAllowed;
}

const DEMOTE: Record<Severity, Severity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'low',
  info: 'info',
  pass: 'pass',
};

/* -------------------------------------------------------------------------- */
/* Data payload                                                               */
/* -------------------------------------------------------------------------- */

const REF_DOM_XSS =
  'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html';
const REF_XSS = 'https://owasp.org/www-community/attacks/xss/';
const REF_CSRF =
  'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html';

/* -------------------------------------------------------------------------- */
/* Analysis                                                                   */
/* -------------------------------------------------------------------------- */

export function analyseInjection(
  html: string,
  pageUrl: URL,
  csp: string | null,
  /** Same-origin script files the scanner fetched, scanned alongside inline code. */
  externalScripts: ExternalScript[] = [],
  /** Same-origin script URLs referenced but not fetched, for the coverage note. */
  skippedScripts: string[] = [],
): { findings: Finding[]; data: InjectionData } {
  const findings: Finding[] = [];
  const mitigated = cspBlocksInjectedScript(csp);
  const grade = (severity: Severity): Severity => (mitigated ? DEMOTE[severity] : severity);
  const cspNote = mitigated
    ? ' Severity is reduced one level because the CSP pins inline script to a nonce or hash, which blocks the usual route to this.'
    : '';

  /* ---------------------------- DOM XSS sinks ---------------------------- */
  const scripts = inlineScripts(html);
  const inlineScriptBytes = scripts.reduce((sum, script) => sum + script.code.length, 0);
  const externalScriptBytes = externalScripts.reduce((sum, file) => sum + file.code.length, 0);

  // Inline code and fetched files are scanned the same way; only the line
  // numbering differs, since an inline body is quoted against the document and
  // a file against itself.
  const units: ScriptUnit[] = [
    ...scripts.map((script) => ({
      code: script.code,
      file: null,
      startLine: lineOffset(html, script.offset) + 1,
    })),
    ...externalScripts.map((file) => ({ code: file.code, file: file.url, startLine: 1 })),
  ];

  const sinks: DomSinkObservation[] = [];
  for (const unit of units) {
    const scriptSource = sourceIn(unit.code);
    // In a minified bundle the whole file is one line, so "a source appears
    // somewhere in this script" is true of every framework runtime ever
    // shipped and points at nothing. Only same-expression hits survive there.
    const scriptProximityMeaningful = !isMinified(unit.code);
    for (const spec of SINKS) {
      const re = new RegExp(spec.re.source, spec.re.flags);
      let match: RegExpExecArray | null;
      let perSink = 0;
      while ((match = re.exec(unit.code)) !== null && perSink < 3) {
        // The matched sink text is cut out of the window: location.href is
        // both a sink and a source, and without this `location.href = "/x"`
        // reports itself as an attacker-controlled redirect.
        const before = unit.code.slice(Math.max(0, match.index - NEAR_BEFORE), match.index);
        const end = match.index + match[0].length;
        const after = unit.code.slice(end, end + NEAR_AFTER);
        const nearSource = sourceIn(`${before} ${after}`);
        const carried = scriptProximityMeaningful ? scriptSource : null;
        sinks.push({
          sink: spec.label,
          source: nearSource ?? carried,
          proximity: nearSource ? 'expression' : carried ? 'script' : 'none',
          line: unit.startLine + lineOffset(unit.code, match.index),
          snippet: snippet(unit.code, match.index),
          file: unit.file,
        });
        perSink += 1;
      }
    }
  }

  const tainted = sinks.filter((sink) => sink.proximity === 'expression');
  const sameScript = sinks.filter((sink) => sink.proximity === 'script');
  const inventory = sinks.filter((sink) => sink.proximity === 'none');

  // One finding per sink kind, so a templating helper called twenty times does
  // not produce twenty identical rows.
  const byKind = new Map<string, DomSinkObservation[]>();
  for (const sink of tainted) {
    const list = byKind.get(sink.sink) ?? [];
    list.push(sink);
    byKind.set(sink.sink, list);
  }

  for (const [kind, group] of byKind) {
    const navigation = kind === 'location assignment';
    const sources = [...new Set(group.map((sink) => sink.source).filter(Boolean))].join(', ');
    const slug = kind.replace(/[^a-z]+/gi, '-').replace(/^-|-$/g, '').toLowerCase();
    findings.push({
      id: `injection.dom.${navigation ? 'redirect' : 'xss'}.${slug}`,
      title: navigation
        ? `Navigation target built from ${sources} (possible DOM open redirect)`
        : `${kind} fed from ${sources} (possible DOM XSS)`,
      severity: grade(navigation ? 'medium' : 'high'),
      status: 'warn',
      detail:
        (navigation
          ? 'Page script assigns a navigation target from a value an attacker controls through the URL. Unless that value is validated against an allowlist, a crafted link can bounce visitors to any site, which is the standard way a phishing page borrows your domain for credibility.'
          : `Page script passes a value an attacker controls through the URL into ${kind}, which parses its input as markup or code. If nothing sanitises it in between, a crafted link runs script in your origin — no server-side bug required, and a payload after the "#" never reaches your logs.`) +
        ' The scanner reads source without executing it, so it cannot see a sanitiser sitting in the middle: treat this as a lead to confirm by hand, not a proven bug.' +
        cspNote,
      evidence: group
        .slice(0, 3)
        .map((sink) => `${locate(sink)}: ${sink.snippet}`)
        .join('\n'),
      recommendation: navigation
        ? 'Validate the target against an allowlist of paths or origins before assigning it, and never pass user input straight to location.'
        : `Replace ${kind} with textContent, or sanitise with a maintained library such as DOMPurify and enforce it with Trusted Types.`,
      scoreImpact: mitigated ? -10 : navigation ? -12 : -20,
      references: [navigation ? REF_XSS : REF_DOM_XSS],
    });
  }

  if (sameScript.length > 0) {
    const kinds = [...new Set(sameScript.map((sink) => sink.sink))];
    findings.push({
      id: 'injection.dom.sink-and-source',
      title: `${kinds.length} HTML or code sink${kinds.length === 1 ? '' : 's'} in a script that also reads the URL`,
      severity: 'low',
      status: 'warn',
      detail:
        'The same script both reads attacker-controllable input and writes markup or evaluates code, but not in the same expression. That is the shape DOM XSS takes once a value passes through a variable or a helper, so it is worth tracing. It is equally the shape of perfectly safe code.',
      evidence: sameScript
        .slice(0, 4)
        .map((sink) => `${locate(sink)}: ${sink.sink} — ${sink.snippet}`)
        .join('\n'),
      recommendation:
        'Trace each value from the URL to the sink and confirm it is escaped or sanitised on the way.',
      scoreImpact: -5,
      references: [REF_DOM_XSS],
    });
  }

  if (inventory.length > 0 && tainted.length === 0 && sameScript.length === 0) {
    const kinds = [...new Set(inventory.map((sink) => sink.sink))];
    findings.push({
      id: 'injection.dom.sinks-present',
      title: `${kinds.length} HTML or code sink${kinds.length === 1 ? '' : 's'} used in page script`,
      severity: 'info',
      status: 'info',
      detail:
        'These calls write markup or evaluate code, but no URL-derived input appears anywhere near them. Listed as inventory: they are the lines to re-check whenever the surrounding code starts handling user input.',
      evidence: kinds.join(', '),
      scoreImpact: 0,
      references: [REF_DOM_XSS],
    });
  }

  // What the sink scan actually read, stated in the finding itself: "no DOM
  // XSS sinks" has to mean "we looked", and on a bundled app almost all of the
  // code lives in files rather than in the document.
  const scanned =
    `${(inlineScriptBytes / 1024).toFixed(1)} KB of inline script` +
    (externalScripts.length > 0
      ? ` and ${(externalScriptBytes / 1024).toFixed(1)} KB across ${externalScripts.length} same-origin script file${externalScripts.length === 1 ? '' : 's'}`
      : '');

  if (skippedScripts.length > 0) {
    findings.push({
      id: 'injection.dom.not-analysed',
      title: `${skippedScripts.length} script file${skippedScripts.length === 1 ? '' : 's'} not read, so the DOM XSS check does not cover ${skippedScripts.length === 1 ? 'it' : 'them'}`,
      severity: 'info',
      status: 'info',
      detail:
        'The page loads these same-origin script files, and the scanner did not read them — it fetches a limited number per scan so one report cannot turn into a crawl of your whole bundle. A DOM XSS sink inside one of these would not appear anywhere in this report, so the result above is a statement about the code that was read, not about the site.',
      evidence: skippedScripts.slice(0, 5).join('\n'),
      recommendation:
        'Review these files for DOM sinks by hand, or scan a page that loads fewer script files so the whole surface fits in one pass.',
      scoreImpact: 0,
      references: [REF_DOM_XSS],
    });
  }

  if (sinks.length === 0 && units.length > 0) {
    findings.push({
      id: 'injection.dom.none',
      title:
        skippedScripts.length > 0
          ? 'No DOM XSS sinks in the script that was read'
          : 'No DOM XSS sinks in page script',
      severity: 'pass',
      status: 'pass',
      detail: `Checked ${SINKS.length} sink patterns against ${scanned}.`,
      // No credit when the coverage is partial: a clean result over part of
      // the code is not evidence of a clean site.
      scoreImpact: skippedScripts.length > 0 ? 0 : 3,
    });
  }

  /* ---------------------------- postMessage ------------------------------ */
  // A listener that never checks event.origin accepts messages from any site
  // that can get a handle on the window.
  let postMessageListeners = 0;
  let postMessageOriginChecks = 0;
  const unchecked: string[] = [];

  for (const unit of units) {
    const re = /addEventListener\s*\(\s*['"`]message['"`]|\bonmessage\s*=(?!=)/gi;
    let match: RegExpExecArray | null;
    while ((match = re.exec(unit.code)) !== null) {
      // A MessageChannel port, a Worker or a socket is not the window: nobody
      // else can post to it, so there is no origin to check. React's scheduler
      // ships a MessageChannel in every bundle, and counting it as an unchecked
      // cross-window listener is a finding about the framework, not the site.
      const receiver = unit.code.slice(Math.max(0, match.index - 60), match.index);
      if (/(?:port\d?|worker|socket|ws|channel|mc|sw|registration)\s*\.\s*$/i.test(receiver)) {
        continue;
      }
      postMessageListeners += 1;
      const body = unit.code.slice(match.index, match.index + 900);
      if (/\.\s*origin\b|\boriginIsAllowed\b|\.\s*source\s*(?:===|!==|==|!=)/i.test(body)) {
        postMessageOriginChecks += 1;
      } else {
        const where = unit.file
          ? `${fileLabel(unit.file)} line ~${unit.startLine + lineOffset(unit.code, match.index)}`
          : `line ~${unit.startLine + lineOffset(unit.code, match.index)}`;
        unchecked.push(`${where}: ${snippet(unit.code, match.index)}`);
      }
    }
  }

  if (unchecked.length > 0) {
    findings.push({
      id: 'injection.postmessage.no-origin-check',
      title: `${unchecked.length} postMessage listener${unchecked.length === 1 ? '' : 's'} with no visible origin check`,
      severity: 'medium',
      status: 'warn',
      detail:
        'A message handler that does not test event.origin processes data from any page that can reach this window — anything that framed it, opened it, or was opened by it. Where the handler feeds a DOM sink that is cross-origin XSS; where it feeds application state it is a free write into your page. The check may live in a helper the scanner cannot follow, so confirm before acting.',
      evidence: unchecked.slice(0, 3).join('\n'),
      recommendation:
        'Compare event.origin against an explicit allowlist as the first statement of the handler, and validate the message shape before using it.',
      scoreImpact: -12,
      references: ['https://developer.mozilla.org/docs/Web/API/Window/message_event'],
    });
  } else if (postMessageListeners > 0) {
    findings.push({
      id: 'injection.postmessage.checked',
      title: `${postMessageListeners} postMessage listener${postMessageListeners === 1 ? '' : 's'} validate the sender`,
      severity: 'pass',
      status: 'pass',
      detail:
        'Every message handler found compares the sender origin before acting on the message.',
      scoreImpact: 2,
    });
  }

  /* --------------------------- javascript: URIs -------------------------- */
  const markup = withoutScripts(html);
  const javascriptUris = [
    ...new Set(
      [
        ...markup.matchAll(
          /\b(?:href|src|action|formaction|data)\s*=\s*["']?\s*(javascript:[^"'\s>]{0,120})/gi,
        ),
      ]
        .map((match) => match[1]!)
        .filter((uri) => !/^javascript:\s*(?:void\s*\(\s*0\s*\)\s*;?|;)\s*$/i.test(uri)),
    ),
  ];

  if (javascriptUris.length > 0) {
    findings.push({
      id: 'injection.javascript-uri',
      title: `${javascriptUris.length} javascript: URI${javascriptUris.length === 1 ? '' : 's'} in markup`,
      severity: 'low',
      status: 'warn',
      detail:
        'Executable URIs mix code into attributes, so any part of that attribute built from user input becomes a script injection point. They also force the CSP to keep allowing inline execution, which means one of these can hold back the single most effective anti-XSS control available.',
      evidence: javascriptUris.slice(0, 5).join('\n'),
      recommendation:
        'Move the code into an addEventListener handler in a script file and leave the attribute a real URL.',
      scoreImpact: -4,
      references: [REF_XSS],
    });
  }

  /* -------------------------- inline event handlers ---------------------- */
  const inlineEventHandlers = [
    ...markup.matchAll(
      /<[a-z][^>]*?\son(?:click|load|error|mouse[a-z]+|focus|blur|change|submit|input|key[a-z]+)\s*=/gi,
    ),
  ].length;

  if (inlineEventHandlers >= 5) {
    findings.push({
      id: 'injection.inline-handlers',
      title: `${inlineEventHandlers} inline event handler attributes`,
      severity: 'info',
      status: 'info',
      detail:
        "Inline handlers are script written inside markup, so the page cannot adopt a nonce-based CSP without rewriting them — they need 'unsafe-inline', which is exactly what a CSP is meant to remove. No penalty here: that cost already shows up as a weaker CSP grade.",
      evidence: `${inlineEventHandlers} occurrences, e.g. onclick / onload attributes`,
      recommendation:
        'Move handlers to addEventListener in a script file, then tighten script-src to a nonce or hash.',
      scoreImpact: 0,
    });
  }

  /* -------------------------- reflected parameters ----------------------- */
  // Observational only: this reports what the operator's own URL already
  // contained. The scanner never appends a parameter of its own.
  const reflectedParams: ReflectedParamObservation[] = [];
  for (const [param, value] of pageUrl.searchParams) {
    if (value.length < 4 || /^\d+$/.test(value)) continue;
    const index = html.indexOf(value);
    if (index === -1) continue;

    const inScript = scripts.some(
      (script) => index >= script.offset && index < script.offset + script.code.length,
    );
    const before = html.slice(Math.max(0, index - 120), index);
    const context: ReflectedParamObservation['context'] = inScript
      ? 'script'
      : /<[^>]*$/.test(before)
        ? 'attribute'
        : 'html';
    reflectedParams.push({ param, context, rawSpecialChars: /[<>"'`]/.test(value) });
  }

  const unencoded = reflectedParams.filter((entry) => entry.rawSpecialChars);
  if (unencoded.length > 0) {
    const scriptContext = unencoded.some((entry) => entry.context === 'script');
    findings.push({
      id: 'injection.reflected.unencoded',
      title: `${unencoded.length} URL parameter${unencoded.length === 1 ? '' : 's'} reflected into the page without encoding`,
      severity: grade(scriptContext ? 'high' : 'medium'),
      status: 'fail',
      detail:
        `The value of ${unencoded.map((entry) => entry.param).join(', ')} came back in the response with its angle brackets or quotes intact, in ${[...new Set(unencoded.map((entry) => entry.context))].join(' and ')} context. Unencoded reflection is the precondition for reflected XSS, and here it is observed rather than inferred.` +
        cspNote,
      evidence: unencoded
        .map(
          (entry) =>
            `${entry.param} → reflected into ${entry.context} context, special characters unescaped`,
        )
        .join('\n'),
      recommendation:
        'Encode on output for the context being written into (HTML, attribute, JavaScript, URL) rather than filtering on input, and let the template engine do it by default.',
      scoreImpact: scriptContext ? -25 : -15,
      references: [REF_XSS],
    });
  } else if (reflectedParams.length > 0) {
    findings.push({
      id: 'injection.reflected.observed',
      title: `${reflectedParams.length} URL parameter${reflectedParams.length === 1 ? '' : 's'} reflected in the response`,
      severity: 'info',
      status: 'info',
      detail:
        'These parameter values appear verbatim in the HTML. The values scanned contained no special characters, so this says nothing about whether output encoding is applied — it only marks where to test. Confirming it needs an active test, which this scanner does not perform.',
      evidence: reflectedParams.map((entry) => `${entry.param} → ${entry.context} context`).join('\n'),
      scoreImpact: 0,
      references: [REF_XSS],
    });
  }

  /* --------------------------- document.domain --------------------------- */
  const documentDomainWrites = units.reduce(
    (sum, unit) => sum + [...unit.code.matchAll(/\bdocument\s*\.\s*domain\s*=(?!=)/g)].length,
    0,
  );

  if (documentDomainWrites > 0) {
    findings.push({
      id: 'injection.document-domain',
      title: 'Script assigns document.domain',
      severity: 'low',
      status: 'warn',
      detail:
        'Writing document.domain opts the page out of strict origin isolation so sibling subdomains can script it. One compromised or user-content subdomain then reaches into this page. Browsers are removing the setter, so this is future breakage as well as a weakened boundary.',
      recommendation: 'Replace it with explicit postMessage between the frames, with origin checks.',
      scoreImpact: -5,
      references: ['https://developer.mozilla.org/docs/Web/API/Document/domain'],
    });
  }

  /* ------------------------------ CSRF tokens ---------------------------- */
  // Hidden-token absence only. Header-based and cookie-to-header schemes are
  // invisible in static HTML, which is why this stays low severity.
  const formBlocks = [...html.matchAll(/<form\b([^>]*)>([\s\S]{0,20000}?)<\/form\s*>/gi)];
  const postForms = formBlocks.filter(
    (match) => (attr(`<form ${match[1] ?? ''}>`, 'method') ?? '').toLowerCase() === 'post',
  );
  const TOKEN_NAME = /(?:csrf|xsrf|authenticity|requestverification|_token|nonce|state)/i;
  const postFormsWithoutToken = postForms.filter((match) => {
    const body = match[2] ?? '';
    return !tagsOf(body, 'input').some((tag) => {
      const type = (attr(tag, 'type') ?? '').toLowerCase();
      const name = attr(tag, 'name') ?? '';
      const id = attr(tag, 'id') ?? '';
      return type === 'hidden' && (TOKEN_NAME.test(name) || TOKEN_NAME.test(id));
    });
  }).length;

  if (postFormsWithoutToken > 0) {
    findings.push({
      id: 'injection.csrf.no-token',
      title: `${postFormsWithoutToken} POST form${postFormsWithoutToken === 1 ? '' : 's'} with no hidden anti-CSRF token`,
      severity: 'low',
      status: 'warn',
      detail:
        'No hidden token field is present on these forms, so if the server accepts the submission on cookies alone another site can make a visitor submit it. Many stacks instead rely on SameSite cookies or a header-based token, neither of which is visible in static HTML — so this is a prompt to verify, not a confirmed gap.',
      evidence: `${postFormsWithoutToken} of ${postForms.length} POST form${postForms.length === 1 ? '' : 's'} on this page`,
      recommendation:
        'Confirm the endpoint requires a per-session token, or a SameSite=Lax/Strict session cookie plus an Origin check, before accepting state-changing requests.',
      scoreImpact: -5,
      references: [REF_CSRF],
    });
  }

  const data: InjectionData = {
    inlineScriptCount: scripts.length,
    inlineScriptBytes,
    externalScriptsAnalysed: externalScripts.length,
    externalScriptBytes,
    externalScriptsSkipped: skippedScripts.length,
    inlineEventHandlers,
    domSinks: sinks.slice(0, 25),
    postMessageListeners,
    postMessageOriginChecks,
    javascriptUris: javascriptUris.slice(0, 10),
    reflectedParams,
    postFormCount: postForms.length,
    postFormsWithoutToken,
    documentDomainWrites,
    cspMitigates: mitigated,
  };

  return { findings, data };
}
