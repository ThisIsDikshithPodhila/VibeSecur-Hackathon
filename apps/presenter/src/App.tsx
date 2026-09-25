import { lazy, Suspense, useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Activity, ArrowRight, ChevronDown, CircleAlert, CircleCheck, Clock3, Download, ExternalLink, FileCheck2, Fingerprint, LockKeyhole, LogOut, Play, RefreshCw, RotateCcw, SearchCheck, ShieldCheck, SquareTerminal, Wrench } from 'lucide-react';
import { ApiError, approvePayment, command, createRun, exportHref, getRun, listRuns, login, logout, session } from './api';
import type { MissionFlowStep } from './MissionFlow';
import { EvaluationSummary } from './EvaluationSummary';
import { ChapterNavigation, ChangingValue, PresenterGuidance, type PresenterCue, type PresenterSection, type PresenterTarget } from './PresentationMotion';
import { AnimatePresence, motion } from 'motion/react';
import { snapshot, type Action, type Environment, type Event, type Run } from './types';

const MissionFlow = lazy(() => import('./MissionFlow').then(module => ({ default: module.MissionFlow })));

const selectedKey = 'vibesecur-presenter-run';
const exportNames = ['incident.md', 'evidence.jsonl', 'mission.json', 'verification-contract.json', 'reproduction.zip', 'patch.diff'];
const actionMeta: { action: Action; label: string; hint: string; icon: typeof Play; tone?: 'danger' | 'positive' }[] = [
  { action: 'attack', label: 'Replay attack', hint: 'Deterministic action replay', icon: SquareTerminal, tone: 'danger' },
  { action: 'alternate-route', label: 'Try alternate route', hint: 'Test a second client path', icon: ArrowRight },
  { action: 'investigate', label: 'Investigate', hint: 'Ground report in recorded evidence', icon: SearchCheck },
  { action: 'authorize-repair', label: 'Authorize bounded repair', hint: 'Dispatch isolated repair attempt', icon: Wrench },
  { action: 'verify-bad-patch', label: 'Test UI-only bad patch', hint: 'Labelled negative control', icon: CircleAlert },
  { action: 'resume', label: 'Resume approved payment', hint: 'Fresh approval required', icon: Play, tone: 'positive' },
];
const runStateLabel = (state: string) => state.replaceAll('_', ' ').replaceAll('-', ' ');
const time = (value: number | string | undefined) => {
  if (value === undefined || value === null) return 'Not recorded';
  const parsed = typeof value === 'number' ? new Date(value < 1e12 ? value * 1000 : value) : new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
};
const money = (minor: number, currency: string) => new Intl.NumberFormat('en-AE', { style: 'currency', currency }).format(minor / 100);
const short = (value: string | undefined) => value ? `${value.slice(0, 8)}…${value.slice(-4)}` : '—';
const textValue = (value: unknown): string => typeof value === 'string' ? value : value === null || value === undefined ? 'Not available' : JSON.stringify(value, null, 2);
const epoch = (value: number | string | undefined) => {
  if (value === undefined) return Number.NaN;
  const parsed = typeof value === 'number' ? value < 1e12 ? value * 1000 : value : new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : Number.NaN;
};

function StatusPill({ label, tone = 'neutral' }: { label: string; tone?: 'neutral' | 'good' | 'warn' | 'bad' }) {
  return <span className={`status-pill ${tone}`}><span className="status-dot" /><ChangingValue value={label} /></span>;
}
function EnvironmentCard({ title, environment, variant, onApprove, busy }: { title: string; environment: Environment; variant: 'baseline' | 'protected'; onApprove: (variant: 'baseline' | 'protected') => void; busy: boolean }) {
  const tx = snapshot(environment);
  const latest = environment.ledger.at(-1);
  const currentApproval = [...environment.approvals].reverse().find(a => !a.consumed && !a.revoked && new Date(typeof a.expiresAt === 'number' && a.expiresAt < 1e12 ? a.expiresAt * 1000 : a.expiresAt).getTime() > Date.now() && a.snapshot?.beneficiaryAccount === tx.beneficiaryAccount && a.snapshot?.supplierRevision === tx.supplierRevision && a.snapshot?.invoiceRevision === tx.invoiceRevision && a.snapshot?.amountMinor === tx.amountMinor);
  return <section className={`environment-card ${variant}`} id={variant === 'protected' ? 'protected-transaction' : undefined} tabIndex={variant === 'protected' ? -1 : undefined} aria-label={`${title} payment environment`}>
    <div className="env-heading"><div><span className="eyebrow">{variant === 'baseline' ? 'Reference path' : 'Guarded path'}</span><h3>{title}</h3></div><StatusPill label={latest ? 'Ledger entry present' : 'No ledger entry'} tone={latest ? variant === 'baseline' ? 'warn' : 'good' : 'neutral'} /></div>
    <div className="invoice-line"><span>Invoice {environment.invoice.invoiceId}</span><strong>{money(environment.invoice.amountMinor, environment.invoice.currency)}</strong></div><div className="effect-summary"><ChangingValue value={String(environment.ledger.length)} /><span>{environment.ledger.length === 1 ? 'payment recorded' : 'payments recorded'}<small>Persisted ledger effects</small></span></div>
    <div className="record-row"><span>Beneficiary on record</span><code>{environment.supplier.beneficiaryAccount}</code></div>
    <div className="record-row"><span>Supplier revision</span><strong>{environment.supplier.supplierRevision}</strong></div>
    <div className="record-row"><span>Exact approval</span><strong>{currentApproval ? `Active · ${short(currentApproval.approvalId)}` : 'None available'}</strong></div>
    <div className="record-row"><span>Ledger effect</span><strong>{latest ? `${latest.status} · ${short(latest.operationId)}` : 'None recorded'}</strong></div>
    {latest && <motion.div className="receipt-box" id={variant === 'protected' ? 'protected-receipt' : undefined} tabIndex={variant === 'protected' ? -1 : undefined} role="group" aria-label={`${title} payment receipt`} key={latest.operationId} initial={{ opacity: 0 }} animate={{ opacity: 1 }}><span>Committed beneficiary</span><code>{latest.transaction.beneficiaryAccount}</code><span>Committed at {time(latest.committedAt)}</span></motion.div>}
    <button className="secondary full" disabled={busy || !environment.active} onClick={() => onApprove(variant)}><Fingerprint size={17} /> Approve exact current transaction</button>
  </section>;
}
function Evidence({ events }: { events: Event[] }) {
  const ordered = [...events].sort((a, b) => a.sequence - b.sequence);
  return <div className="event-list" aria-live="polite">{ordered.length ? ordered.map(event => <article className="event" key={event.eventId || event.sequence}>
    <div className="event-rail"><span className="event-node" /></div><div className="event-body"><div className="event-title"><strong>{runStateLabel(event.kind)}</strong><span>#{event.sequence} · {time(event.timestamp)}</span></div><details className="technical-details"><summary>Technical event details</summary><pre>{textValue(event.data)}</pre></details></div>
  </article>) : <div className="empty-state">No event evidence has been recorded for this run.</div>}</div>;
}
function ObjectDetail({ title, data, empty, id, summary, children }: { title: string; data: Record<string, unknown> | null; empty: string; id?: 'repair-record' | 'verifier-record'; summary?: string; children?: ReactNode }) {
  const status = typeof data?.status === 'string' ? runStateLabel(data.status) : typeof data?.state === 'string' ? runStateLabel(data.state) : null;
  const description = !data ? empty : summary ?? (title === 'Verifier record'
    ? data.passed === true ? 'Independent verification passed.' : data.passed === false ? 'Independent verification did not pass.' : 'Verification is in progress or has no final result.'
    : status ? `${title} status: ${status}.` : `${title} details are recorded.`);
  return <section className="detail-block" id={id} tabIndex={id ? -1 : undefined} aria-labelledby={id ? `${id}-title` : undefined}><h3 id={id ? `${id}-title` : undefined}>{title}</h3><p className={data ? 'detail-summary' : 'muted'}>{description}</p>{data && children}{data && <details className="technical-details"><summary>Technical details</summary><pre>{textValue(data)}</pre></details>}</section>;
}
function App() {
  const [accessCode, setAccessCode] = useState('');
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [run, setRun] = useState<Run | null>(null);
  const [mode, setMode] = useState<'live' | 'replay'>('replay');
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<Action | null>(null);
  const [showAllEvidence, setShowAllEvidence] = useState(false);
  const [showFlow, setShowFlow] = useState(false);
  const [selectedChapter, setSelectedChapter] = useState<PresenterSection>('business-state');
  const [connection, setConnection] = useState<'connecting' | 'connected' | 'reconnecting' | 'offline'>('connecting');
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const runId = useRef<string | null>(null);
  const busyRef = useRef(false);
  const refreshingRef = useRef(false);
  const refreshSequence = useRef(0);
  const selectionSequence = useRef(0);
  const refreshFailures = useRef(0);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const updateRun = useCallback((next: Run | null) => {
    setRun(next); runId.current = next?.runId ?? null;
    if (next) { try { localStorage.setItem(selectedKey, next.runId); } catch { /* Server state remains available if browser storage is restricted. */ } }
  }, []);
  const refresh = useCallback(async (id?: string | null) => {
    if (busyRef.current || refreshingRef.current) return;
    refreshingRef.current = true;
    const target = id === undefined ? runId.current : id;
    const sequence = ++refreshSequence.current;
    const selection = selectionSequence.current;
    const stillCurrent = () => sequence === refreshSequence.current && selection === selectionSequence.current && target === runId.current;
    try {
      const nextRun = target ? await getRun(target) : null;
      const nextRuns = await listRuns();
      if (!stillCurrent()) return;
      if (nextRun) updateRun(nextRun);
      else if (!target && nextRuns.length) updateRun(nextRuns[0]);
      setRuns(nextRuns);
      refreshFailures.current = 0;
      setConnection('connected'); setRefreshError(null); setLastUpdated(Date.now());
    } catch (reason) {
      if (!stillCurrent()) return;
      if (reason instanceof ApiError && reason.status === 401) { setAuthenticated(false); updateRun(null); setConnection('offline'); setRefreshError('Your session has expired. Sign in again to reconnect.'); return; }
      if (reason instanceof ApiError && reason.status === 404 && target) {
        try { localStorage.removeItem(selectedKey); } catch { /* Storage can be restricted. */ } updateRun(null);
        refreshFailures.current = 0; setConnection('connected'); setLastUpdated(Date.now());
        setRefreshError('This saved run is no longer available. Choose another saved run.');
        return;
      }
      else setRefreshError(reason instanceof Error ? reason.message : 'Could not refresh server state.');
      refreshFailures.current += 1;
      setConnection(refreshFailures.current >= 3 ? 'offline' : 'reconnecting');
    } finally {
      refreshingRef.current = false;
    }
  }, [updateRun]);
  useEffect(() => {
    let stopped = false;
    let retry: number | undefined;
    let failures = 0;
    const connect = async () => {
      try {
        const result = await session();
        if (stopped) return;
        setConnection('connected'); setRefreshError(null); setLastUpdated(Date.now()); setAuthenticated(result.authenticated);
        if (!result.authenticated) return;
        let last: string | null = null;
        try { last = localStorage.getItem(selectedKey); } catch { /* Reconnect to available server runs. */ }
        if (last) runId.current = last;
        await refresh(last);
      } catch (reason) {
        if (stopped) return;
        if (reason instanceof ApiError && reason.status === 401) {
          setConnection('connected'); setRefreshError(null); setAuthenticated(false); setError(null); return;
        }
        failures += 1;
        setConnection(failures >= 3 ? 'offline' : 'reconnecting');
        setRefreshError(reason instanceof Error ? reason.message : 'Presenter is unreachable. Retrying…');
        retry = window.setTimeout(() => void connect(), Math.min(1000 * 2 ** Math.min(failures, 4), 15000));
      }
    };
    void connect();
    return () => { stopped = true; if (retry !== undefined) window.clearTimeout(retry); };
  }, [refresh, updateRun]);
  useEffect(() => {
    if (!authenticated) return;
    const progressing = busy !== null || (run && /running|pending|repairing|investigating|verifying|resuming|starting/i.test(run.state));
    const timer = window.setInterval(() => { void refresh(); }, progressing ? 1000 : 3000);
    return () => window.clearInterval(timer);
  }, [authenticated, busy, refresh, run?.state]);
  useEffect(() => {
    if (!confirmAction) return;
    const previousFocus = returnFocusRef.current;
    const background = [...document.querySelectorAll<HTMLElement>('.topbar, .workspace')];
    background.forEach(element => { element.inert = true; });
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const dialog = dialogRef.current;
    const focusable = () => dialog?.querySelectorAll<HTMLElement>('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])') ?? [];
    const first = focusable()[0];
    first?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); setConfirmAction(null); }
      if (event.key !== 'Tab') return;
      const items = [...focusable()];
      if (!items.length) return;
      const firstItem = items[0], lastItem = items[items.length - 1];
      if (event.shiftKey && document.activeElement === firstItem) { event.preventDefault(); lastItem.focus(); }
      else if (!event.shiftKey && document.activeElement === lastItem) { event.preventDefault(); firstItem.focus(); }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      background.forEach(element => { element.inert = false; });
      document.body.style.overflow = previousOverflow;
      window.requestAnimationFrame(() => previousFocus?.focus());
    };
  }, [confirmAction]);
  async function guarded(label: string, task: () => Promise<Run | void>) {
    if (busyRef.current) return;
    busyRef.current = true; setBusy(label); setError(null); setNotice(null);
    try { const next = await task(); if (next) updateRun(next); setNotice(`${label} accepted. Showing persisted server state.`); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Request failed'); }
    finally { busyRef.current = false; setBusy(null); await refresh(); }
  }
  async function runMission() {
    await guarded('Run mission', async () => {
      const created = await createRun(mode); updateRun(created);
      const result = await command(created.runId, 'start'); return result.run;
    });
  }
  async function approve(variant: 'baseline' | 'protected') {
    if (!run) return;
    const current = run[variant];
    await guarded(`Approve ${variant} transaction`, async () => { await approvePayment(run.runId, variant, snapshot(current)); return await getRun(run.runId); });
  }
  async function execute(action: Action, trigger?: HTMLElement) {
    if (!run) return;
    if (action === 'reset' || action === 'authorize-repair') { if (trigger) requestConfirmation(action, trigger); return; }
    await guarded(actionMeta.find(item => item.action === action)?.label ?? runStateLabel(action), async () => (await command(run.runId, action)).run);
  }
  function requestConfirmation(action: Action, trigger: HTMLElement) {
    returnFocusRef.current = trigger;
    setConfirmAction(action);
  }
  function selectRun(selected: Run) {
    selectionSequence.current += 1;
    runId.current = selected.runId;
    updateRun(selected);
    setRefreshError(null);
    void refresh(selected.runId);
  }
  async function confirmed() {
    const action = confirmAction; setConfirmAction(null);
    if (!run || !action) return;
    await guarded(runStateLabel(action), async () => (await command(run.runId, action)).run);
  }
  async function signIn(event: React.FormEvent) {
    event.preventDefault();
    if (!accessCode.trim()) return;
    busyRef.current = true; setBusy('Sign in'); setError(null);
    try { const result = await login(accessCode); setAuthenticated(result.authenticated); setAccessCode(''); setError(null); await refresh(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Sign in failed'); }
    finally { busyRef.current = false; setBusy(null); await refresh(); }
  }
  async function signOut() {
    await guarded('Sign out', async () => { await logout(); setAuthenticated(false); updateRun(null); setRuns([]); try { localStorage.removeItem(selectedKey); } catch { /* Storage can be restricted. */ } });
  }
  if (authenticated === null) return <div className="splash" role="status" aria-live="polite"><ShieldCheck size={38}/><span>{connection === 'connecting' ? 'Connecting to VibeSecur…' : connection === 'offline' ? 'VibeSecur is offline. Retrying connection…' : 'Reconnecting to VibeSecur…'}</span>{refreshError && <small>{refreshError}</small>}</div>;
  if (!authenticated) return <main className="login-shell">
    <motion.div className="login-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <div className="login-brand"><div className="brand-icon"><ShieldCheck size={24}/></div><strong>VibeSecur</strong><span>MISSION CONTROL</span></div>
      <span className="eyebrow">AGENT ASSURANCE / HUMAN AUTHORITY</span>
      <h1>Useful work.<br/>Protected decisions.<br/><em>Proven recovery.</em></h1>
      <p>Your private workspace for the payment assurance demonstration.</p>
      <form onSubmit={signIn}><label htmlFor="access-code">Presenter access code</label><input id="access-code" type="password" autoComplete="one-time-code" value={accessCode} onChange={event => setAccessCode(event.target.value)} placeholder="Enter your access code" autoFocus /><button className="primary full" disabled={!!busy || !accessCode.trim()}>{busy || 'Open control room'} <ArrowRight size={18}/></button></form>
      {error && <p role="alert" className="alert error">{error}</p>}
      <div className="login-footnote"><LockKeyhole size={14}/><span>Private presenter session · Run state saved on the server</span></div>
    </motion.div>
    <aside className="login-aside" aria-label="Demonstration overview">
      <div className="login-aside-heading"><span className="eyebrow">ONE INVOICE. THE WHOLE STORY.</span><span className="demo-tag">SYNTHETIC SCENARIO</span></div>
      <div className="login-illustration"><div className="invoice-preview"><FileCheck2 size={26}/><span>ILLUSTRATIVE SUPPLIER INVOICE</span><strong><small>AED</small> 250,000<span>.00</span></strong><div><span>Procurement → payment</span><span>Human approval required</span></div></div>
      <div className="illustration-connector"/>
      <div className="assurance-node"><ShieldCheck size={26}/><div><strong>VibeSecur</strong><span>Govern the action. Preserve the evidence.</span></div></div>
      <div className="illustration-branches"><span>Business effect</span><span>Independent proof</span></div></div>
      <div className="login-story"><span>01 / BUSINESS</span><span>02 / INVESTIGATION</span><span>03 / RECOVERY</span></div><p>Illustrative journey · Actual results appear inside the workspace</p>
    </aside>
  </main>;
  const selectedEvents = showAllEvidence ? run?.events ?? [] : (run?.events ?? []).slice(-8);
  const repair = run?.repair;
  const verification = run?.verification;
  const deployment = repair?.deployment as Record<string, unknown> | undefined;
  const deploymentProbe = repair?.deploymentProbe as Record<string, unknown> | undefined;
  const verificationDigest = verification?.artifactDigest;
  const deploymentDigest = deployment?.artifactDigest;
  const exactArtifact = typeof verificationDigest === 'string' && verificationDigest.length > 0 && deploymentDigest === verificationDigest;
  const contained = ['contained', 'held', 'repairing', 'verifying', 'resuming', 'resumed'].includes(run?.state ?? '') && !!run?.incident;
  const candidate = repair?.status === 'candidate' && typeof repair?.artifactDigest === 'string';
  const verified = verification?.passed === true && verificationDigest === repair?.artifactDigest;
  const deployed = deployment?.deployed === true && exactArtifact &&
    deploymentProbe?.artifactDigest === verificationDigest && deploymentProbe?.imageDigest === deployment?.imageDigest &&
    deploymentProbe?.paymentRouteReady === true && deploymentProbe?.separateService === true;
  const resumed = run?.state === 'resumed' && run.events.some(event => event.kind === 'resume.payment_committed');
  const negativeControl = run?.negativeControl ?? null;
  const deployedAt = epoch(repair?.deployedAt as number | string | undefined);
  const currentProtected = run ? snapshot(run.protected) : null;
  const freshApproval = !!run && Number.isFinite(deployedAt) && run.protected.approvals.some(approval =>
    !approval.consumed && !approval.revoked && epoch(approval.createdAt) >= deployedAt && epoch(approval.expiresAt) > Date.now() &&
    !!currentProtected && ['environmentId', 'workspaceId', 'missionId', 'invoiceId', 'invoiceRevision', 'supplierId', 'supplierRevision', 'beneficiaryAccount', 'amountMinor', 'currency']
      .every(key => approval.snapshot[key as keyof typeof approval.snapshot] === currentProtected[key as keyof typeof currentProtected]));
  const liveMode = run?.mode === 'live';
  const evidenceActions = actionMeta.slice(0,3).filter(item => !(liveMode && (item.action === 'attack' || item.action === 'alternate-route')));
  const recoveryActions = actionMeta.slice(3).map(item => ({...item, disabled: item.action === 'resume' && !freshApproval}));
  const repairing = typeof repair?.status === 'string' && ['running', 'starting', 'pending'].includes(repair.status);
  const repairHeld = typeof repair?.status === 'string' && ['blocked', 'failed', 'cancelled'].includes(repair.status);
  const deploymentHeld = run?.events.some(event => event.kind === 'repair.deployment_unavailable') ?? false;
  const missionSteps: MissionFlowStep[] = [
    { id: 'containment', label: 'Containment', status: contained ? 'complete' : run?.state === 'running' ? 'active' : run?.state === 'held' ? 'held' : 'pending', detail: contained ? `Recorded in ${runStateLabel(run!.state)} state` : run?.incident ? 'Incident details recorded; containment state not confirmed' : 'No containment state recorded', targetId: 'candidate' },
    { id: 'candidate', label: 'Repair candidate', status: candidate ? 'complete' : repairing ? 'active' : repairHeld ? 'held' : 'pending', detail: candidate ? 'Candidate artifact recorded' : repairHeld ? 'Repair attempt stopped without a candidate' : repairing ? 'Repair attempt is in progress' : 'No candidate recorded', targetId: 'verification' },
    { id: 'verification', label: 'Independent verification', status: verified ? 'complete' : run?.state === 'verifying' ? 'active' : verification ? 'held' : 'pending', detail: verified ? 'Verifier passed for this artifact' : verification ? 'Verifier result did not pass for the current artifact' : 'No verifier result recorded', targetId: 'deployment' },
    { id: 'deployment', label: 'Deployment', status: deployed ? 'complete' : deploymentHeld ? 'held' : 'pending', detail: deployed ? 'Matching deployment and post-deployment probe recorded' : deploymentHeld ? 'Deployment did not complete' : 'No matching deployment recorded', targetId: 'resumption' },
    { id: 'resumption', label: 'Resumed payment', status: resumed ? 'complete' : run?.state === 'resuming' ? 'active' : deployed && !freshApproval ? 'held' : 'pending', detail: resumed ? 'Server recorded a payment commit' : deployed && !freshApproval ? 'Fresh exact approval required after deployment' : 'No resumed payment recorded' },
  ];
  // Guidance is a reading order for persisted records, never authority to advance a run.
  const presenterCue: PresenterCue = (() => {
    if (!run) return { id: 'new', chapter: '01 / Business', title: 'Start with the supplier payment', detail: 'Choose an execution mode, then run the mission to create the two isolated payment environments.', destination: 'mission-start', link: 'Choose execution mode' };
    if (['cancelled', 'reset'].includes(run.state)) return { id: 'closed', chapter: '01 / Business', title: 'Review the saved outcome', detail: 'This run has stopped. Its payment records and evidence remain available to review.', destination: 'business-state', link: 'Review payment records' };
    if (resumed) return { id: 'resumed', chapter: '03 / Resume', title: 'Payment resumption recorded', detail: 'The server recorded a resumed payment. Open the business records to show its receipt and actual ledger effect.', destination: 'business-state', target: run.protected.ledger.length ? 'protected-receipt' : 'protected-transaction', link: 'Show payment receipt', tone: 'complete' };
    if (run.state === 'resuming') return { id: 'resuming', chapter: '03 / Resume', title: 'Waiting for the payment outcome', detail: 'Resumption is in progress. The ledger will show whether a payment was committed.', destination: 'business-state', target: 'protected-transaction', link: 'Watch payment records' };
    if (repairHeld) return { id: 'repair-held', chapter: '03 / Repair', title: 'Repair needs attention', detail: 'The recorded repair attempt stopped without a candidate. Review its result before choosing another action.', destination: 'recovery-proof', target: 'repair-record', link: 'Review repair record', tone: 'attention' };
    if (repairing || run.state === 'repairing') return { id: 'repairing', chapter: '03 / Repair', title: 'Follow the bounded repair', detail: 'A repair attempt is in progress. Its output still needs independent verification.', destination: 'recovery-proof', target: 'repair-record', link: 'View repair progress' };
    if (run.state === 'verifying') return { id: 'verifying', chapter: '03 / Verification', title: 'Independent checks are in progress', detail: 'Wait for the recorded verifier result before presenting this candidate as verified.', destination: 'recovery-proof', target: 'verifier-record', link: 'View verifier record' };
    if (verification && !verified) return { id: 'verification-review', chapter: '03 / Verification', title: 'Review the verification result', detail: 'There is no matching passing result for the current repair artifact. Open the verifier record for the outcome.', destination: 'recovery-proof', target: 'verifier-record', link: 'Review verifier record', tone: 'attention' };
    if (verified && deployed) return freshApproval
      ? { id: 'resume-ready', chapter: '03 / Resume', title: 'Continue with the approved payment', detail: 'A matching deployment and fresh exact approval are recorded. Use the resume control to request the payment.', destination: 'recovery-proof', target: 'resume-control', link: 'Open resume control' }
      : { id: 'approval-needed', chapter: '03 / Resume', title: 'Review and approve the current payment', detail: 'A matching deployment is recorded. Review the protected transaction and give fresh exact approval before requesting resumption.', destination: 'business-state', target: 'protected-transaction', link: 'Review protected transaction', tone: 'attention' };
    if (deploymentHeld || verified) return { id: deploymentHeld ? 'deployment-held' : 'deployment-pending', chapter: '03 / Deployment', title: deploymentHeld ? 'Deployment needs attention' : 'Deployment is not yet confirmed', detail: 'Review the repair and verifier records. A matching deployment and readiness probe are still needed before resumption.', destination: 'recovery-proof', target: 'repair-record', link: 'Review deployment evidence', tone: deploymentHeld ? 'attention' : undefined };
    if (candidate) return { id: 'candidate', chapter: '03 / Verification', title: 'A repair candidate is recorded', detail: 'Review the candidate and its independent verification evidence before moving toward recovery.', destination: 'recovery-proof', target: 'repair-record', link: 'Review candidate and proof' };
    if (run.state === 'investigating') return { id: 'investigating', chapter: '02 / Investigation', title: 'Follow the investigation', detail: 'The saved run is investigating. Open the recorded events and findings as they become available.', destination: 'evidence-trail', link: 'View investigation' };
    if (run.incident) return { id: 'incident', chapter: '02 / Investigation', title: 'Explain the incident before repair', detail: 'An incident is recorded. Review the evidence and investigation before authorizing a bounded repair.', destination: 'evidence-trail', link: 'Review incident evidence', tone: 'attention' };
    if (run.state === 'held') return { id: 'held', chapter: '02 / Investigation', title: 'The mission is held', detail: 'Review the recorded activity to understand what needs attention. A held state alone does not establish prevention.', destination: 'evidence-trail', link: 'Review recorded activity', tone: 'attention' };
    return { id: 'business', chapter: '01 / Business', title: 'Follow the payment mission', detail: 'Start with the invoice and actual ledger effects, then open the evidence trail to follow the recorded activity.', destination: 'business-state', link: 'Show business records' };
  })();
  function navigateSection(targetId: PresenterCue['destination'], keyboard = false, detailId?: PresenterTarget) {
    if (targetId !== 'mission-start') setSelectedChapter(targetId);
    const section = document.getElementById(targetId);
    const detail = detailId ? document.getElementById(detailId) : targetId === 'mission-start' ? document.getElementById('mode') : null;
    const target = detail && !detail.matches(':disabled') ? detail : section;
    target?.scrollIntoView({ behavior: keyboard || window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start' });
    if (keyboard) target?.focus({ preventScroll: true });
  }
  function navigateStage(id: string, keyboard = false) {
    navigateSection(id === 'containment' ? 'evidence-trail' : id === 'resumption' ? 'business-state' : 'recovery-proof', keyboard);
  }
  return <div className="app-shell">
    <header className="topbar"><div className="brand"><div className="brand-icon"><ShieldCheck size={22}/></div><div><strong>VibeSecur</strong><span>ACTION FIREWALL</span></div></div><div className="topbar-center"><span className={`live-mark ${connection}`}/> PRESENTER CONTROL ROOM <span className="topbar-divider"/> <span>Payment assurance mission</span></div><div className="topbar-actions"><span data-testid="connection-status" className={`connection-label ${connection}`} role="status" aria-live="polite">{connection === 'connected' ? 'Connected' : connection === 'connecting' ? 'Connecting' : connection === 'offline' ? 'Offline · retrying' : 'Reconnecting'}</span><button className="icon-button" title="Refresh from server" aria-label="Refresh from server" onClick={() => void refresh()} disabled={!!busy}><RefreshCw size={18}/></button><button className="icon-button" title="Sign out" aria-label="Sign out" onClick={() => void signOut()} disabled={!!busy}><LogOut size={18}/></button></div></header>
    <main className="workspace">
      <section className={`hero ${run ? 'has-run' : ''}`} id="mission-start" tabIndex={-1}>
        <div><div className="section-kicker"><span className="kicker-line"/> PROCUREMENT / PAYMENT ASSURANCE <span className="demo-tag">SYNTHETIC</span></div>
          {run ? <>
            <h1 className="mission-amount">{money(run.protected.invoice.amountMinor, run.protected.invoice.currency)}<span>Payment assurance</span></h1>
            <p>Invoice {run.protected.invoice.invoiceId} · Two isolated payment environments</p>
            <div className="outcome-snapshot" aria-label="Recorded payment totals"><span><ChangingValue value={String(run.baseline.ledger.length)}/><span>Baseline payments</span></span><span><ChangingValue value={String(run.protected.ledger.length)}/><span>Protected payments</span></span><small>Recorded ledger effects</small></div>
          </> : <><h1>Useful work.<em> Accountable agents.</em></h1><p>One supplier invoice. Follow the money, understand the intervention, and see the proof of recovery.</p></>}
        </div>
        <div className="hero-controls"><label htmlFor="mode">Start a new demonstration</label><div className="mission-launch"><div className="select-wrap"><select id="mode" value={mode} onChange={event => setMode(event.target.value as 'live' | 'replay')} disabled={!!busy}><option value="live">Live agent</option><option value="replay">Deterministic replay</option></select><ChevronDown size={17}/></div><button className="primary" disabled={!!busy} onClick={() => void runMission()}><Play size={16} fill="currentColor"/> {busy === 'Run mission' ? 'Starting…' : 'Run mission'}</button></div><span className="control-note">New isolated run · Existing history stays available</span></div>
      </section>
      <div className="session-strip"><div className="run-selector"><label className="eyebrow" htmlFor="selected-run">SAVED RUN</label><select id="selected-run" aria-label="Select run" value={run?.runId ?? ''} onChange={event => { const selected = runs.find(item => item.runId === event.target.value); if (selected) selectRun(selected) }} disabled={!!busy}><option value="">{runs.length ? 'Select a saved run' : 'No saved runs'}</option>{runs.map(item => <option key={item.runId} value={item.runId}>{short(item.runId)} · {item.mode} · {runStateLabel(item.state)}</option>)}</select></div>
        <div className="session-info"><span>EXECUTION <strong>{run?.mode === 'replay' ? 'Deterministic replay' : run?.mode === 'live' ? 'Live agent requested' : 'Awaiting mission'}</strong></span><span className="updated-time">LAST SYNC <strong>{lastUpdated ? new Date(lastUpdated).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'}) : 'Connecting'}</strong></span></div>
        {run && <StatusPill label={runStateLabel(run.state)} tone={/verified|resumed|complete/i.test(run.state) ? 'good' : /blocked|failed|error/i.test(run.state) ? 'bad' : /held|contained/i.test(run.state) ? 'warn' : 'neutral'}/>}
      </div>
      {refreshError && <div data-testid="connection-error" role="status" className={`alert connection-alert ${connection}`}><CircleAlert size={18}/><span>{refreshError}{lastUpdated ? ` Last successful update: ${time(lastUpdated)}.` : ''}</span><button className="retry-button" onClick={() => void refresh()} aria-label="Retry server connection">Retry now <RefreshCw size={15}/></button></div>}
      {busy && <div className="work-status" role="status" aria-live="polite"><RefreshCw size={15}/>{busy} in progress. Waiting for the server response.</div>}
      {error && <div role="alert" className="alert error"><CircleAlert size={18}/><span>{error}</span><button onClick={() => setError(null)} aria-label="Dismiss error">×</button></div>}{notice && <div role="status" className="alert notice"><CircleCheck size={18}/><span>{notice}</span><button onClick={() => setNotice(null)} aria-label="Dismiss notice">×</button></div>}
      <section className="journey-overview" aria-label="Recovery progress">
        <PresenterGuidance cue={presenterCue} savedState={run ? runStateLabel(run.state) : 'No run selected'} onNavigate={navigateSection}><button className="text-button" aria-expanded={showFlow} aria-controls="expanded-flow" onClick={() => setShowFlow(value => !value)}>{showFlow ? 'Close workflow map' : 'Explore workflow'}<ChevronDown size={15} className={showFlow ? 'rotated' : ''}/></button></PresenterGuidance>
        <ol className="journey-steps" aria-label="Recovery checkpoints">{missionSteps.map((step, index) => <li key={step.id} data-status={step.status}><button onClick={event => navigateStage(step.id, event.detail === 0)} title={step.detail}><span className="journey-marker">{step.status === 'complete' ? <CircleCheck size={17}/> : step.status === 'held' ? <CircleAlert size={17}/> : String(index + 1).padStart(2, '0')}</span><span><strong>{step.label}</strong><small><ChangingValue value={step.status === 'complete' ? 'Recorded' : step.status === 'pending' ? 'Awaiting evidence' : step.status === 'held' ? 'Held' : 'In progress'}/></small></span></button></li>)}</ol>
        <AnimatePresence initial={false}>{showFlow && <motion.div id="expanded-flow" key="flow" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{duration: .16}} className="mission-flow-panel"><Suspense fallback={<div className="flow-loading" role="status">Opening workflow map…</div>}><MissionFlow steps={missionSteps} onStepSelect={navigateStage}/></Suspense></motion.div>}</AnimatePresence>
      </section>
      <ChapterNavigation selected={selectedChapter} onNavigate={navigateSection}/>
      <div className="areas">
        <section className="area business" id="business-state" tabIndex={-1}><div className="area-title"><div className="area-index">01</div><div><span className="eyebrow">WHAT ACTUALLY HAPPENED</span><h2>Business effect</h2></div><Activity size={21}/></div><p className="area-intro">Compare the actual ledger effects. Each environment has its own records and approval.</p>{run ? <div className="environments"><EnvironmentCard title="Baseline" environment={run.baseline} variant="baseline" onApprove={approve} busy={!!busy}/><EnvironmentCard title="Protected" environment={run.protected} variant="protected" onApprove={approve} busy={!!busy}/></div> : <div className="empty-state tall"><FileCheck2 size={34}/><strong>No mission started</strong><span>Run a mission to create the isolated baseline and protected records.</span></div>}</section>
        <section className="area evidence" id="evidence-trail" tabIndex={-1}><div className="area-title"><div className="area-index">02</div><div><span className="eyebrow">OBSERVE & INTERVENE</span><h2>Evidence trail</h2></div><LockKeyhole size={21}/></div><p className="area-intro">Follow recorded activity and open the investigation when you need the explanation.</p><div className="action-grid">{evidenceActions.map(item => <button data-testid={`action-${item.action}`} className={`action-card ${item.tone ?? ''}`} key={item.action} disabled={!run || !!busy} onClick={event => void execute(item.action, event.currentTarget)}><item.icon size={19}/><span><strong>{item.label}</strong><small>{item.hint}</small></span><ArrowRight size={16}/></button>)}</div>{liveMode && <p className="mode-note" role="status">Live mode is selected. Deterministic replay controls are available only on replay runs.</p>}<div className="evidence-top"><h3>Recorded events <span>{run?.events.length ?? 0}</span></h3>{(run?.events.length ?? 0) > 8 && <button className="text-button" onClick={() => setShowAllEvidence(!showAllEvidence)}>{showAllEvidence ? 'Latest only' : 'Show all'}</button>}</div><Evidence events={selectedEvents}/><ObjectDetail title="Intervention & investigation" data={run?.incident ?? null} empty="Investigation and incident findings have not been recorded." summary="Protected payment rule: the beneficiary, amount, currency and record revisions must match the approved transaction. Changed details require fresh approval.">
          <dl className="record-milestones"><div><dt>Investigation status</dt><dd>{typeof run?.incident?.status === 'string' ? runStateLabel(run.incident.status) : typeof run?.incident?.state === 'string' ? runStateLabel(run.incident.state) : 'Recorded'}</dd></div></dl>
          <p className="record-context">Incident findings and supporting evidence are in the technical details.</p>
        </ObjectDetail></section>
        <section className="area recovery" id="recovery-proof" tabIndex={-1}><div className="area-title"><div className="area-index">03</div><div><span className="eyebrow">REPAIR & RESUME</span><h2>Independent proof</h2></div><SearchCheck size={21}/></div><p className="area-intro">Follow the repair candidate through verification, deployment and the next approved payment.</p><div className="action-grid recovery-actions">{recoveryActions.map(item => <button id={item.action === 'resume' ? 'resume-control' : undefined} className={`action-card ${item.tone ?? ''}`} key={item.action} disabled={!run || !!busy || item.disabled} onClick={event => void execute(item.action, event.currentTarget)}><item.icon size={19}/><span><strong>{item.label}</strong><small>{item.action === 'resume' && deployed && !freshApproval ? 'Fresh exact approval required after deployment' : item.hint}</small></span><ArrowRight size={16}/></button>)}</div><ObjectDetail id="repair-record" title="Repair record" data={repair ?? null} empty="No bounded repair attempt has been recorded." summary="Repair output, independent verification and deployment are recorded separately.">
          <dl className="record-milestones">
            <div><dt>Repair output</dt><dd>{candidate ? 'Candidate recorded' : typeof repair?.status === 'string' ? runStateLabel(repair.status) : 'No candidate recorded'}</dd></div>
            <div><dt>Verification</dt><dd>{verified ? 'Passed for this artifact' : verification ? 'Matching pass not recorded' : 'Not recorded'}</dd></div>
            <div><dt>Deployment</dt><dd>{deployed ? 'Deployment and readiness probe recorded' : deploymentHeld ? 'Deployment unavailable' : 'Not recorded'}</dd></div>
          </dl>
        </ObjectDetail><ObjectDetail id="verifier-record" title="Verifier record" data={verification ?? null} empty="No independent verification result has been recorded."/><ObjectDetail title="Negative-control evidence" data={negativeControl} empty="No separate negative-control result has been recorded. This evidence does not establish repair verification."/></section>
      </div>
      <EvaluationSummary/>
      <section className="bottom-panel"><div><span className="eyebrow">REAL WORK PRODUCTS</span><h2>Evidence & handoff</h2><p>Exports are served by the current run. A missing export remains unavailable until produced by the server.</p></div><div className="exports">{exportNames.map(name => run ? <a key={name} href={exportHref(run.runId, name)} target="_blank" rel="noreferrer"><Download size={15}/>{name}<ExternalLink size={13}/></a> : <span className="disabled-export" key={name}><Download size={15}/>{name}</span>)}</div><div className="utility-actions"><button className="text-button" disabled={!run || !!busy} onClick={() => void execute('cancel')}><Clock3 size={16}/> Cancel active work</button><button data-testid="reset-run" className="text-button danger-text" disabled={!run || !!busy} onClick={event => void execute('reset', event.currentTarget)}><RotateCcw size={16}/> Reset this run</button></div></section>
      <footer><span>VIBESECUR · SYNTHETIC PAYMENT ASSURANCE</span><span>Server records are authoritative. Live agent, replay, repair and verification have distinct evidence.</span></footer>
    </main>
    <AnimatePresence>{confirmAction && <motion.div initial={{opacity: 0}} animate={{opacity: 1}} exit={{opacity: 0}} transition={{duration: .15}} className="modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) setConfirmAction(null); }}><motion.div initial={{opacity: 0, scale: .97}} animate={{opacity: 1, scale: 1}} exit={{opacity: 0, scale: .985}} transition={{duration: .18}} ref={dialogRef} data-testid="confirmation-dialog" className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><span className="eyebrow">PRESENTER CONFIRMATION</span><h2 id="confirm-title">{confirmAction === 'reset' ? 'Reset this run?' : 'Authorize bounded repair?'}</h2><p>{confirmAction === 'reset' ? 'This marks the selected run as reset and opens a new run. The original run record and ledger remain available in run history.' : 'This asks the server to dispatch a bounded repair attempt. Repair output still needs independent verification before it can count as recovery.'}</p><div><button data-testid="cancel-confirmation" className="secondary" onClick={() => setConfirmAction(null)}>Keep current run</button><button className="primary" onClick={() => void confirmed()}>{confirmAction === 'reset' ? 'Confirm reset' : 'Authorize repair'}</button></div></motion.div></motion.div>}</AnimatePresence>
  </div>;
}
export default App;
