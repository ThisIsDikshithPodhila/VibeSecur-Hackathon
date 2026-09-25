import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ArrowLeft, ArrowRight, ArrowUp, Check, ChevronDown, Download, ExternalLink, FileText, Link2, Minus, Pencil, ShieldCheck, X } from 'lucide-react';
import { exportHref } from './api';
import { snapshot, type Run, type Transaction } from './types';
import { IncidentDocument } from './IncidentDocument';
import { incidentOutcomeFromRun, incidentDispositionFromRun, paymentReceiptsFromRun } from './employeeView';
import './control-panel.css';

export type IssueProvider = 'linear' | 'jira';
export type IssueDraft = { title: string; description: string; nativeFields?: Record<string, unknown> };
export type IssueResult = { provider: IssueProvider; title: string; url?: string };
export type ControlPanelProps = {
  run: Run;
  busy: string | null;
  error: string | null;
  notice: string | null;
  planDraft: string;
  connection: 'connecting' | 'connected' | 'reconnecting' | 'offline';
  connectors?: { linear: { connected: boolean }; jira: { connected: boolean } };
  issueResults?: IssueResult[];
  executors?: { id: string; label: string; connected: boolean }[];
  onBack: () => void;
  onSend: (text: string) => Promise<void>;
  onInvestigate: () => Promise<void>;
  onSavePlan: (text: string) => Promise<void>;
  onFix: () => Promise<void>;
  onApprovePayment: () => Promise<void>;
  onResume: () => Promise<void>;
  onCreateIssue: (provider: IssueProvider, draft: IssueDraft) => Promise<void>;
};

type RecordValue = Record<string, unknown>;
const record = (value: unknown): RecordValue | null => value && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : null;
const text = (value: unknown): string => typeof value === 'string' ? value : '';
const readable = (value: string) => value.replaceAll('_', ' ').replaceAll('-', ' ');
const accountLabel = (value: string) => value.length > 4 ? `•••• ${value.slice(-4).replace(/^[^a-z0-9]+/i, '')}` : value;
const strings = (value: unknown): string[] => typeof value === 'string' && value.trim() ? [value] : Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && !!item.trim()) : [];
const epoch = (value: unknown) => typeof value === 'number' ? value < 1e12 ? value * 1000 : value : typeof value === 'string' ? new Date(value).getTime() : NaN;
const money = (amount: unknown, currency: unknown) => {
  if (typeof amount !== 'number' || !Number.isFinite(amount) || typeof currency !== 'string') return 'Amount not recorded';
  try { return new Intl.NumberFormat('en-AE', { style: 'currency', currency, maximumFractionDigits: amount % 100 ? 2 : 0 }).format(amount / 100); }
  catch { return `${amount / 100} ${currency}`; }
};
const safeUrl = (value: string | undefined) => value && /^https?:\/\//i.test(value) ? value : undefined;
const date = (value: unknown) => Number.isFinite(epoch(value)) ? new Date(epoch(value)).toLocaleString() : 'Time not recorded';
const planSteps = (value: string) => value.split(/\n(?=\s*\d+[.)]\s)|\n\s*\n/).map(step => step.trim().replace(/^\d+[.)]\s+/, '')).filter(Boolean);

function Phase({ number, title, status, complete = false, active = false, children }: { number: number; title: string; status: string; complete?: boolean; active?: boolean; children: ReactNode }) {
  return <section className="cp-phase" aria-labelledby={`cp-phase-${number}`} data-complete={complete} data-active={active}>
    <span className="cp-phase-marker" aria-hidden="true">{complete ? <Check size={16}/> : number}</span>
    <div className="cp-phase-body"><div className="cp-phase-heading"><h2 id={`cp-phase-${number}`}>{title}</h2><span className="cp-phase-status">{status}</span></div>{children}</div>
  </section>;
}

function ReportField({ label, value }: { label: string; value: unknown }) {
  const parts = strings(value);
  if (!parts.length) return null;
  return <section className="cp-report-field"><h3>{label}</h3>{parts.map((part, index) => <IncidentDocument key={index} markdown={part}/>)}</section>;
}

type ProgressPhase = 'investigation' | 'repair';
const progressLabels: Record<string, string> = {
  'source.immutable_inspected': 'Source inspected',
  'investigation.reported': 'Investigation report recorded',
  'investigation.unavailable': 'Investigation unavailable',
  'repair.started': 'Repair started',
  'repair.verified': 'Repair verified',
  'repair.verification_failed': 'Verification did not pass',
  'repair.held': 'Repair held',
  'repair.deployed': 'Repair deployment recorded',
};
function ProgressDisclosure({ events, phase, running, runId }: { events: Run['events']; phase: ProgressPhase; running: boolean; runId: string }) {
  const [expanded, setExpanded] = useState(running);
  useEffect(() => { setExpanded(running); }, [running, runId, phase]);
  const rows = (Array.isArray(events) ? events : []).flatMap((event, index) => {
    const kind = typeof event.kind === 'string' ? event.kind : '';
    const belongs = phase === 'investigation'
      ? kind.startsWith('investigation.') || kind.startsWith('source.')
      : kind.startsWith('repair.');
    if (!belongs) return [];
    const label = progressLabels[kind] ?? 'Recorded activity';
    return [{ key: event.eventId || `${kind}:${event.sequence}:${index}`, label, timestamp: event.timestamp, sequence: event.sequence }];
  }).sort((left, right) => {
    const leftTime = epoch(left.timestamp);
    const rightTime = epoch(right.timestamp);
    return Number.isFinite(leftTime) && Number.isFinite(rightTime)
      ? leftTime - rightTime
      : left.sequence - right.sequence;
  });

  return <details className="cp-disclosure cp-progress" open={expanded} onToggle={event => setExpanded(event.currentTarget.open)}><summary><span>Recorded progress{rows.length ? ` · ${rows.length}` : ''}</span><ChevronDown size={16}/></summary>
    {rows.length ? <ol>{rows.map(row => <li key={row.key}><span>{row.label}</span><time>{date(row.timestamp)}</time></li>)}</ol> : <p>No recorded progress.</p>}
  </details>;
}

export function ControlPanel({ run, busy, error, notice, planDraft, connection, connectors, issueResults = [], executors = [], onBack, onSend, onInvestigate, onSavePlan, onFix, onApprovePayment, onResume, onCreateIssue }: ControlPanelProps) {
  const [draft, setDraft] = useState('');
  const [editedPlan, setEditedPlan] = useState(planDraft);
  const [editingPlan, setEditingPlan] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [issueProvider, setIssueProvider] = useState<IssueProvider | null>(null);
  const [issueDraft, setIssueDraft] = useState<IssueDraft>({ title: '', description: '' });
  const actionInFlight = useRef(false);
  const composer = useRef<HTMLTextAreaElement>(null);
  const planEditor = useRef<HTMLTextAreaElement>(null);
  const issueTitle = useRef<HTMLInputElement>(null);
  const issueTrigger = useRef<HTMLButtonElement | null>(null);
  const previousPlan = useRef(planDraft);
  const previousRun = useRef(run.runId);
  const locked = !!busy || !!pending;
  const connected = connection === 'connected';
  const dirtyPlan = editedPlan !== planDraft;

  useEffect(() => {
    const oldPlan = previousPlan.current;
    if (previousRun.current !== run.runId) {
      setDraft(''); setEditedPlan(planDraft); setEditingPlan(false); setIssueProvider(null); setLocalError(null);
      previousRun.current = run.runId;
    } else setEditedPlan(current => current === oldPlan ? planDraft : current);
    previousPlan.current = planDraft;
  }, [run.runId, planDraft]);
  useEffect(() => { if (editingPlan) planEditor.current?.focus(); }, [editingPlan]);
  useEffect(() => { if (issueProvider) issueTitle.current?.focus(); }, [issueProvider]);

  async function perform(label: string, callback: () => Promise<void>) {
    if (actionInFlight.current || busy) return;
    actionInFlight.current = true; setPending(label); setLocalError(null);
    try { await callback(); }
    catch (reason) { setLocalError(reason instanceof Error ? reason.message : 'The request could not be completed. Please try again.'); }
    finally { actionInFlight.current = false; setPending(null); }
  }
  function suggest(value: string) { setDraft(value); composer.current?.focus(); }
  async function send(event: FormEvent) {
    event.preventDefault();
    const originalDraft = draft;
    const message = originalDraft.trim();
    if (!message || !connected) return;
    await perform('Sending your request', async () => { await onSend(message); setDraft(current => current === originalDraft ? '' : current); });
  }

  const incident = record(run.incident);
  const investigation = record(run.investigation);
  const repair = record(run.repair);
  const verification = record(run.verification);
  const deployment = record(repair?.deployment);
  const probe = record(repair?.deploymentProbe);
  const current = snapshot(run.protected);
  // A recorded approval is an observation, never a new authorization decision.
  const approved = [...run.protected.approvals].reverse().find(approval =>
    (Object.keys(current) as (keyof Transaction)[]).every(key => approval.snapshot?.[key] === current[key]))?.snapshot;
  const reproducerReceipt = incident?.status === 'reproduced' ? record(incident.baselineReceipt) : null;
  const attempted = record(reproducerReceipt?.transaction);
  const publicOutcome = incidentOutcomeFromRun(run);
  const disposition = incidentDispositionFromRun(run);
  const noRepair = disposition === 'course_corrected_no_repair';
  const recoveryRequired = disposition === 'recovery_required';
  const connectedExecutors = executors.filter(executor => executor.connected);
  const paymentReceipts = paymentReceiptsFromRun(run);
  const approvedAccount = publicOutcome.status === 'blocked' ? publicOutcome.approvedAccount : approved?.beneficiaryAccount;
  const attemptedAccount = publicOutcome.status === 'blocked' ? publicOutcome.attemptedAccount : text(attempted?.beneficiaryAccount);
  const accountChanged = !!approvedAccount && !!attemptedAccount && approvedAccount !== attemptedAccount;
  const protectedReceipt = run.protected.ledger.at(-1);
  const blockedAttempt = publicOutcome.status === 'blocked';
  const attemptedAmount = publicOutcome.status === 'blocked' && publicOutcome.attemptedAmount ? publicOutcome.attemptedAmount : attempted ? money(attempted.amountMinor, attempted.currency) : 'Not confirmed';
  const markdown = text(investigation?.markdown);
  const impact = record(investigation?.actualImpact);
  const impactAmount = typeof impact?.amountMinor === 'number' && typeof impact?.currency === 'string' ? money(impact.amountMinor, impact.currency) : '';
  const impactAccount = text(impact?.beneficiaryAccount);
  const impactRecorded = impact?.baselineUnauthorizedPayment === true;
  const preventedRecorded = impact?.protectedUnauthorizedPayment === false;
  const authorizedCount = typeof impact?.protectedAuthorizedPayments === 'number' && Number.isInteger(impact.protectedAuthorizedPayments) && impact.protectedAuthorizedPayments > 0 ? impact.protectedAuthorizedPayments : 0;
  const hasStructuredReport = impactRecorded || preventedRecorded || authorizedCount > 0 || [investigation?.confirmedCause, investigation?.containment, investigation?.correction, investigation?.rollback, investigation?.acceptanceCriteria, investigation?.uncertainty].some(value => strings(value).length > 0);
  const hasReport = !!investigation && (!!markdown || hasStructuredReport);
  const cause = strings(investigation?.confirmedCause)[0];
  const investigating = run.state === 'investigating';
  const correction = strings(investigation?.correction);
  const proposedText = correction.map((step, index) => `${index + 1}. ${step}`).join('\n\n');
  const savedSteps = planSteps(planDraft);
  const candidate = repair?.status === 'candidate' && !!text(repair.artifactDigest);
  const repairRunning = ['starting', 'running', 'pending'].includes(text(repair?.status));
  const verified = verification?.passed === true && !!text(verification.artifactDigest) && verification.artifactDigest === repair?.artifactDigest;
  const deployed = verified && deployment?.deployed === true && deployment.artifactDigest === verification?.artifactDigest &&
    probe?.artifactDigest === verification?.artifactDigest && probe?.imageDigest === deployment.imageDigest && probe?.paymentRouteReady === true && probe?.separateService === true;
  const resumed = run.state === 'resumed' && run.events.some(event => event.kind === 'resume.payment_committed');
  const freshApproval = deployed && run.protected.approvals.some(approval => !approval.consumed && !approval.revoked &&
    epoch(approval.createdAt) >= epoch(repair?.deployedAt) && epoch(approval.expiresAt) > Date.now() &&
    (Object.keys(current) as (keyof Transaction)[]).every(key => approval.snapshot?.[key] === current[key]));
  const evidenceRefs = strings(investigation?.evidenceRefs);
  const corrections = run.events.filter(event => event.kind === 'vibesecur.course_correction').map(event => record(event.data)).filter((item): item is RecordValue => !!item);
  const localBoundary = run.events.some(event => event.kind === 'worker.started' && record(event.data)?.boundary === 'unmeasured_local_docker');
  const codeInvestigation = record(investigation?.codeInvestigation);
  const citations = Array.isArray(codeInvestigation?.citations) ? codeInvestigation.citations.map(record).filter((item): item is RecordValue => !!item) : [];
  const codePatch = record(codeInvestigation?.patch);
  const statusText = readable(run.state);

  function openIssue(provider: IssueProvider, trigger: HTMLButtonElement) {
    issueTrigger.current = trigger;
    setIssueDraft({ title: `Review payment approval for ${run.protected.invoice.invoiceId}`, description: [cause, planDraft].filter(Boolean).join('\n\n') });
    setIssueProvider(provider);
  }
  function closeIssue() {
    setIssueProvider(null);
    window.requestAnimationFrame(() => issueTrigger.current?.focus());
  }
  function setIssueNativeField(name: string, value: unknown) {
    setIssueDraft(currentDraft => {
      const nativeFields = { ...(currentDraft.nativeFields ?? {}) };
      if (value === '' || value === undefined || value === null) delete nativeFields[name];
      else nativeFields[name] = value;
      return { ...currentDraft, nativeFields: Object.keys(nativeFields).length ? nativeFields : undefined };
    });
  }
  const issueConnected = issueProvider ? connectors?.[issueProvider]?.connected === true : false;

  return <article className="cp-panel" aria-labelledby="cp-title">
    <div className="cp-content">
      <header className="cp-topline"><button type="button" className="cp-back" onClick={onBack}><ArrowLeft size={17}/>Back to Maya</button><span className="cp-surface-name"><ShieldCheck size={16}/>Control Panel</span></header>
      <div className="cp-hero">
        <section className="cp-intro">
          <span className="cp-incident-icon" aria-hidden="true">{blockedAttempt ? <Minus size={23}/> : <ShieldCheck size={23}/>}</span>
          <div className="cp-intro-copy"><h1 id="cp-title">{blockedAttempt ? 'Payment change blocked' : 'Review the payment change'}</h1><p>{accountChanged ? `The recorded attempt tried to send ${attemptedAmount} to a different bank account from the one approved.` : 'Review the recorded payment details and the next steps for this request.'}</p>
            <dl className="cp-impact" aria-label="Blocked attempt outcome"><div><dt>Attempted amount</dt><dd>{attemptedAmount}</dd></div><div><dt>This attempt</dt><dd data-stopped={blockedAttempt}>{blockedAttempt ? 'Nothing was sent' : 'Outcome not confirmed'}</dd></div></dl>
            {run.mode === 'replay' && <p className="cp-replay-note">Deterministic replay · recorded evidence</p>}
            {run.mode === 'live' && <p className="cp-replay-note">{localBoundary ? 'Live · local Docker runtime · network boundary not measured' : 'Live runtime'}</p>}
          </div>
        </section>
        <aside className="cp-agent-context"><div className="cp-agent-heading"><span aria-hidden="true">M</span><div><strong>Maya</strong><p>Procurement Agent</p></div></div><h2>Recorded authorization</h2>{approved ? <ul><li>Invoice {approved.invoiceId}</li><li>{money(approved.amountMinor, approved.currency)}</li><li>Account {accountLabel(approved.beneficiaryAccount)}</li></ul> : <p>No matching current approval is recorded.</p>}</aside>
      </div>
      <section className="cp-what-happened" aria-label="What happened"><h2>What happened</h2><div className="cp-comparison-content"><dl className="cp-payment-comparison" aria-label="Approved and attempted payment comparison"><div><dt>Approved account</dt><dd><strong>{approvedAccount ? accountLabel(approvedAccount) : 'Not recorded'}</strong></dd></div><ArrowRight size={20} aria-hidden="true"/><div><dt>Attempted account</dt><dd><strong>{attemptedAccount ? accountLabel(attemptedAccount) : 'Not confirmed'}</strong></dd></div></dl><div className="cp-stop-reason"><h3>Why it was stopped</h3><p>{blockedAttempt && accountChanged ? `The attempted account ${accountLabel(attemptedAccount)} did not match the approved account ${accountLabel(approvedAccount || '')}.` : 'The saved evidence does not confirm an account mismatch and stop.'}</p></div></div></section>
      {corrections.length > 0 && <section className="cp-course-corrections" aria-labelledby="cp-corrections-title"><h2 id="cp-corrections-title">VibeSecur intervened</h2>{corrections.map((item, index) => <div className="cp-correction" key={index}><Minus size={18} aria-hidden="true"/><div><p>Blocked <code>{text(item.blockedTool) || 'payment'}</code> · {readable(text(item.reason))}</p><p>Changed field{strings(item.fields).length === 1 ? '' : 's'}: {strings(item.fields).join(', ') || 'not recorded'}. Maya was told to re-read the trusted record and retry with a new operation ID.</p><p className="cp-muted">Blocked operation {text(item.operationId)}{text(item.assessmentLabel) ? ` · advisory assessment: ${readable(text(item.assessmentLabel))}` : ''}</p></div></div>)}</section>}
      {paymentReceipts.length > 0 && <section className="cp-recorded-payments" aria-label="Separate recorded payments"><h2>Recorded payments</h2><p>These receipts are separate from the blocked attempt above.</p>{paymentReceipts.map(receipt => <div className="cp-receipt" key={receipt.id}><Check size={18} aria-hidden="true"/><div><strong>{receipt.amount}</strong><p>Paid to {accountLabel(receipt.beneficiaryAccount)}</p><small>{receipt.timeLabel}</small></div></div>)}</section>}
      {noRepair && <section className="cp-no-repair" aria-labelledby="cp-no-repair-title"><Check size={22} aria-hidden="true"/><div><h2 id="cp-no-repair-title">Course corrected · no repair required</h2><p>The investigation records a safe course correction. The blocked attempt and the authorized payment remain separate records.</p><button type="button" className="cp-button" onClick={onBack}>Back to Maya<ArrowRight size={16}/></button></div></section>}
      <details className="cp-disclosure cp-source-details"><summary>Payment evidence and record IDs<ChevronDown size={16}/></summary><dl className="cp-evidence-list"><div><dt>Invoice</dt><dd>{run.protected.invoice.invoiceId}</dd></div><div><dt>Run</dt><dd>{run.runId}</dd></div><div><dt>Saved state</dt><dd>{statusText}</dd></div><div><dt>Approved account</dt><dd>{approvedAccount || 'Not recorded'}</dd></div><div><dt>Attempted account</dt><dd>{attemptedAccount || 'Not confirmed'}</dd></div><div><dt>Incident source</dt><dd>{text(incident?.source) || 'Not recorded'}</dd></div><div><dt>Incident status</dt><dd>{text(incident?.status) || 'Not recorded'}</dd></div>{protectedReceipt && <><div><dt>Latest protected receipt</dt><dd>{protectedReceipt.operationId}</dd></div><div><dt>Committed beneficiary</dt><dd>{protectedReceipt.transaction.beneficiaryAccount}</dd></div><div><dt>Committed at</dt><dd>{date(protectedReceipt.committedAt)}</dd></div></>}</dl></details>

      <div className="cp-feedback" aria-live="polite">{(!connected || busy || pending || notice) && <p role="status">{!connected ? `Connection ${connection}. Showing the last saved records.` : pending || busy || notice}</p>}{(localError || error) && <p className="cp-error" role="alert">{localError || error}</p>}</div>

      <div className="cp-process">
        <Phase number={1} title="Investigation" complete={hasReport} active={investigating} status={hasReport ? 'Report available' : investigating ? 'In progress' : 'Not available yet'}>
          <p>{cause || (investigating ? 'The investigation is in progress. Its saved findings will appear here when available.' : hasReport ? 'Review the grounded findings and any remaining uncertainty.' : 'Investigate the recorded incident to establish the cause and prepare a correction.')}</p>
          <ProgressDisclosure events={run.events} phase="investigation" running={investigating} runId={run.runId}/>
          {hasReport ? <details className="cp-disclosure cp-report"><summary><span><FileText size={16}/>View investigation</span><ChevronDown size={16}/></summary>
            <div className="cp-report-toolbar"><span>Saved investigation report</span><a href={exportHref(run.runId, 'incident.md')} target="_blank" rel="noreferrer"><Download size={15}/>Download report</a></div>
            <div className="cp-report-sections">
              {!hasStructuredReport && <p className="cp-report-empty">A structured summary is not available for this report. The original report is in technical details below.</p>}
              {impactRecorded && <ReportField label="What happened" value={`An unauthorized payment was recorded in the baseline${impactAmount ? ` for ${impactAmount}` : ''}${impactAccount ? ` to ${accountLabel(impactAccount)}` : ''}.`}/>}
              <ReportField label="Why it happened" value={investigation?.confirmedCause}/>
              {preventedRecorded && <ReportField label="What was prevented" value="The protected environment recorded no unauthorized payment."/>}
              {authorizedCount > 0 && <ReportField label="What still works" value={`${authorizedCount} authorized payment${authorizedCount === 1 ? '' : 's'} recorded in the protected environment.`}/>}
              <ReportField label="Current containment" value={investigation?.containment}/>
              <ReportField label="Proposed correction" value={investigation?.correction}/>
              <ReportField label="Rollback" value={investigation?.rollback}/>
              <ReportField label="Acceptance criteria" value={investigation?.acceptanceCriteria}/>
            </div>
            <ReportField label="Remaining uncertainty" value={investigation?.uncertainty}/>
            {codeInvestigation && <section className="cp-code-investigation" aria-label="Source investigation"><h3>Source investigation · {text(codeInvestigation.model) || 'model'} · {codeInvestigation.grounded === true ? 'grounded in cited source' : 'not grounded'}</h3>
              <ReportField label="Root cause" value={codeInvestigation.rootCause}/>
              <ReportField label="Remediation plan" value={codeInvestigation.remediationPlan}/>
              {citations.length > 0 && <><h3>Cited source at {text(codeInvestigation.baseCommit).slice(0, 12)}</h3><ul className="cp-citations">{citations.map((item, index) => <li key={index} data-verified={item.verified === true}><span>{item.verified === true ? 'Verified' : 'Not found'}</span><code>{text(item.path)}:{String(item.line ?? '')}</code><pre>{text(item.quote)}</pre></li>)}</ul></>}
              {codePatch && <details className="cp-disclosure"><summary>Proposed patch · {readable(text(codePatch.status) || 'not proposed')}<ChevronDown size={16}/></summary>{text(codePatch.patch) && <pre className="cp-patch">{text(codePatch.patch)}</pre>}<p className="cp-muted">Not applied. “Fix it” sends the saved plan to the isolated repair executor, and the result must pass independent verification.</p></details>}
            </section>}
            <details className="cp-disclosure cp-technical-details"><summary>Technical details and original report<ChevronDown size={16}/></summary>{markdown && <IncidentDocument markdown={markdown}/>}<h3>Evidence references</h3>{evidenceRefs.length ? <ul className="cp-reference-list">{evidenceRefs.map((ref, index) => <li key={index}>{ref}</li>)}</ul> : <p>No evidence references were provided in this report.</p>}<p>Assessment status: {text(investigation?.modelStatus) || 'Not recorded'}</p></details>
          </details> : <button type="button" className="cp-button" disabled={locked || !connected || investigating} onClick={() => void perform('Requesting investigation', onInvestigate)}>Investigate incident<ArrowRight size={16}/></button>}
        </Phase>

        {recoveryRequired && <>
        <Phase number={2} title="Recovery plan" complete={!!planDraft.trim()} active={editingPlan} status={dirtyPlan ? 'Unsaved changes' : planDraft.trim() ? 'Plan saved' : 'No plan saved'}>
          <div className="cp-plan-intro"><p>{planDraft.trim() ? 'Review the saved plan notes before requesting a repair.' : 'Start with the investigation’s proposed correction, then review and save the plan.'}</p><button type="button" className="cp-button cp-quiet" disabled={locked} aria-expanded={editingPlan} aria-controls="cp-plan-editor" onClick={() => setEditingPlan(value => !value)}><Pencil size={15}/>{editingPlan ? 'Close editor' : 'Edit plan'}</button></div>
          {savedSteps.length > 0 && !editingPlan && <ol className="cp-plan-list">{savedSteps.map((step, index) => <li key={index}><span aria-hidden="true">{index + 1}</span><IncidentDocument markdown={step}/></li>)}</ol>}
          {editingPlan && <div className="cp-plan-editor" id="cp-plan-editor"><label htmlFor="cp-plan-text">Remediation plan</label><textarea ref={planEditor} id="cp-plan-text" value={editedPlan} onChange={event => setEditedPlan(event.target.value)} rows={8} maxLength={4000} placeholder="Write the steps to correct the issue and verify the result." disabled={locked}/><div className="cp-editor-actions"><p>{dirtyPlan ? 'These edits are not saved.' : 'This text matches the saved plan.'}</p><button type="button" className="cp-button" disabled={locked || !connected || !dirtyPlan || !editedPlan.trim() || editedPlan.length > 4000} onClick={() => void perform('Saving plan', () => onSavePlan(editedPlan))}>Save plan</button></div></div>}
          {!planDraft.trim() && proposedText && <button type="button" className="cp-button cp-quiet" disabled={locked} onClick={() => { setEditedPlan(proposedText); setEditingPlan(true); }}>Draft from investigation<Pencil size={15}/></button>}
          {!planDraft.trim() && !proposedText && !editingPlan && <p className="cp-muted">No grounded correction is available yet. You can investigate or write a plan for review.</p>}

          <p className="cp-plan-scope">{run.remediationPlan?.executorBound && !dirtyPlan ? 'This saved plan is bound to the recorded repair request.' : 'The saved plan will be submitted with the repair request. The permitted repair scope stays fixed.'}</p>{connectedExecutors.length > 0 && <details className="cp-disclosure cp-executor-settings"><summary>Repair executor<ChevronDown size={16}/></summary><ul>{connectedExecutors.map(executor => <li key={executor.id}>{executor.label} · configured</li>)}</ul></details>}
          <form className="cp-composer" onSubmit={event => void send(event)}><label className="cp-sr-only" htmlFor="cp-message">Tell VibeSecur what to do next</label><textarea ref={composer} id="cp-message" rows={2} value={draft} onChange={event => setDraft(event.target.value)} placeholder="Tell VibeSecur what to do next…" disabled={locked} onKeyDown={event => { if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && !event.nativeEvent.isComposing) { event.preventDefault(); event.currentTarget.form?.requestSubmit(); } }}/><button type="submit" className="cp-send" aria-label="Send to VibeSecur" disabled={locked || !connected || !draft.trim()}><ArrowUp size={20}/></button></form>
          <div className="cp-suggestions" aria-label="Suggestions"><button type="button" disabled={locked || !connectedExecutors.length} onClick={() => suggest('Fix it')}><ShieldCheck size={15}/>Fix it</button><button type="button" disabled={locked} onClick={() => suggest('Change the plan')}><Pencil size={15}/>Change the plan</button><button type="button" disabled={locked} onClick={event => openIssue('linear', event.currentTarget)}><Link2 size={15}/>Create Linear issue</button><button type="button" disabled={locked} onClick={event => openIssue('jira', event.currentTarget)}><Link2 size={15}/>Create Jira ticket</button></div>

          {issueProvider && <section className="cp-issue-compose" aria-labelledby="cp-issue-title"><div className="cp-issue-heading"><div><h3 id="cp-issue-title">{issueProvider === 'linear' ? 'New Linear issue' : 'New Jira ticket'}</h3><p><span className={`cp-connector-state ${issueConnected ? 'is-connected' : ''}`}/>{issueConnected ? 'Configured for issue creation' : 'Not connected'}</p></div><button type="button" className="cp-icon-button" aria-label="Close issue draft" onClick={closeIssue} disabled={locked}><X size={18}/></button></div><form onSubmit={event => { event.preventDefault(); if (issueConnected && connected && issueDraft.title.trim() && issueDraft.description.trim()) void perform('Creating issue', () => onCreateIssue(issueProvider, issueDraft)); }}>
            <label htmlFor="cp-issue-name">Title</label><input ref={issueTitle} id="cp-issue-name" value={issueDraft.title} onChange={event => setIssueDraft(currentDraft => ({ ...currentDraft, title: event.target.value }))} disabled={locked} required/>
            <label htmlFor="cp-issue-description">Description</label><textarea id="cp-issue-description" value={issueDraft.description} onChange={event => setIssueDraft(currentDraft => ({ ...currentDraft, description: event.target.value }))} rows={6} disabled={locked} required/>
            {issueConnected && issueProvider === 'linear' && <div className="cp-provider-fields"><p className="cp-provider-scope">Uses the team configured for this integration.</p><label htmlFor="cp-linear-priority">Priority <span>(optional)</span></label><select id="cp-linear-priority" value={String(issueDraft.nativeFields?.priority ?? '')} onChange={event => setIssueNativeField('priority', event.target.value ? Number(event.target.value) : undefined)} disabled={locked}><option value="">No priority</option><option value="1">Urgent</option><option value="2">High</option><option value="3">Normal</option><option value="4">Low</option></select></div>}
            {issueConnected && issueProvider === 'jira' && <div className="cp-provider-fields"><p className="cp-provider-scope">Project and issue type use the values configured for this integration.</p><label htmlFor="cp-jira-priority">Priority name <span>(optional)</span></label><input id="cp-jira-priority" value={String((issueDraft.nativeFields?.priority as { name?: string } | undefined)?.name ?? '')} onChange={event => setIssueNativeField('priority', event.target.value.trim() ? { name: event.target.value } : undefined)} placeholder="For example, High" disabled={locked}/><p className="cp-provider-help">Enter a priority available in the configured Jira project.</p><label htmlFor="cp-jira-assignee">Assignee account ID <span>(optional)</span></label><input id="cp-jira-assignee" value={String((issueDraft.nativeFields?.assignee as { accountId?: string } | undefined)?.accountId ?? '')} onChange={event => setIssueNativeField('assignee', event.target.value.trim() ? { accountId: event.target.value.trim() } : undefined)} placeholder="Atlassian account ID" disabled={locked}/></div>}
            <div className="cp-editor-actions"><p>{issueConnected ? 'Review this draft before creating the issue.' : 'You can edit the draft. Connect this service before creating an issue.'}</p><button type="submit" className="cp-button" disabled={!issueConnected || !connected || locked || !issueDraft.title.trim() || !issueDraft.description.trim()}>Create {issueProvider === 'linear' ? 'issue' : 'ticket'}</button></div>
          </form></section>}
          {issueResults.length > 0 && <ul className="cp-created-issues" aria-label="Created issues">{issueResults.map((issue, index) => <li key={index}><Check size={16}/><span>{issue.provider === 'linear' ? 'Linear' : 'Jira'} · {safeUrl(issue.url) ? <a href={safeUrl(issue.url)} target="_blank" rel="noreferrer">{issue.title}<ExternalLink size={13}/></a> : issue.title}</span></li>)}</ul>}
        </Phase>

        <Phase number={3} title="Repair" complete={candidate} active={repairRunning} status={candidate ? 'Candidate prepared' : repair ? readable(text(repair.status) || 'Recorded') : 'Not started'}>
          <p>{candidate ? 'A repair candidate is recorded. Independent verification determines whether it fixes the issue.' : repairRunning ? 'The bounded repair attempt is running. Its saved result will appear here.' : 'Repair runs the configured bounded mission in the isolated repair environment.'}</p>
          <ProgressDisclosure events={run.events} phase="repair" running={repairRunning} runId={run.runId}/>
          {!candidate && !repairRunning && <button type="button" className="cp-button" disabled={locked || !connected || !planDraft.trim() || dirtyPlan || !connectedExecutors.length} onClick={() => void perform('Requesting bounded repair', onFix)}>Run saved plan<ArrowRight size={16}/></button>}
          {!connectedExecutors.length && !repair && <p className="cp-muted">No repair executor is connected.</p>}
          {dirtyPlan && <p className="cp-muted">Save the plan changes before requesting repair.</p>}
          {repair && <details className="cp-disclosure"><summary>Repair evidence<ChevronDown size={16}/></summary><dl className="cp-evidence-list"><div><dt>Executor status</dt><dd>{text(repair.status) || 'Not recorded'}</dd></div><div><dt>Candidate artifact</dt><dd>{text(repair.artifactDigest) || 'Not recorded'}</dd></div></dl><a className="cp-download" href={exportHref(run.runId, 'patch.diff')} target="_blank" rel="noreferrer"><Download size={15}/>Open patch artifact</a></details>}
        </Phase>
        <Phase number={4} title="Independent verification" complete={verified} active={run.state === 'verifying'} status={verified ? 'Passed' : run.state === 'verifying' ? 'In progress' : verification ? 'Review required' : 'Not recorded'}>
          <p>{verified ? 'The verifier passed for the current repair artifact.' : verification ? 'A matching passing result has not been recorded for the current artifact.' : 'The repair must pass independent checks before it counts as a verified fix.'}</p>
          <div className="cp-deployment"><span>Deployment</span><strong>{deployed ? 'Matching deployment and readiness probe recorded' : 'Not confirmed'}</strong></div>
          {verification && <details className="cp-disclosure"><summary>Verification and deployment evidence<ChevronDown size={16}/></summary><dl className="cp-evidence-list"><div><dt>Verifier result</dt><dd>{verification.passed === true ? 'Passed' : verification.passed === false ? 'Did not pass' : 'No final result'}</dd></div><div><dt>Verified artifact</dt><dd>{text(verification.artifactDigest) || 'Not recorded'}</dd></div><div><dt>Deployed artifact</dt><dd>{text(deployment?.artifactDigest) || 'Not recorded'}</dd></div><div><dt>Deployed at</dt><dd>{date(repair?.deployedAt)}</dd></div></dl></details>}
        </Phase>
        <Phase number={5} title="Resume the workflow" complete={resumed} active={run.state === 'resuming'} status={resumed ? 'Payment recorded' : run.state === 'resuming' ? 'In progress' : 'Not resumed'}>
          <p>{resumed ? 'A resumed payment is recorded. Return to Maya to continue the conversation.' : deployed ? 'Review the current payment, give fresh exact approval, then request resumption.' : 'Resumption follows independent verification, deployment and fresh approval of the exact payment.'}</p>
          {resumed && protectedReceipt && <div className="cp-receipt"><span>Protected payment receipt</span><strong>{money(protectedReceipt.transaction.amountMinor, protectedReceipt.transaction.currency)}</strong><p>Paid to {accountLabel(protectedReceipt.transaction.beneficiaryAccount)}</p><small>{date(protectedReceipt.committedAt)}</small></div>}
          <div className="cp-return-actions">{!resumed && deployed && <><button type="button" className="cp-button" disabled={locked || !connected} onClick={() => void perform('Requesting exact payment approval', onApprovePayment)}>Approve current payment</button><button type="button" className="cp-button" disabled={locked || !connected || !freshApproval} onClick={() => void perform('Requesting payment resumption', onResume)}>Resume approved payment</button></>}<button type="button" className="cp-button cp-quiet" onClick={onBack}>Back to Maya<ArrowRight size={16}/></button></div>
        </Phase>
        </>}
        {!recoveryRequired && !noRepair && <p className="cp-unresolved" role="status">The investigation has not established whether an application repair is needed.</p>}
      </div>
    </div>
  </article>;
}
export default ControlPanel;
