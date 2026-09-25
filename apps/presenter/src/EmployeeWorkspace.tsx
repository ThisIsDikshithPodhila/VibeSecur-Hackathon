import { useMemo, useState, type ReactNode } from 'react';
import { AlertCircle, ArrowRight, BriefcaseBusiness, Check, Circle, FileText, MessageCircle, Minus, MoreHorizontal, RefreshCw, UserRound } from 'lucide-react';
import type { Run } from './types';
import { AssistantConversation, type ConversationMarker } from './AssistantConversation';
import {
  activityFromRun, conversationFromRun, incidentOutcomeFromRun, incidentDispositionFromRun, workflowSuggestions,
  paymentReceiptsFromRun, maskAccount, modeLabel, runCreatedLabel, stateLabel, taskBriefFromRun,
  type EmployeeActivity, type EmployeeConnectionStatus,
} from './employeeView';
import './employee-workspace.css';

export type EmployeeRunMode = 'live' | 'replay';
export type EmployeeWorkspaceProps = {
  run: Run | null;
  savedRuns: Run[];
  connectionStatus: EmployeeConnectionStatus;
  busy?: boolean;
  error?: string | null;
  notice?: string | null;
  rightPanel?: ReactNode;
  onSend: (text: string) => Promise<unknown>;
  onStart: (mode: EmployeeRunMode) => void | Promise<void>;
  onSelectRun: (run: Run) => void | Promise<void>;
  onViewIncident: () => void | Promise<void>;
  onApprovePayment: () => Promise<void>;
  onReset?: () => void;
  onRefresh: () => void | Promise<void>;
  onSignOut: () => void | Promise<void>;
};

function ActivityItem({ activity }: { activity: EmployeeActivity }) {
  return <li className={`employee-activity is-${activity.status}`}>
    <span className="employee-activity__marker" aria-hidden="true">{activity.status === 'succeeded' ? <Check size={16}/> : activity.status === 'blocked' ? <Minus size={17}/> : activity.status === 'failed' ? <AlertCircle size={16}/> : <Circle size={18}/>}</span>
    <div className="employee-activity__body"><div className="employee-activity__heading"><strong>{activity.title}</strong><time>{activity.timeLabel}</time></div>{activity.description && <p>{activity.description}</p>}</div>
  </li>;
}

export function EmployeeWorkspace({ run, savedRuns, connectionStatus, busy = false, error, notice, rightPanel, onSend, onStart, onSelectRun, onViewIncident, onReset, onRefresh }: EmployeeWorkspaceProps) {
  const [activeSection, setActiveSection] = useState<'chat' | 'work' | 'activity'>('chat');
  const [modeToStart, setModeToStart] = useState<EmployeeRunMode>('live');
  const [startPending, setStartPending] = useState(false);
  const [utilityError, setUtilityError] = useState<string | null>(null);
  const activities = useMemo(() => activityFromRun(run), [run]);
  const conversation = useMemo(() => conversationFromRun(run), [run]);
  const brief = useMemo(() => taskBriefFromRun(run), [run]);
  const incident = useMemo(() => incidentOutcomeFromRun(run), [run]);
  const suggestions = useMemo(() => workflowSuggestions(run), [run]);
  const receipts = useMemo(() => paymentReceiptsFromRun(run), [run]);
  const disposition = incidentDispositionFromRun(run);
  const isOffline = connectionStatus !== 'connected';
  const conversationState = run?.conversation as { turns?: { status?: string }[] } | undefined;
  const running = run?.mode === 'live' && !!conversationState?.turns?.some(turn => turn.status === 'running');
  const queued = run?.mode === 'live' && !!conversationState?.turns?.some(turn => turn.status === 'queued');
  const replay = run?.mode === 'replay';
  const activeError = utilityError || error;

  async function perform(callback: () => unknown | Promise<unknown>, failure: string) {
    setUtilityError(null);
    try { await callback(); } catch { setUtilityError(failure); }
  }
  async function startRun() {
    if (startPending || busy || isOffline) return;
    setStartPending(true);
    try { await perform(async () => { await onStart(modeToStart); setActiveSection('chat'); }, 'The work session could not be started. Please try again.'); }
    finally { setStartPending(false); }
  }
  function selectRun(id: string) {
    const selected = savedRuns.find(item => item.runId === id);
    if (selected) void perform(async () => { await onSelectRun(selected); setActiveSection('chat'); }, 'This saved work could not be opened.');
  }
  const viewIncident = () => void perform(onViewIncident, 'The incident details could not be opened.');
  const blockedCard = incident.status === 'blocked' ? <article className="employee-blocked-card" aria-label="Blocked payment attempt">
    <div className="employee-blocked-card__header"><span className="employee-stop-icon" aria-hidden="true"><Minus size={22}/></span><h2>VibeSecur stopped an action</h2><time>{incident.timeLabel || 'Recorded incident'}</time></div>
    <div className="employee-blocked-card__body"><p>Maya tried to send the approved payment to a different bank account. VibeSecur blocked it — no payment was sent — and told her to use the approved account.</p><button className="employee-link-button" type="button" onClick={viewIncident}>View what happened <ArrowRight size={17} aria-hidden="true"/></button></div>
    <dl><div><dt>{incident.attemptedAmount ? 'Attempted amount' : 'Invoice amount'}</dt><dd>{incident.attemptedAmount || brief.amount || 'Not recorded'}</dd></div><div><dt>Attempted account</dt><dd>{maskAccount(incident.attemptedAccount)}</dd></div><div><dt>Approved account</dt><dd>{maskAccount(incident.approvedAccount)}</dd></div></dl>
  </article> : null;
  const markers: ConversationMarker[] = incident.status === 'blocked' ? [{ id: incident.id, sequence: incident.sequence ?? Number.MAX_SAFE_INTEGER - 1, content: blockedCard }] : [];
  for (const receipt of receipts) markers.push({ id: `receipt-${receipt.id}`, sequence: receipt.sequence ?? Number.MAX_SAFE_INTEGER, content: <article className="employee-receipt" aria-label="Recorded payment receipt"><Check size={20} aria-hidden="true"/><div><strong>Payment recorded</strong><p>{receipt.amount} to {maskAccount(receipt.beneficiaryAccount)}</p><time>{receipt.timeLabel}</time></div></article> });
  const feedItems = activities.map(activity => ({ id: activity.id, sequence: activity.sequence, content: <ActivityItem activity={activity}/> }));
  feedItems.sort((a, b) => a.sequence - b.sequence);
  const feedback = <>{queued && <p className="employee-feedback" role="status">Your request is queued.</p>}{incident.status === 'unavailable' && <p className="employee-outcome-unavailable" role="status">The payment outcome is not confirmed in this saved run.</p>}{activeError && <p className="employee-feedback is-error" role="alert">{activeError}</p>}{notice && <p className="employee-feedback" role="status">{notice}</p>}</>;

  return <main className="employee-workspace">
    <header className="employee-topbar">
      <div className="employee-brand" aria-label="VibeSecur"><span className="employee-brand__mark" aria-hidden="true"><MessageCircle size={22}/></span><span>VibeSecur</span></div>
      <nav className="employee-nav" aria-label="Main navigation">{([['chat', 'Chat'], ['work', 'Work'], ['activity', 'Activity']] as const).map(([id, label]) => <button key={id} type="button" className={activeSection === id ? 'is-active' : ''} aria-current={activeSection === id ? 'page' : undefined} onClick={() => setActiveSection(id)}>{label}</button>)}</nav>
      <div className="employee-topbar__actions"><span className={`employee-security-mark is-${connectionStatus}`} role="status"><span aria-hidden="true"/>{connectionStatus === 'connected' ? 'VibeSecur ON' : connectionStatus === 'reconnecting' ? 'Reconnecting' : 'Offline'}</span><span className="employee-account-menu" aria-hidden="true"><UserRound size={20}/></span></div>
    </header>
    <div className={`employee-layout${rightPanel ? ' has-control-panel' : ''}`}>
      <section className="employee-chat-panel" aria-labelledby="employee-chat-title">
        <div className="employee-chat-header"><div className="employee-avatar" aria-hidden="true">M</div><div className="employee-chat-header__copy"><h1 id="employee-chat-title">Maya</h1><p>Procurement Agent</p><p className="employee-maya-description">I help review supplier invoices and prepare payments.</p></div><button className="employee-icon-button employee-work-settings" type="button" aria-label="Open work settings" onClick={() => setActiveSection('work')}><MoreHorizontal size={20}/></button></div>
        {activeSection === 'chat' ? <AssistantConversation key={run?.runId || 'new'} messages={conversation} markers={markers} replay={replay} busy={busy || queued} offline={isOffline} running={running} suggestions={suggestions} onSend={onSend} feedback={feedback} empty={<div className="employee-empty-state"><MessageCircle size={28} aria-hidden="true"/><h2>What would you like to work on?</h2><p>{run ? 'Send Maya a message to continue this work.' : 'Send Maya a message or choose a suggestion below.'}</p>{replay && <p>Deterministic replay · no conversation was saved.</p>}</div>}/> : <div className="employee-chat-body employee-history">
          <div className="employee-subheading"><h2>{activeSection === 'work' ? 'Saved work' : 'Recorded activity'}</h2><button className="employee-icon-button" type="button" aria-label="Refresh saved runs" onClick={() => void perform(onRefresh, 'Saved work could not be refreshed.')}><RefreshCw size={18}/></button></div>
          {activeSection === 'work' ? <><label className="employee-run-select-label" htmlFor="employee-saved-run">Open a saved run</label><select id="employee-saved-run" value={run?.runId || ''} onChange={event => selectRun(event.target.value)}><option value="">Select saved work</option>{savedRuns.map(item => <option key={item.runId} value={item.runId}>{modeLabel(item.mode)} · {runCreatedLabel(item)}</option>)}</select><ul className="employee-run-list">{savedRuns.map(item => <li key={item.runId}><button type="button" onClick={() => selectRun(item.runId)} aria-current={item.runId === run?.runId ? 'true' : undefined}><strong>{modeLabel(item.mode)}</strong><span>{runCreatedLabel(item)} · {stateLabel(item.state)}</span></button></li>)}</ul><details className="employee-run-settings"><summary>Run settings</summary><div className="employee-start-controls"><label htmlFor="employee-run-mode">Run mode</label><select id="employee-run-mode" value={modeToStart} onChange={event => setModeToStart(event.target.value as EmployeeRunMode)}><option value="live">Live agent</option><option value="replay">Deterministic replay</option></select><button type="button" className="employee-primary-button" disabled={busy || startPending || isOffline} onClick={() => void startRun()}>{startPending ? 'Starting…' : 'Start work session'}</button></div>{run && onReset && <button className="employee-reset-button" type="button" onClick={onReset}>Reset this run</button>}</details></> : <ol className="employee-timeline">{feedItems.map(item => <ReactNodeRow key={item.id}>{item.content}</ReactNodeRow>)}</ol>}
          {feedback}
        </div>}
      </section>
      <aside className={`employee-work-panel${rightPanel ? ' is-control-panel' : ''}`} aria-label={rightPanel ? 'Incident control panel' : 'Current work'}>{rightPanel || <>
        <section className="employee-work-card"><div className="employee-work-card__header"><div><h2>Maya’s work</h2><p>{running ? 'Real-time progress on your request.' : replay ? 'Recorded activity · deterministic replay.' : 'Activity from your work session.'}</p></div>{running && <span className="employee-live-label"><span/>Live</span>}</div>{feedItems.length ? <ol className="employee-timeline" aria-label="Recorded work timeline">{feedItems.map(item => <ReactNodeRow key={item.id}>{item.content}</ReactNodeRow>)}</ol> : <div className="employee-empty-work"><BriefcaseBusiness size={22}/><p>Work activity will appear here.</p></div>}</section>
        {run && brief.hasDetails && <section className="employee-task-card"><h2>Current request</h2><div className="employee-request-heading"><span><FileText size={22}/></span><div><strong>Supplier payment</strong><p>{[brief.invoice, brief.supplier].filter(Boolean).join(' · ')}</p></div></div><dl>{brief.amount && <div><dt>Amount</dt><dd>{brief.amount}</dd></div>}{disposition === 'course_corrected_no_repair' && <div><dt>Outcome</dt><dd><span className="employee-state-chip is-complete">Course corrected</span></dd></div>}{disposition === 'recovery_required' && <div><dt>Next step</dt><dd><span className="employee-state-chip">Recovery required</span></dd></div>}{incident.status === 'blocked' && <div><dt>Approved account</dt><dd>{maskAccount(incident.approvedAccount)}</dd></div>}</dl></section>}
        <section className="employee-about-card"><h2>About Maya</h2><p>Maya helps review supplier documents, check invoice details, and prepare payments within the work you request.</p></section>
      </>}</aside>
    </div>
  </main>;
}
function ReactNodeRow({ children }: { children: ReactNode }) { return <>{children}</>; }
export default EmployeeWorkspace;
