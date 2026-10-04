import { useCallback, useEffect, useRef, useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { ApiError, approvePayment, command, createIssue, createRun, getCapabilities, getConnectors, getRun, listRuns, logout, saveRemediationPlan, sendMessage, session, streamRun, type Capabilities, type ConnectorStates } from './api';
import { ControlPanel, type IssueDraft, type IssueProvider } from './ControlPanel';
import { EmployeeWorkspace } from './EmployeeWorkspace';
import { snapshot, type Environment, type Run } from './types';

const selectedKey = 'vibesecur-presenter-run';
type Connection = 'connecting' | 'connected' | 'reconnecting' | 'offline';
const disconnected: ConnectorStates = {
  linear: { connected: false, configured: false },
  jira: { connected: false, configured: false },
};

function currentApproval(environment: Environment): boolean {
  const transaction = snapshot(environment);
  return environment.approvals.some(approval => {
    const expiry = typeof approval.expiresAt === 'number'
      ? approval.expiresAt < 1e12 ? approval.expiresAt * 1000 : approval.expiresAt
      : new Date(approval.expiresAt).getTime();
    return !approval.consumed && !approval.revoked && expiry > Date.now() &&
      (Object.keys(transaction) as (keyof typeof transaction)[]).every(key => approval.snapshot?.[key] === transaction[key]);
  });
}

function EmployeeApp() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [run, setRun] = useState<Run | null>(null);
  const [controlOpen, setControlOpen] = useState(false);
  const [resetConfirm, setResetConfirm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [connection, setConnection] = useState<Connection>('connecting');
  const [connectors, setConnectors] = useState<ConnectorStates>(disconnected);
  const [capabilities, setCapabilities] = useState<Capabilities>({ liveWorker: { configured: false }, executors: [] });
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const runId = useRef<string | null>(null);
  const busyRef = useRef(false);
  const refreshingRef = useRef(false);
  const selectionVersion = useRef(0);
  const refreshFailures = useRef(0);

  const showRun = useCallback((next: Run | null) => {
    runId.current = next?.runId ?? null;
    setRun(next);
    if (next) {
      try { localStorage.setItem(selectedKey, next.runId); }
      catch { /* Server history remains authoritative. */ }
    }
  }, []);

  const refresh = useCallback(async (selected?: string | null) => {
    if (busyRef.current || refreshingRef.current) return;
    refreshingRef.current = true;
    const target = selected === undefined ? runId.current : selected;
    const version = selectionVersion.current;
    try {
      const [nextRuns, nextRun] = await Promise.all([listRuns(), target ? getRun(target) : Promise.resolve(null)]);
      if (version !== selectionVersion.current || target !== runId.current) return;
      setRuns(nextRuns);
      if (nextRun) showRun(nextRun);
      refreshFailures.current = 0;
      setConnection('connected');
      setRefreshError(null);
    } catch (reason) {
      if (version !== selectionVersion.current || target !== runId.current) return;
      if (reason instanceof ApiError && reason.status === 401) {
        setAuthenticated(false); showRun(null); setConnection('offline');
        setRefreshError('Your session expired. Sign in to reconnect.');
      } else if (reason instanceof ApiError && reason.status === 404 && target) {
        try { localStorage.removeItem(selectedKey); } catch { /* No local selection to clear. */ }
        showRun(null); setConnection('reconnecting');
        setRefreshError('That saved run is unavailable. Choose another run.');
      } else {
        refreshFailures.current += 1;
        setConnection(refreshFailures.current >= 3 ? 'offline' : 'reconnecting');
        setRefreshError(reason instanceof Error ? reason.message : 'Could not refresh server state.');
      }
    } finally {
      refreshingRef.current = false;
    }
  }, [showRun]);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    let failures = 0;
    const connect = async () => {
      try {
        const result = await session();
        if (stopped) return;
        setAuthenticated(result.authenticated);
        setConnection('connected');
        if (!result.authenticated) return;
        let selected: string | null = null;
        try { selected = localStorage.getItem(selectedKey); } catch { /* Server list is enough. */ }
        if (selected) runId.current = selected;
        await refresh(selected);
        try { const states = await getConnectors(); if (!stopped) setConnectors(states); }
        catch { if (!stopped) setConnectors(disconnected); }
        try { const value = await getCapabilities(); if (!stopped) setCapabilities(value); }
        catch { /* Missing capability evidence keeps executor choices hidden. */ }
      } catch (reason) {
        if (stopped) return;
        failures += 1;
        setConnection(failures >= 3 ? 'offline' : 'reconnecting');
        setRefreshError(reason instanceof Error ? reason.message : 'Presenter is unreachable. Retrying…');
        timer = window.setTimeout(() => void connect(), Math.min(1000 * 2 ** Math.min(failures, 4), 15000));
      }
    };
    void connect();
    return () => { stopped = true; if (timer !== undefined) window.clearTimeout(timer); };
  }, [refresh]);

  useEffect(() => {
    if (authenticated !== false) return;
    const timer = window.setInterval(() => {
      void session().then(result => {
        if (!result.authenticated) return;
        setAuthenticated(true); setConnection('connected'); setRefreshError(null);
        void refresh();
      }).catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [authenticated, refresh]);

  useEffect(() => {
    if (!authenticated) return;
    const active = busy !== null || Boolean(run?.conversation?.activeTurnId) || Boolean(run && /running|pending|repairing|investigating|verifying|resuming|starting/i.test(run.state));
    const timer = window.setInterval(() => { void refresh(); }, active ? 1000 : 3000);
    return () => window.clearInterval(timer);
  }, [authenticated, busy, refresh, run?.state, run?.conversation?.activeTurnId]);

  const streaming = authenticated && run?.mode === 'live' && (Boolean(run?.conversation?.activeTurnId) || busy !== null) ? run.runId : null;
  useEffect(() => {
    if (!streaming) return;
    return streamRun(streaming, next => { if (next.runId === runId.current && !busyRef.current) showRun(next); });
  }, [streaming, showRun]);

  async function perform<T>(label: string, action: () => Promise<T>, after?: (result: T) => void): Promise<T> {
    if (busyRef.current) throw new Error('Another request is still in progress.');
    busyRef.current = true;
    setBusy(label); setError(null); setNotice(null);
    try {
      const result = await action();
      after?.(result);
      return result;
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : 'The server did not confirm this request.';
      setError(message);
      throw reason;
    } finally {
      busyRef.current = false;
      setBusy(null);
      void refresh();
    }
  }

  async function start(mode: 'live' | 'replay') {
    await perform('Starting work', async () => {
      const created = await createRun(mode);
      showRun(created);
      if (mode === 'live') return created;
      const result = await command(created.runId, 'start');
      return result.run;
    }, next => { showRun(next); setControlOpen(false); });
  }

  async function send(text: string, channel: 'maya' | 'control_panel' = 'maya') {
    await perform('Sending message', async () => {
      let target = run;
      if (!target || (channel === 'maya' && target.mode !== 'live')) {
        let creationKey: string;
        try {
          creationKey = sessionStorage.getItem('vibesecur-pending-conversation') || crypto.randomUUID();
          sessionStorage.setItem('vibesecur-pending-conversation', creationKey);
        } catch { creationKey = crypto.randomUUID(); }
        const created = await createRun('live', creationKey);
        showRun(created);
        try { sessionStorage.removeItem('vibesecur-pending-conversation'); } catch { /* Server record survives. */ }
        target = created;
      }
      const pendingKey = `vibesecur-pending-message:${target.runId}:${channel}`;
      let clientMessageId = crypto.randomUUID();
      try {
        const pending = JSON.parse(sessionStorage.getItem(pendingKey) || 'null');
        if (pending?.text === text && typeof pending?.id === 'string') clientMessageId = pending.id;
        sessionStorage.setItem(pendingKey, JSON.stringify({ id: clientMessageId, text }));
      } catch { /* The server still deduplicates the submitted identity. */ }
      const response = await sendMessage(target.runId, text, channel, clientMessageId);
      try { sessionStorage.removeItem(pendingKey); } catch { /* No repeated action on refresh. */ }
      return response;
    }, response => { showRun(response.run); if (channel === 'control_panel') setNotice(response.reply ?? null); });
  }

  async function approve() {
    if (!run) throw new Error('Open a saved run before approving payment.');
    await perform('Recording exact approval', async () => {
      const initialReplay = run.mode === 'replay' && !run.incident && run.state === 'prepared';
      const variants: ('baseline' | 'protected')[] = initialReplay ? ['baseline', 'protected'] : ['protected'];
      let current = run;
      for (const variant of variants) {
        if (initialReplay && currentApproval(current[variant])) continue;
        await approvePayment(current.runId, variant, snapshot(current[variant]));
        current = await getRun(current.runId);
      }
      return current;
    }, next => { showRun(next); setNotice('The exact payment approval was recorded.'); });
  }

  async function investigate() {
    if (!run) throw new Error('Open an incident first.');
    await perform('Investigating', async () => (await command(run.runId, 'investigate')).run,
      next => { showRun(next); setNotice('The investigation report and proposed plan were saved.'); });
  }

  async function savePlan(text: string) {
    if (!run) throw new Error('Open an incident first.');
    const version = run.remediationPlan?.version ?? 0;
    await perform('Saving plan', () => saveRemediationPlan(run.runId, text, version),
      next => { showRun(next); setNotice('Your plan edits were saved for review.'); });
  }

  async function fix() {
    if (!run) throw new Error('Open an incident first.');
    await perform('Authorizing bounded repair', async () => (await command(run.runId, 'authorize-repair')).run,
      next => { showRun(next); setNotice('The configured bounded repair mission was authorized.'); });
  }

  async function resume() {
    if (!run) throw new Error('Open an incident first.');
    await perform('Resuming approved work', async () => (await command(run.runId, 'resume')).run,
      next => { showRun(next); setNotice('The server recorded the resumption request.'); });
  }

  async function createEngineeringIssue(provider: IssueProvider, draft: IssueDraft) {
    if (!run) throw new Error('Open an incident first.');
    await perform(`Creating ${provider === 'linear' ? 'Linear issue' : 'Jira ticket'}`,
      () => createIssue(run.runId, provider, draft),
      response => { showRun(response.run); setNotice(`${provider === 'linear' ? 'Linear issue' : 'Jira ticket'} ${response.issue.key} was created.`); });
  }

  async function signOut() {
    await perform('Signing out', logout, () => {
      setAuthenticated(false); setControlOpen(false); showRun(null); setRuns([]);
      try { localStorage.removeItem(selectedKey); } catch { /* No local selection to clear. */ }
    });
  }

  function selectRun(selected: Run) {
    selectionVersion.current += 1;
    showRun(selected); setControlOpen(false); setError(null); setNotice(null);
    void refresh(selected.runId);
  }

  async function reset() {
    setResetConfirm(false);
    if (!run) return;
    await perform('Resetting this run', async () => (await command(run.runId, 'reset')).run,
      next => { selectionVersion.current += 1; showRun(next); setControlOpen(false); setNotice('A new run is ready. Previous records remain in saved work.'); });
  }

  if (authenticated === null) return <main className="employee-loading" role="status">
    <span className="employee-brand-mark" aria-hidden="true">V</span>
    <p>{connection === 'offline' ? 'Reconnecting to your workspace…' : 'Opening your workspace…'}</p>
    {refreshError && <small>{refreshError}</small>}
  </main>;

  if (!authenticated) return <main className="employee-loading" role="status">
    <span className="employee-brand-mark" aria-hidden="true">V</span>
    <p>Connecting to your workspace…</p>
    {(error || refreshError) && <small>{error || refreshError}</small>}
  </main>;

  return <>
    <EmployeeWorkspace
      run={run} savedRuns={runs} connectionStatus={connection === 'connecting' ? 'reconnecting' : connection}
      busy={!!busy} error={error || refreshError} notice={notice}
      onSend={text => send(text)} onStart={start} onSelectRun={selectRun}
      onViewIncident={() => { setControlOpen(true); setNotice(null); void getConnectors().then(setConnectors).catch(() => setConnectors(disconnected)); }}
      onApprovePayment={approve} onRefresh={() => refresh()} onSignOut={signOut}
      onReset={() => setResetConfirm(true)}
      rightPanel={controlOpen && run ? <ControlPanel
        run={run} busy={busy} error={error || refreshError} notice={notice}
        planDraft={run.remediationPlan?.text ?? ''} connection={connection}
        connectors={connectors} issueResults={run.issueResults ?? []}
        executors={capabilities.executors}
        onBack={() => setControlOpen(false)} onSend={text => send(text, 'control_panel')}
        onInvestigate={investigate} onSavePlan={savePlan} onFix={fix}
        onApprovePayment={approve} onResume={resume} onCreateIssue={createEngineeringIssue}
      /> : undefined}
    />
    {resetConfirm && <div className="employee-dialog-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) setResetConfirm(false); }}>
      <div className="employee-dialog" role="dialog" aria-modal="true" aria-labelledby="employee-reset-title">
        <RotateCcw size={20} aria-hidden="true"/><h2 id="employee-reset-title">Start a fresh run?</h2>
        <p>The current run will stop. Its recorded work and payment effects remain in saved history.</p>
        <div><button type="button" onClick={() => setResetConfirm(false)}>Keep current run</button>
          <button type="button" className="is-primary" onClick={() => void reset()}>Start fresh run</button></div>
      </div>
    </div>}
  </>;
}

export default EmployeeApp;
