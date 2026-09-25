import { snapshot, type Event, type Run } from './types';

export type EmployeeConnectionStatus = 'connected' | 'reconnecting' | 'offline';
export type EmployeeActivity = {
  id: string;
  sequence: number;
  timestamp: number | string;
  timeLabel: string;
  title: string;
  description?: string;
  toolCallId?: string;
  tool?: string;
  status: 'started' | 'succeeded' | 'failed' | 'blocked' | 'recorded';
};
export type EmployeeConversationEntry = {
  id: string;
  sequence: number;
  role: 'user' | 'maya';
  timestamp: number | string;
  timeLabel: string;
  text: string;
  sourceKind: 'conversation.user' | 'conversation.maya';
  steps?: EmployeeStep[];
  reasoning?: string;
  streaming?: boolean;
};
export type EmployeeStep = {
  toolCallId: string;
  tool: string;
  status: 'started' | 'succeeded' | 'failed';
  thought?: string;
  detail?: string;
  result?: string;
};
export type EmployeeIncidentOutcome =
  | { status: 'none' | 'unavailable' }
  | {
      status: 'blocked'; id: string; sequence: number | null; timestamp: number | string | null;
      timeLabel: string; attemptedAmount?: string; attemptedAccount: string; approvedAccount: string;
      source: 'payment.decision' | 'legacy_replay';
    };
export type EmployeePaymentReceipt = {
  id: string;
  sequence: number | null;
  timestamp: number | string;
  timeLabel: string;
  amount: string;
  beneficiaryAccount: string;
  operationId: string;
};
export type EmployeeIncidentDisposition =
  | 'unresolved'
  | 'course_corrected_no_repair'
  | 'recovery_required'
  | 'unavailable';
export type EmployeeTaskBrief = {
  supplier: string;
  invoice: string;
  amount: string;
  beneficiary: string;
  hasDetails: boolean;
};

const titleCase = (value: string) => value
  .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
  .replace(/[_./-]+/g, ' ')
  .replace(/\s+/g, ' ')
  .trim()
  .replace(/\b\w/g, (letter) => letter.toUpperCase());

const employeeEventLabels: Record<string, string> = {
  'mission.prepared': 'Work session prepared',
  'mission.reconciled_receipt': 'Saved payment receipt reconciled',
  'mission.reconciled_after_restart': 'Saved work state reconciled',
  'mission.cancelled': 'Work session cancelled',
  'mission.reset_from': 'New run started from saved work',
  'presenter.approved_exact_transaction': 'Payment approval recorded',
  'live_agent.started': 'Live agent started',
  'live_agent.unavailable': 'Live agent unavailable',
  'live_agent.assessed': 'Live assessment recorded',
  'live_agent.event': 'Live agent activity recorded',
  'live_agent.result': 'Live agent result recorded',
  'source.document_http': 'Invoice source checked',
  'source.unavailable': 'Invoice source unavailable',
  'deterministic_replay.payment_http': 'Replay payment check recorded',
  'replay.unavailable': 'Replay unavailable',
  'replay.assessed': 'Replay assessment recorded',
  'alternate_route.result': 'Alternate route response recorded',
  'alternate_route.unavailable': 'Alternate route unavailable',
  'investigation.reported': 'Investigation report recorded',
  'investigation.unavailable': 'Investigation unavailable',
  'repair.started': 'Repair work started',
  'repair.incomplete_promotion_reconciled': 'Repair promotion state reconciled',
  'repair.verified': 'Independent verification recorded',
  'repair.verification_failed': 'Independent verification did not pass',
  'repair.held': 'Repair is held',
  'repair.deployed': 'Deployment recorded',
  'repair.deployment_unavailable': 'Deployment unavailable',
  'resume.payment_committed': 'Protected payment receipt recorded',
  'resume.unconfirmed': 'Resumption is unconfirmed',
};

const workerActivityStatuses = new Set(['started', 'succeeded', 'failed'] as const);
type WorkerActivityStatus = 'started' | 'succeeded' | 'failed';
type PaymentTransaction = { beneficiaryAccount?: unknown; amountMinor?: unknown; currency?: unknown };
const confirmedPaymentDenialReasons = new Set(['transaction_mismatch', 'scope_mismatch']);
const heldPaymentDenialDescriptions: Record<string, string> = {
  assessment_unavailable: 'Assessment was unavailable, so the payment was held for review.',
  assessment_input_too_large: 'Assessment input exceeded its limit, so the payment was held for review.',
};

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function formatMinorAmount(amountMinor: unknown, currencyValue: unknown): string | undefined {
  const currency = nonEmptyString(currencyValue);
  if (typeof amountMinor !== 'number' || !Number.isFinite(amountMinor) || !currency) return undefined;
  try {
    return new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(amountMinor / 100);
  } catch {
    return `${currency} ${(amountMinor / 100).toFixed(2)}`;
  }
}

function transactionAmount(value: unknown): string | undefined {
  const transaction = record(value) as PaymentTransaction | null;
  return transaction ? formatMinorAmount(transaction.amountMinor, transaction.currency) : undefined;
}

function isWorkerActivityStatus(value: unknown): value is WorkerActivityStatus {
  return typeof value === 'string' && workerActivityStatuses.has(value as WorkerActivityStatus);
}

function decisionEvents(run: Run): Event[] {
  return run.events
    .filter((event) => event.kind === 'payment.decision')
    .sort((left, right) => left.sequence - right.sequence);
}

function deniedPaymentActivity(event: Event): EmployeeActivity | null {
  if (event.data.decision !== 'denied') return null;
  const reason = nonEmptyString(event.data.reason) || '';
  const confirmedDenial = confirmedPaymentDenialReasons.has(reason);
  const description = confirmedDenial
    ? reason === 'transaction_mismatch'
      ? 'The attempted transaction did not match the approved transaction.'
      : 'The requested action exceeded the approved scope.'
    : heldPaymentDenialDescriptions[reason];
  return {
    id: event.eventId || `payment-decision-${event.sequence}`,
    sequence: event.sequence,
    timestamp: event.timestamp,
    timeLabel: eventTime(event.timestamp),
    title: confirmedDenial ? 'Payment attempt denied' : reason ? 'Payment review held' : 'Payment decision recorded',
    ...(description ? { description } : {}),
    status: confirmedDenial ? 'blocked' : 'recorded',
  };
}

function paymentDecisionActivity(event: Event): EmployeeActivity | null {
  if (event.data.decision === 'denied') return deniedPaymentActivity(event);
  if (event.data.decision !== 'committed') return null;
  return {
    id: event.eventId || `payment-decision-${event.sequence}`,
    sequence: event.sequence,
    timestamp: event.timestamp,
    timeLabel: eventTime(event.timestamp),
    title: 'Protected payment receipt recorded',
    status: 'recorded',
  };
}

function workerActivitiesFromRun(run: Run, locale?: string): EmployeeActivity[] {
  const latestByTool = new Map<string, EmployeeActivity>();
  for (const event of [...run.events].sort((left, right) => left.sequence - right.sequence)) {
    if (event.kind !== 'worker.activity') continue;
    const status = event.data.status;
    if (!isWorkerActivityStatus(status)) continue;
    const tool = nonEmptyString(event.data.tool);
    const toolCallId = nonEmptyString(event.data.toolCallId);
    const key = tool ? `tool:${tool}` : toolCallId ? `call:${toolCallId}` : `event:${event.eventId || event.sequence}`;
    const title = nonEmptyString(event.data.title) || (tool ? titleCase(tool) : 'Agent activity recorded');
    const description = nonEmptyString(event.data.description);
    latestByTool.set(key, {
      id: event.eventId || toolCallId || `${event.sequence}-worker.activity`,
      sequence: event.sequence,
      timestamp: event.timestamp,
      timeLabel: eventTime(event.timestamp, locale),
      title,
      ...(description ? { description } : {}),
      ...(toolCallId ? { toolCallId } : {}),
      ...(tool ? { tool } : {}),
      status,
    });
  }
  return [...latestByTool.values()];
}

function dateFromEpoch(value: number | string): Date {
  if (typeof value === 'number') return new Date(value * 1000);
  const trimmed = value.trim();
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return new Date(Number(trimmed) * 1000);
  return new Date(trimmed);
}

export function isEmployeeEvent(kind: string): boolean {
  return Object.hasOwn(employeeEventLabels, kind) || kind === 'worker.activity' || kind === 'payment.decision';
}

export function eventTitle(event: Event): string {
  if (event.kind === 'worker.activity') return nonEmptyString(event.data.title) || 'Agent activity recorded';
  if (event.kind === 'payment.decision' && event.data.decision === 'denied') {
    return deniedPaymentActivity(event)?.title || 'Payment decision recorded';
  }
  if (event.kind === 'payment.decision' && event.data.decision === 'committed') return 'Protected payment receipt recorded';
  return employeeEventLabels[event.kind] || 'Recorded system activity';
}

export function eventTime(value: Event['timestamp'], locale?: string): string {
  const parsed = dateFromEpoch(value);
  if (!Number.isFinite(parsed.getTime())) return 'Time not recorded';
  return new Intl.DateTimeFormat(locale, { hour: 'numeric', minute: '2-digit' }).format(parsed);
}

export function activityFromRun(run: Run | null, locale?: string): EmployeeActivity[] {
  if (!run) return [];
  const events = [...run.events].sort((left, right) => left.sequence - right.sequence);
  const legacyActivities = events.flatMap((event): EmployeeActivity[] => {
    if (!Object.hasOwn(employeeEventLabels, event.kind)) return [];
    return [{
      id: event.eventId || `${event.sequence}-${event.kind}`,
      sequence: event.sequence,
      timestamp: event.timestamp,
      timeLabel: eventTime(event.timestamp, locale),
      title: eventTitle(event),
      status: event.kind === 'repair.verification_failed' ? 'failed' : 'recorded',
    }];
  });
  const decisions = events.flatMap((event) => event.kind === 'payment.decision' && event.sequence !== undefined
    ? [paymentDecisionActivity(event)]
    : []).filter((event): event is EmployeeActivity => event !== null);
  return [...legacyActivities, ...workerActivitiesFromRun(run, locale), ...decisions]
    .sort((left, right) => left.sequence - right.sequence);
}

function conversationText(event: Event): string | null {
  if (event.kind !== 'conversation.user' && event.kind !== 'conversation.maya') return null;
  const candidate = typeof event.data.text === 'string'
    ? event.data.text
    : typeof event.data.message === 'string' ? event.data.message : '';
  const text = candidate.trim();
  return text ? candidate : null;
}

function stepsByTurn(run: Run): Map<string, EmployeeStep[]> {
  const turns = new Map<string, EmployeeStep[]>();
  for (const event of [...run.events].filter(item => item.kind === 'worker.step').sort((a, b) => a.sequence - b.sequence)) {
    const data = event.data;
    const turnId = nonEmptyString(data.turnId);
    const toolCallId = nonEmptyString(data.toolCallId);
    const status = data.status;
    if (!turnId || !toolCallId || (status !== 'started' && status !== 'succeeded' && status !== 'failed')) continue;
    const steps = turns.get(turnId) ?? [];
    let step = steps.find(item => item.toolCallId === toolCallId);
    if (!step) { step = { toolCallId, tool: nonEmptyString(data.tool) || 'tool', status }; steps.push(step); }
    step.status = status;
    for (const key of ['thought', 'detail', 'result'] as const) {
      const value = nonEmptyString(data[key]);
      if (value) step[key] = value;
    }
    turns.set(turnId, steps);
  }
  return turns;
}

export function conversationFromRun(run: Run | null, locale?: string): EmployeeConversationEntry[] {
  if (!run) return [];
  const steps = stepsByTurn(run);
  const entries: EmployeeConversationEntry[] = run.events
    .filter((event) => event.kind === 'conversation.user' || event.kind === 'conversation.maya')
    .sort((left, right) => left.sequence - right.sequence)
    .flatMap((event) => {
      const text = conversationText(event);
      if (!text) return [];
      const sourceKind = event.kind as EmployeeConversationEntry['sourceKind'];
      const turnSteps = sourceKind === 'conversation.maya' ? steps.get(nonEmptyString(event.data.turnId) || '') : undefined;
      return [{
        id: event.eventId || `${event.sequence}-${event.kind}`,
        sequence: event.sequence,
        role: sourceKind === 'conversation.user' ? 'user' as const : 'maya' as const,
        timestamp: event.timestamp,
        timeLabel: eventTime(event.timestamp, locale),
        text,
        sourceKind,
        ...(turnSteps?.length ? { steps: turnSteps } : {}),
      }];
    });
  const active = run.conversation?.activeTurnId;
  const answered = run.events.some(event => event.kind === 'conversation.maya' && event.data.turnId === active);
  const asked = active ? run.events.find(event => event.kind === 'conversation.user' && event.data.turnId === active) : undefined;
  if (active && asked && !answered) {
    const live = run.live && run.live.turnId === active ? run.live : null;
    entries.push({
      id: `live-${active}`,
      sequence: asked.sequence + 0.5,
      role: 'maya',
      timestamp: asked.timestamp,
      timeLabel: 'Working…',
      text: live?.text ?? '',
      reasoning: live?.reasoning || undefined,
      sourceKind: 'conversation.maya',
      steps: steps.get(active) ?? [],
      streaming: true,
    });
    entries.sort((left, right) => left.sequence - right.sequence);
  }
  return entries;
}

export function incidentOutcomeFromRun(run: Run | null): EmployeeIncidentOutcome {
  if (!run) return { status: 'none' };
  const deniedEvents = decisionEvents(run).filter((event) => event.data.decision === 'denied');
  const denied = deniedEvents.filter((event) => confirmedPaymentDenialReasons.has(nonEmptyString(event.data.reason) || '')).at(-1);
  if (denied) {
    const attempted = record(denied.data.attemptedTransaction);
    const authorized = record(denied.data.authorizedTransaction);
    const attemptedAccount = nonEmptyString(attempted?.beneficiaryAccount);
    const approvedAccount = nonEmptyString(authorized?.beneficiaryAccount);
    if (!attemptedAccount || !approvedAccount) return { status: 'unavailable' };
    return {
      status: 'blocked',
      id: denied.eventId || `payment-decision-${denied.sequence}`,
      sequence: denied.sequence,
      timestamp: denied.timestamp,
      timeLabel: eventTime(denied.timestamp),
      attemptedAmount: transactionAmount(attempted),
      attemptedAccount,
      approvedAccount,
      source: 'payment.decision',
    };
  }
  if (deniedEvents.length > 0) return { status: 'unavailable' };
  // Old replay records remain readable. Legacy incident fields never establish
  // a live blocked outcome; live runs require a trusted sequenced denial event.
  if (run.mode !== 'replay' || run.incident?.status !== 'reproduced') return { status: 'none' };
  const baselineReceipt = run.incident.baselineReceipt;
  if (!baselineReceipt || typeof baselineReceipt !== 'object' || Array.isArray(baselineReceipt)) return { status: 'unavailable' };
  const transaction = (baselineReceipt as Record<string, unknown>).transaction;
  if (!transaction || typeof transaction !== 'object' || Array.isArray(transaction)) return { status: 'unavailable' };
  const attemptedValue = (transaction as Record<string, unknown>).beneficiaryAccount;
  const attemptedAccount = typeof attemptedValue === 'string' ? attemptedValue.trim() : '';
  const approvedAccount = run.protected.supplier?.beneficiaryAccount?.trim();
  if (!attemptedAccount || !approvedAccount || attemptedAccount === approvedAccount) return { status: 'unavailable' };
  if (!attemptedAccount.replace(/\D/g, '') || !approvedAccount.replace(/\D/g, '')) return { status: 'unavailable' };
  const protectedAttemptExists = run.protected.ledger.some((receipt) =>
    receipt.transaction?.beneficiaryAccount === attemptedAccount);
  if (protectedAttemptExists) return { status: 'unavailable' };
  const incidentRecord = run.incident as Record<string, unknown>;
  const timestampValue = incidentRecord.timestamp;
  const timestamp = typeof timestampValue === 'number' || typeof timestampValue === 'string' ? timestampValue : null;
  const incidentId = nonEmptyString(incidentRecord.incidentId) || `${run.runId}:legacy-incident`;
  return {
    status: 'blocked',
    id: incidentId,
    sequence: null,
    timestamp,
    timeLabel: timestamp === null ? 'Time not recorded' : eventTime(timestamp),
    attemptedAmount: transactionAmount(transaction),
    attemptedAccount,
    approvedAccount,
    source: 'legacy_replay',
  };
}

export function paymentReceiptsFromRun(run: Run | null, locale?: string): EmployeePaymentReceipt[] {
  if (!run) return [];
  const committedByOperation = new Map<string, Event>();
  for (const event of decisionEvents(run)) {
    if (event.data.decision !== 'committed') continue;
    const operationId = nonEmptyString(event.data.operationId);
    if (operationId) committedByOperation.set(operationId, event);
  }
  return run.protected.ledger.flatMap((receipt) => {
    const operationId = nonEmptyString(receipt.operationId);
    const beneficiaryAccount = nonEmptyString(receipt.transaction?.beneficiaryAccount);
    const amount = formatMinorAmount(receipt.transaction?.amountMinor, receipt.transaction?.currency);
    if (!operationId || !beneficiaryAccount || !amount) return [];
    const event = committedByOperation.get(operationId);
    const timestamp = event?.timestamp ?? receipt.committedAt;
    return [{
      id: operationId,
      operationId,
      sequence: event?.sequence ?? null,
      timestamp,
      timeLabel: event ? eventTime(event.timestamp, locale) : eventTime(receipt.committedAt, locale),
      amount,
      beneficiaryAccount,
    }];
  });
}

export function incidentDispositionFromRun(run: Run | null): EmployeeIncidentDisposition {
  const disposition = run?.investigation?.disposition;
  return disposition === 'unresolved' || disposition === 'course_corrected_no_repair' || disposition === 'recovery_required'
    ? disposition
    : 'unavailable';
}

export function maskAccount(account: string): string {
  const digits = account.replace(/\D/g, '');
  return `•••• ${digits.slice(-4)}`;
}

export function modeLabel(mode: Run['mode']): string {
  if (mode === 'live') return 'Live agent run';
  if (mode === 'replay') return 'Deterministic replay';
  return `Run mode: ${titleCase(mode) || 'unavailable'}`;
}

export function stateLabel(state: string): string {
  return titleCase(state) || 'State not recorded';
}

export function taskBriefFromRun(run: Run | null): EmployeeTaskBrief {
  if (!run) return { supplier: '', invoice: '', amount: '', beneficiary: '', hasDetails: false };
  const env = run.protected;
  const supplier = env?.supplier?.supplierId?.trim() || '';
  const invoice = env?.invoice?.invoiceId?.trim() || '';
  const amountMinor = env?.invoice?.amountMinor;
  const currency = env?.invoice?.currency?.trim();
  const beneficiary = env?.supplier?.beneficiaryAccount?.trim() || '';
  let amount = '';
  if (Number.isFinite(amountMinor) && currency) {
    try {
      amount = new Intl.NumberFormat(undefined, { style: 'currency', currency }).format((amountMinor as number) / 100);
    } catch {
      amount = `${currency} ${((amountMinor as number) / 100).toFixed(2)}`;
    }
  }
  return { supplier, invoice, amount, beneficiary, hasDetails: Boolean(supplier || invoice || amount || beneficiary) };
}

export function hasCurrentProtectedApproval(run: Run | null, now = Date.now()): boolean {
  if (!run?.protected) return false;
  const env = run.protected;
  const current = snapshot(env);
  return env.approvals.some((approval) => {
    if (approval.consumed || approval.revoked) return false;
    const expiresAt = typeof approval.expiresAt === 'number'
      ? approval.expiresAt * 1000
      : /^-?\d+(?:\.\d+)?$/.test(approval.expiresAt)
        ? Number(approval.expiresAt) * 1000
        : Date.parse(approval.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= now) return false;
    return (Object.keys(current) as (keyof typeof current)[]).every((key) => approval.snapshot[key] === current[key]);
  });
}

export function runCreatedLabel(run: Run, locale?: string): string {
  const date = dateFromEpoch(run.createdAt);
  if (!Number.isFinite(date.getTime())) return 'Saved run';
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

export type WorkflowSuggestionKind = 'pay' | 'inspect' | 'explain' | 'receipt' | 'investigate';
export type WorkflowSuggestion = { text: string; kind: WorkflowSuggestionKind };

export function workflowSuggestions(run: Run | null): WorkflowSuggestion[] {
  const invoice = run?.protected.invoice.invoiceId;
  const pay = { text: invoice ? `Process invoice ${invoice} and pay the approved supplier` : 'Process the supplier invoice and pay the approved supplier', kind: 'pay' } as const;
  if (!run) return [pay, { text: 'Show invoice details', kind: 'inspect' }, { text: 'Check supplier status', kind: 'inspect' }];
  const blocked = incidentOutcomeFromRun(run).status === 'blocked';
  const paid = run.protected.ledger.length > 0;
  if (blocked && paid) return [
    { text: 'Explain what VibeSecur blocked and how you corrected it', kind: 'explain' },
    { text: 'Show the payment receipt', kind: 'receipt' },
    { text: 'Why did the first attempt use a different account?', kind: 'investigate' },
  ];
  if (blocked) return [
    { text: 'Re-read the trusted record and retry with the approved details', kind: 'pay' },
    { text: 'Explain the blocked change', kind: 'explain' },
  ];
  if (paid) return [{ text: 'Show the payment receipt', kind: 'receipt' }, { text: 'Summarize what you did', kind: 'explain' }];
  return [pay, { text: 'Show invoice details', kind: 'inspect' }, { text: 'Show pending approvals', kind: 'inspect' }];
}
