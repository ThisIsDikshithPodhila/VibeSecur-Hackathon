import { expect, test } from '@playwright/test';
import type { Event, Run, Transaction } from './types';
import {
  activityFromRun,
  conversationFromRun,
  stepLabel,
  incidentDispositionFromRun,
  incidentOutcomeFromRun,
  paymentReceiptsFromRun,
  workflowSuggestions,
} from './employeeView';

// Authored display-projection fixtures only. The mode value exercises the
// legacy/live mapping boundary; these are not runtime records, worker evidence,
// payment authority, or a security-gate result.
const transaction = (beneficiaryAccount: string, amountMinor = 25000000): Transaction => ({
  environmentId: 'display-fixture-env',
  workspaceId: 'display-fixture-workspace',
  missionId: 'display-fixture-mission',
  invoiceId: 'display-fixture-invoice',
  invoiceRevision: 2,
  supplierId: 'display-fixture-supplier',
  supplierRevision: 4,
  beneficiaryAccount,
  amountMinor,
  currency: 'AED',
});

const event = (sequence: number, kind: string, data: Record<string, unknown>, eventId = `display-fixture-event-${sequence}`): Event => ({
  eventId,
  sequence,
  timestamp: `2026-09-25T09:${String(sequence).padStart(2, '0')}:00.000Z`,
  kind,
  data,
});

const protectedReceipt = {
  operationId: 'display-fixture-operation-approved',
  environmentId: 'display-fixture-env',
  transaction: transaction('SYNTH-AE-APPROVED-001'),
  approvalId: 'display-fixture-approval',
  committedAt: '2026-09-25T09:07:00.000Z',
  status: 'committed' as const,
};

const sequencedDisplayTestFixture = {
  runId: 'display-fixture-live-run',
  owner: 'display-fixture-owner',
  mode: 'live',
  state: 'completed',
  createdAt: '2026-09-25T09:00:00.000Z',
  baseline: {
    environmentId: 'display-fixture-env', workspaceId: 'display-fixture-workspace', missionId: 'display-fixture-mission',
    invoice: { invoiceId: 'display-fixture-invoice', invoiceRevision: 2, amountMinor: 25000000, currency: 'AED' },
    supplier: { supplierId: 'display-fixture-supplier', supplierRevision: 4, beneficiaryAccount: 'SYNTH-AE-APPROVED-001' },
    approvals: [], ledger: [], compensatingRule: false, attemptId: 'display-fixture-attempt', active: true,
  },
  protected: {
    environmentId: 'display-fixture-env', workspaceId: 'display-fixture-workspace', missionId: 'display-fixture-mission',
    invoice: { invoiceId: 'display-fixture-invoice', invoiceRevision: 2, amountMinor: 25000000, currency: 'AED' },
    supplier: { supplierId: 'display-fixture-supplier', supplierRevision: 4, beneficiaryAccount: 'SYNTH-AE-APPROVED-001' },
    approvals: [], ledger: [protectedReceipt], compensatingRule: false, attemptId: 'display-fixture-attempt', active: true,
  },
  // Deliberately out of input order; projections must use sequence.
  events: [
    event(8, 'conversation.maya', { text: 'The approved payment receipt is recorded.', channel: 'maya', turnId: 'display-fixture-turn-2' }),
    event(3, 'payment.decision', {
      decisionId: 'display-fixture-denial', environmentId: 'display-fixture-env', operationId: 'display-fixture-operation-denied',
      decision: 'denied', reason: 'transaction_mismatch',
      attemptedTransaction: transaction('SYNTH-AE-CHANGED-999'),
      authorizedTransaction: transaction('SYNTH-AE-APPROVED-001'),
    }),
    event(7, 'payment.decision', {
      decisionId: 'display-fixture-commit', environmentId: 'display-fixture-env', operationId: 'display-fixture-operation-approved',
      decision: 'committed', attemptedTransaction: transaction('SYNTH-AE-APPROVED-001'),
      authorizedTransaction: transaction('SYNTH-AE-APPROVED-001'),
    }),
    event(6, 'worker.activity', {
      turnId: 'display-fixture-turn-1', toolCallId: 'display-fixture-call-2', tool: 'invoice.read', status: 'succeeded',
      title: 'Invoice read complete', description: 'Read the saved synthetic invoice.',
    }),
    event(1, 'worker.activity', {
      turnId: 'display-fixture-turn-1', toolCallId: 'display-fixture-call-1', tool: 'invoice.read', status: 'started',
      title: 'Reading invoice', description: 'Inspection started.',
    }),
    event(5, 'conversation.user', { text: 'Summarize the invoice', channel: 'maya', turnId: 'display-fixture-turn-2' }),
    event(2, 'worker.activity', {
      turnId: 'display-fixture-turn-1', toolCallId: 'display-fixture-call-1', tool: 'invoice.read', status: 'failed',
      title: 'Invoice read retry failed', description: 'The first read attempt failed.',
    }),
    event(4, 'worker.activity', {
      turnId: 'display-fixture-turn-1', toolCallId: 'display-fixture-call-3', tool: 'supplier.lookup', status: 'started',
      title: 'Checking supplier', description: 'Supplier lookup started.',
    }),
    event(9, 'worker.activity', {
      turnId: 'display-fixture-turn-1', toolCallId: 'display-fixture-call-invalid', tool: 'invoice.read', status: 'complete',
      title: 'Unsupported status must not render as completed.',
    }),
  ],
  incident: {
    status: 'reproduced',
    baselineReceipt: { transaction: transaction('SYNTH-AE-CHANGED-999') },
  },
  investigation: { disposition: 'recovery_required' },
  repair: null,
  verification: null,
} as unknown as Run;

test.describe('employee view projections', () => {
  test('maps real worker activity payloads and keeps the latest event per tool in sequence order', () => {
    const activity = activityFromRun(sequencedDisplayTestFixture);
    const worker = activity.filter((item) => item.tool);
    expect(worker.map((item) => [item.tool, item.status, item.sequence])).toEqual([
      ['invoice.read', 'succeeded', 6],
      ['supplier.lookup', 'started', 4],
    ].sort((left, right) => Number(left[2]) - Number(right[2])));
    expect(worker[0]).toMatchObject({
      toolCallId: 'display-fixture-call-3',
      title: 'Checking supplier',
      description: 'Supplier lookup started.',
      timestamp: '2026-09-25T09:04:00.000Z',
    });
    expect(worker.some((item) => item.title.includes('Unsupported status'))).toBe(false);
  });

  test('orders user and Maya entries by event sequence while retaining raw and display time', () => {
    const conversation = conversationFromRun(sequencedDisplayTestFixture);
    expect(conversation.map((item) => [item.role, item.text, item.sequence])).toEqual([
      ['user', 'Summarize the invoice', 5],
      ['maya', 'The approved payment receipt is recorded.', 5.5],
    ]);
    expect(typeof conversation[0].timestamp).toBe('string');
    expect(conversation[0].timeLabel.length).toBeGreaterThan(0);
  });

  test('keeps the trusted blocked attempt visible when a later approved receipt exists', () => {
    const outcome = incidentOutcomeFromRun(sequencedDisplayTestFixture);
    expect(outcome).toMatchObject({
      status: 'blocked',
      source: 'payment.decision',
      id: 'display-fixture-event-3',
      sequence: 3,
      attemptedAmount: expect.stringContaining('250,000'),
      attemptedAccount: 'SYNTH-AE-CHANGED-999',
      approvedAccount: 'SYNTH-AE-APPROVED-001',
    });
    expect(paymentReceiptsFromRun(sequencedDisplayTestFixture)).toEqual([expect.objectContaining({
      id: 'display-fixture-operation-approved',
      operationId: 'display-fixture-operation-approved',
      sequence: 7,
      amount: expect.stringContaining('250,000'),
      beneficiaryAccount: 'SYNTH-AE-APPROVED-001',
    })]);
    expect(incidentDispositionFromRun(sequencedDisplayTestFixture)).toBe('recovery_required');
  });

  for (const reason of [
    'assessment_unavailable',
    'assessment_input_too_large',
    'assessment_purpose_mismatch',
    'stale_record',
    'approval_unavailable',
    'attempt_mismatch',
  ]) {
    test(`keeps ${reason} as a neutral hold instead of a blocked payment claim`, () => {
      const heldRun = {
        ...sequencedDisplayTestFixture,
        incident: null,
        events: [event(1, 'payment.decision', {
          decisionId: `display-fixture-${reason}`,
          environmentId: 'display-fixture-env',
          operationId: `display-fixture-held-${reason}`,
          decision: 'denied', reason,
          attemptedTransaction: transaction('SYNTH-AE-CHANGED-999'),
          authorizedTransaction: transaction('SYNTH-AE-APPROVED-001'),
        })],
      } as Run;
      expect(incidentOutcomeFromRun(heldRun)).toEqual({ status: 'unavailable' });
      expect(activityFromRun(heldRun)).toContainEqual(expect.objectContaining({
        id: 'display-fixture-event-1',
        status: 'recorded',
        title: 'Payment review held',
      }));
      expect(activityFromRun(heldRun).some((item) => item.status === 'blocked')).toBe(false);
    });
  }

  test('reads legacy incident fields only for saved replay records, not live runs', () => {
    const legacy = {
      ...sequencedDisplayTestFixture,
      mode: 'replay',
      events: sequencedDisplayTestFixture.events.filter((item) => item.kind !== 'payment.decision'),
      protected: { ...sequencedDisplayTestFixture.protected, ledger: [] },
    } as Run;
    expect(incidentOutcomeFromRun(legacy)).toMatchObject({
      status: 'blocked', source: 'legacy_replay', attemptedAccount: 'SYNTH-AE-CHANGED-999',
    });
    const liveWithoutDecision = { ...legacy, mode: 'live' } as Run;
    expect(incidentOutcomeFromRun(liveWithoutDecision)).toEqual({ status: 'none' });
  });

  test('suggestions follow the payment workflow stage', () => {
    expect(workflowSuggestions(null)[0].kind).toBe('pay');
    const fresh = { ...sequencedDisplayTestFixture, events: [], protected: { ...sequencedDisplayTestFixture.protected, ledger: [] } } as Run;
    expect(workflowSuggestions(fresh)[0].text).toContain('missing in my inventory');
    expect(workflowSuggestions(fresh)[2].text).toContain('display-fixture-invoice');
    const blocked = { ...sequencedDisplayTestFixture, protected: { ...sequencedDisplayTestFixture.protected, ledger: [] } } as Run;
    expect(workflowSuggestions(blocked)[0].text).toContain('retry with the approved details');
    expect(workflowSuggestions(sequencedDisplayTestFixture)[0].text).toContain('how you corrected it');
  });
});

test('labels worker steps by the business action they perform', () => {
  expect(stepLabel({ tool: 'terminal', detail: 'curl -s $APP/api/inventory', status: 'succeeded' }).label).toBe('Checking inventory levels');
  expect(stepLabel({ tool: 'terminal', detail: 'curl -X POST $APP/api/purchase-orders', status: 'succeeded' }).label).toBe('Placing purchase order');
  expect(stepLabel({ tool: 'terminal', detail: 'curl -X POST $APP/api/payments', result: '{"error":"transaction_mismatch"}', status: 'succeeded' }))
    .toEqual({ label: 'Payment blocked by VibeSecur', blocked: true });
});

test('an active turn streams steps and live text without a durable reply', () => {
  const turnId = '11111111-1111-4111-8111-111111111111';
  const base = sequencedDisplayTestFixture;
  const run = {
    ...base,
    conversation: { conversationId: 'c', status: 'active', activeTurnId: turnId, turns: [] },
    live: { turnId, text: 'Checking the trusted', reasoning: '' },
    events: [
      { sequence: 900, kind: 'conversation.user', eventId: 'u', timestamp: 1, data: { text: 'Pay it', turnId } },
      { sequence: 901, kind: 'worker.step', eventId: 's1', timestamp: 2, data: { turnId, toolCallId: 'c1', tool: 'terminal', status: 'started', thought: 'Read context', detail: 'curl context' } },
      { sequence: 902, kind: 'worker.step', eventId: 's2', timestamp: 3, data: { turnId, toolCallId: 'c1', tool: 'terminal', status: 'succeeded', result: 'ok' } },
    ],
  } as unknown as Run;
  const entries = conversationFromRun(run);
  const live = entries[entries.length - 1];
  expect(live.streaming).toBe(true);
  expect(live.text).toBe('Checking the trusted');
  expect(live.steps).toEqual([{ toolCallId: 'c1', tool: 'terminal', status: 'succeeded', thought: 'Read context', detail: 'curl context', result: 'ok' }]);
  const answered = { ...run, events: [...run.events, { sequence: 903, kind: 'conversation.maya', eventId: 'm', timestamp: 4, data: { text: 'Paid.', turnId } }] } as unknown as Run;
  const final = conversationFromRun(answered);
  expect(final.filter(entry => entry.role === 'maya' && entry.streaming)).toHaveLength(0);
  expect(final[final.length - 1].steps?.[0].status).toBe('succeeded');
});
