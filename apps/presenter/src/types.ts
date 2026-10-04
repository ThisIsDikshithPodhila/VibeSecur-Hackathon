export type Transaction = {
  environmentId: string; workspaceId: string; missionId: string;
  invoiceId: string; invoiceRevision: number; supplierId: string;
  supplierRevision: number; beneficiaryAccount: string; amountMinor: number; currency: string;
};
export type Approval = { approvalId: string; snapshot: Transaction; principal: string; createdAt: number | string; expiresAt: number | string; consumed: boolean; revoked: boolean };
export type Receipt = { operationId: string; environmentId: string; transaction: Transaction; approvalId: string; committedAt: number | string; status: 'committed' };
export type Environment = {
  environmentId: string; workspaceId: string; missionId: string;
  invoice: { invoiceId: string; invoiceRevision: number; amountMinor: number; currency: string };
  supplier: { supplierId: string; supplierRevision: number; beneficiaryAccount: string };
  approvals: Approval[]; ledger: Receipt[]; compensatingRule: boolean; attemptId: string; active: boolean;
};
export type Event = { eventId: string; sequence: number; timestamp: number | string; kind: string; data: Record<string, unknown> };
export type Run = {
  runId: string; owner: string; mode: 'live' | 'replay' | string; state: string; createdAt: number | string;
  baseline: Environment; protected: Environment; events: Event[];
  incident: Record<string, unknown> | null; repair: Record<string, unknown> | null;
  verification: Record<string, unknown> | null; negativeControl?: Record<string, unknown> | null;
  investigation?: Record<string, unknown> | null;
  conversation?: { conversationId: string; status: string; activeTurnId: string | null;
    turns: { turnId: string; clientMessageId: string; text: string; scope: string; status: string }[] };
  remediationPlan?: { text: string; version: number; updatedAt: number | string; origin: string; executorBound: boolean } | null;
  issueResults?: { provider: 'linear' | 'jira'; id: string; key: string; title: string; url: string }[];
  live?: { turnId: string; text: string; reasoning: string } | null;
  [key: string]: unknown;
};
export type Session = { authenticated: boolean; csrfToken?: string; openAccess?: boolean };
export type Action = 'start' | 'attack' | 'alternate-route' | 'investigate' | 'authorize-repair' | 'verify-bad-patch' | 'resume' | 'cancel' | 'reset';
export const snapshot = (env: Environment): Transaction => ({
  environmentId: env.environmentId, workspaceId: env.workspaceId, missionId: env.missionId,
  invoiceId: env.invoice.invoiceId, invoiceRevision: env.invoice.invoiceRevision,
  supplierId: env.supplier.supplierId, supplierRevision: env.supplier.supplierRevision,
  beneficiaryAccount: env.supplier.beneficiaryAccount, amountMinor: env.invoice.amountMinor,
  currency: env.invoice.currency,
});
