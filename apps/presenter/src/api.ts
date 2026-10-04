import type { Action, Approval, Run, Session, Transaction } from './types';

const root = '/api';
let csrfToken = '';
export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}
async function request<T>(path: string, method = 'GET', body?: unknown, idempotencyKey?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') {
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    headers['Idempotency-Key'] = idempotencyKey ?? crypto.randomUUID();
  }
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(`${root}${path}`, { method, credentials: 'same-origin', headers, body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal });
    const raw = await response.text();
    let data: unknown = null;
    if (raw) { try { data = JSON.parse(raw); } catch { data = raw; } }
    if (!response.ok) {
      const detail = data && typeof data === 'object' ? (data as Record<string, unknown>).detail ?? (data as Record<string, unknown>).message : data;
      throw new ApiError(typeof detail === 'string' ? detail : `Request failed (${response.status})`, response.status);
    }
    return data as T;
  } catch (reason) {
    if (controller.signal.aborted) throw new ApiError(method === 'GET'
      ? 'The presenter status request timed out. Retrying connection…'
      : 'The server did not confirm this action before timeout. Check the saved run before retrying.', 0);
    if (reason instanceof TypeError) throw new ApiError('The presenter API is unreachable. Retrying connection…', 0);
    throw reason;
  } finally {
    window.clearTimeout(timeout);
  }
}
export async function session(): Promise<Session> {
  const result = await request<Session>('/session');
  csrfToken = result.csrfToken || '';
  return result;
}
export async function login(accessCode: string): Promise<Session> {
  await request<unknown>('/session', 'POST', { accessCode });
  return session();
}
export async function logout(): Promise<void> { await request('/logout', 'POST'); csrfToken = ''; }
export const listRuns = () => request<Run[]>('/runs');
export const getRun = (id: string) => request<Run>(`/runs/${encodeURIComponent(id)}`);
export const createRun = (mode: 'live' | 'replay', key?: string) => request<Run>('/runs', 'POST', { mode }, key);
export const approvePayment = (id: string, environment: 'baseline' | 'protected', transaction: Transaction) => request<Approval>(`/runs/${encodeURIComponent(id)}/approve-payment`, 'POST', { environment, snapshot: transaction });
export const command = (id: string, action: Action) => request<{ accepted: boolean; run: Run }>(`/runs/${encodeURIComponent(id)}/commands/${action}`, 'POST', {});
export const sendMessage = (id: string, text: string, channel: 'maya' | 'control_panel', clientMessageId = crypto.randomUUID()) =>
  request<{ accepted: boolean; reply?: string; run: Run }>(`/runs/${encodeURIComponent(id)}/messages`, 'POST',
    { text, channel, clientMessageId }, clientMessageId);
export const saveRemediationPlan = (id: string, text: string, expectedVersion: number) =>
  request<Run>(`/runs/${encodeURIComponent(id)}/remediation-plan`, 'POST', { text, expectedVersion });
export type ConnectorStates = { linear: { connected: boolean; configured: boolean }; jira: { connected: boolean; configured: boolean } };
export const getConnectors = () => request<ConnectorStates>('/connectors');
export type Capabilities = { liveWorker: { configured: boolean }; executors: { id: string; label: string; connected: boolean }[] };
export const getCapabilities = () => request<Capabilities>('/capabilities');
export const createIssue = (id: string, provider: 'linear' | 'jira', draft: { title: string; description: string; nativeFields?: Record<string, unknown> }) =>
  request<{ issue: { provider: 'linear' | 'jira'; id: string; key: string; title: string; url: string }; run: Run }>(
    `/runs/${encodeURIComponent(id)}/issues/${provider}`, 'POST', draft);
export const exportHref = (id: string, name: string) => `${root}/runs/${encodeURIComponent(id)}/exports/${encodeURIComponent(name)}`;
export function streamRun(id: string, onRun: (run: Run) => void): () => void {
  if (typeof EventSource === 'undefined') return () => undefined;
  const source = new EventSource(`${root}/runs/${encodeURIComponent(id)}/stream`, { withCredentials: true });
  source.onmessage = event => { try { onRun(JSON.parse(event.data) as Run); } catch { /* Polling remains the fallback. */ } };
  return () => source.close();
}
