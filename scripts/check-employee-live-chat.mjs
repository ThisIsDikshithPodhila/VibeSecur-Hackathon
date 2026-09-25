import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import path from 'node:path';

// Opt-in transport/persistence smoke on one fresh live run. It admits one live
// run creation and two exact read-only Maya messages; every other write is blocked.
const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(here, '..');
const requirePresenter = createRequire(path.join(project, 'apps/presenter/package.json'));
const { chromium } = requirePresenter('playwright');
const baseURL = process.env.PRESENTER_URL;
const accessCode = process.env.PRESENTER_ACCESS_CODE;
const outputDir = process.env.EMPLOYEE_CHAT_OUTPUT_DIR || '/output';
const channel = 'maya';
const prompts = [
  'Summarize the invoice',
  'From your prior summary, name the supplier and invoice amount.',
];
if (!baseURL || !accessCode) throw new Error('Set PRESENTER_URL and PRESENTER_ACCESS_CODE.');
if (new URL(baseURL).protocol !== 'https:') throw new Error('PRESENTER_URL must use HTTPS.');
await fs.mkdir(outputDir, { recursive: true });

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'], chromiumSandbox: false });
const result = {
  scope: 'Fresh live-run chat transport and persistence only. Prompts request safe reads. This does not test payment decisions, security enforcement, repair, approval, or provider identity.',
  baseURL,
  channel,
  prompts,
  checks: {},
  blockedMutations: [],
  allowedMutations: [],
  pageErrors: [],
  screenshots: [],
};
let protectWrites = false;
let runCreateCount = 0;
let runId;
const messageClientIds = new Set();
let page;
const origin = new URL(baseURL).origin;

function check(key, passed, detail) {
  result.checks[key] = { status: passed ? 'passed' : 'failed', ...(detail ? { detail } : {}) };
  if (!passed) {
    result.failures ??= [];
    result.failures.push(`${key}${detail ? `: ${detail}` : ''}`);
  }
}

function asRun(payload) {
  return payload?.run && typeof payload.run === 'object' ? payload.run : payload;
}

function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function orderedEvents(run) {
  return Array.isArray(run?.events) ? [...run.events].sort((a, b) => a.sequence - b.sequence) : [];
}

function turnForPrompt(run, prompt) {
  const turns = run?.conversation?.turns;
  return Array.isArray(turns) ? turns.find(turn => turn.text === prompt) : undefined;
}

function conversationEventsForTurn(run, turnId) {
  return orderedEvents(run).filter(event =>
    (event.kind === 'conversation.user' || event.kind === 'conversation.maya') && event.data?.turnId === turnId);
}

async function fetchRunSnapshot() {
  if (!runId) throw new Error('The fresh live run ID is missing.');
  const snapshot = await page.evaluate(async id => {
    const response = await fetch(`/api/runs/${encodeURIComponent(id)}`, { credentials: 'same-origin' });
    return { status: response.status, ok: response.ok, body: await response.json() };
  }, runId);
  if (!snapshot.ok) throw new Error(`Run snapshot GET failed with HTTP ${snapshot.status}.`);
  return asRun(snapshot.body);
}

async function waitForTurn(prompt, afterSequence, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  let latestRun;
  while (Date.now() < deadline) {
    latestRun = await fetchRunSnapshot();
    const turn = turnForPrompt(latestRun, prompt);
    if (turn && ['succeeded', 'failed', 'held', 'cancelled'].includes(turn.status)) return { run: latestRun, turn };
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  const newEvents = orderedEvents(latestRun).filter(event => event.sequence > afterSequence);
  throw new Error(`Turn did not reach a terminal state; new event count=${newEvents.length}.`);
}

function validateTurn(run, turn, prompt, priorConversationId) {
  const matching = conversationEventsForTurn(run, turn.turnId);
  const user = matching.find(event => event.kind === 'conversation.user' && event.data?.text === prompt && event.data?.channel === channel);
  const maya = matching.filter(event => event.kind === 'conversation.maya' && typeof event.data?.text === 'string' && event.data.text.trim()).at(-1);
  const turnStatus = turn.status === 'succeeded';
  const turnScope = turn.scope === 'read_only';
  const conversationId = run?.conversation?.conversationId;
  check(`turn_${turn.turnId}_succeeded`, turnStatus, `status=${turn.status}`);
  check(`turn_${turn.turnId}_read_only`, turnScope, `scope=${turn.scope}`);
  check(`turn_${turn.turnId}_user_event`, Boolean(user), user ? `sequence=${user.sequence}` : 'Missing matching conversation.user event.');
  check(`turn_${turn.turnId}_maya_event`, Boolean(maya), maya ? `sequence=${maya.sequence}` : 'Missing non-empty conversation.maya event.');
  check(`turn_${turn.turnId}_conversation_continuity`, typeof conversationId === 'string' && conversationId.length > 0 && (!priorConversationId || priorConversationId === conversationId),
    priorConversationId ? 'conversationId remained stable' : 'conversationId recorded');
  if (user && maya) {
    check(`turn_${turn.turnId}_event_order`, user.sequence < maya.sequence, `${user.sequence} < ${maya.sequence}`);
    return { conversationId, turnId: turn.turnId, userEventId: user.eventId, mayaEventId: maya.eventId, mayaText: maya.data.text };
  }
  return { conversationId, turnId: turn.turnId, userEventId: user?.eventId, mayaEventId: maya?.eventId, mayaText: maya?.data?.text || '' };
}

try {
  page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  page.on('pageerror', error => result.pageErrors.push(error.message));
  await page.goto(baseURL, { waitUntil: 'networkidle' });
  const access = page.getByLabel('Workspace access code');
  await access.waitFor({ state: 'visible', timeout: 15000 });
  await access.fill(accessCode);
  await page.getByRole('button', { name: /open workspace/i }).click();
  protectWrites = true;

  let admittedMessageCount = 0;
  const messageRequests = [];
  await page.route('**/*', async route => {
    const request = route.request();
    const method = request.method().toUpperCase();
    const requestUrl = new URL(request.url());
    if (!protectWrites || ['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      await route.continue();
      return;
    }

    let body;
    try { body = request.postDataJSON(); } catch { body = null; }
    if (requestUrl.origin === origin && method === 'POST' && requestUrl.pathname === '/api/runs' &&
      body?.mode === 'live' && Object.keys(body).length === 1 && runCreateCount === 0) {
      runCreateCount += 1;
      result.allowedMutations.push({ method, path: requestUrl.pathname, mode: 'live' });
      await route.continue();
      return;
    }

    const pathMatch = runId && requestUrl.origin === origin && requestUrl.pathname === `/api/runs/${runId}/messages`;
    const expectedPrompt = prompts[admittedMessageCount];
    const clientMessageId = body?.clientMessageId ?? request.headers()['idempotency-key'];
    const validMessage = pathMatch && method === 'POST' && body?.text === expectedPrompt && body?.channel === channel && isUuid(clientMessageId) &&
      !messageClientIds.has(clientMessageId) && admittedMessageCount < prompts.length;
    if (validMessage) {
      admittedMessageCount += 1;
      messageClientIds.add(clientMessageId);
      messageRequests.push({ prompt: expectedPrompt, clientMessageId });
      result.allowedMutations.push({ method, path: requestUrl.pathname, channel, text: expectedPrompt, clientMessageId });
      await route.continue();
      return;
    }

    result.blockedMutations.push({ method, path: requestUrl.pathname, origin: requestUrl.origin });
    await route.abort('blockedbyclient');
  });

  await page.getByRole('button', { name: 'Work', exact: true }).click();
  const settings = page.getByText('Run settings', { exact: true });
  await settings.click();
  const mode = page.locator('#employee-run-mode');
  await mode.waitFor({ state: 'visible', timeout: 10000 });
  await mode.selectOption('live');
  const createResponsePromise = page.waitForResponse(response =>
    response.request().method().toUpperCase() === 'POST' && new URL(response.url()).pathname === '/api/runs',
  { timeout: 30000 });
  await page.getByRole('button', { name: 'Start work session', exact: true }).click();
  const createResponse = await createResponsePromise;
  const createdPayload = await createResponse.json();
  const createdRun = asRun(createdPayload);
  runId = typeof createdRun?.runId === 'string' ? createdRun.runId : undefined;
  check('one_fresh_live_run_created', createResponse.ok() && runCreateCount === 1 && createdRun?.mode === 'live' && Boolean(runId),
    `HTTP ${createResponse.status()}; mode=${createdRun?.mode}; runId=${runId ? 'present' : 'missing'}`);
  if (!createResponse.ok() || !runId || createdRun?.mode !== 'live') throw new Error('Fresh live run creation response did not match the expected RunView.');
  result.runId = runId;
  result.initialEventIds = orderedEvents(createdRun).map(event => event.eventId).filter(Boolean);
  const initialMaxSequence = Math.max(0, ...orderedEvents(createdRun).map(event => Number(event.sequence) || 0));
  await page.getByRole('heading', { name: 'Maya' }).waitFor({ state: 'visible', timeout: 15000 });

  const transcript = page.getByRole('log', { name: 'Saved conversation with Maya' });
  await transcript.waitFor({ state: 'visible', timeout: 15000 });
  const turnResults = [];
  let stableConversationId;
  let afterSequence = initialMaxSequence;

  for (let index = 0; index < prompts.length; index += 1) {
    const prompt = prompts[index];
    const messagePostPromise = page.waitForResponse(response =>
      response.request().method().toUpperCase() === 'POST' && new URL(response.url()).pathname === `/api/runs/${runId}/messages`,
    { timeout: 30000 });
    await page.locator('#employee-message').fill(prompt);
    await page.getByRole('button', { name: 'Send message', exact: true }).click();
    const messageResponse = await messagePostPromise;
    const accepted = await messageResponse.json();
    const acceptedRun = asRun(accepted);
    check(`turn_${index + 1}_accepted`, messageResponse.status() === 202 && accepted?.accepted === true && acceptedRun?.runId === runId,
      `HTTP ${messageResponse.status()}; accepted=${accepted?.accepted}`);
    if (messageResponse.status() !== 202 || accepted?.accepted !== true || acceptedRun?.runId !== runId) {
      throw new Error(`Turn ${index + 1} was not accepted for the fresh run.`);
    }

    const completed = await waitForTurn(prompt, afterSequence);
    const turnResult = validateTurn(completed.run, completed.turn, prompt, stableConversationId);
    stableConversationId = turnResult.conversationId;
    const relevantEvents = conversationEventsForTurn(completed.run, turnResult.turnId);
    afterSequence = Math.max(afterSequence, ...relevantEvents.map(event => Number(event.sequence) || 0));
    turnResults.push({
      turnId: turnResult.turnId,
      userEventId: turnResult.userEventId,
      mayaEventId: turnResult.mayaEventId,
      userText: prompt,
      mayaTextLength: turnResult.mayaText.length,
      eventSequence: relevantEvents.map(event => event.sequence),
    });
    await transcript.getByText(prompt, { exact: true }).last().waitFor({ state: 'visible', timeout: 15000 });
    if (turnResult.mayaText) await transcript.getByText(turnResult.mayaText, { exact: true }).last().waitFor({ state: 'visible', timeout: 15000 });
  }

  check('two_turn_continuity', turnResults.length === 2 && turnResults[0].turnId !== turnResults[1].turnId && Boolean(stableConversationId),
    `${turnResults.length} completed turns in one conversation`);
  const persistedBeforeReload = await fetchRunSnapshot();
  const beforeReloadEvents = orderedEvents(persistedBeforeReload);
  const newConversationEvents = beforeReloadEvents.filter(event => !result.initialEventIds.includes(event.eventId) &&
    (event.kind === 'conversation.user' || event.kind === 'conversation.maya'));
  check('new_conversation_events_persisted', newConversationEvents.length >= 4, `${newConversationEvents.length} new conversation events`);
  const unexpectedAllowedWrites = result.allowedMutations.filter(item => item.path !== '/api/runs' && item.path !== `/api/runs/${runId}/messages`);
  check('only_expected_run_and_message_writes', unexpectedAllowedWrites.length === 0 && result.blockedMutations.length === 0,
    JSON.stringify({ unexpectedAllowedWrites, blocked: result.blockedMutations }));
  check('exactly_two_unique_message_posts', admittedMessageCount === 2 && messageRequests.length === 2 && new Set(messageRequests.map(item => item.clientMessageId)).size === 2,
    `messagePosts=${admittedMessageCount}`);
  await page.screenshot({ path: path.join(outputDir, 'employee-live-chat-before-reload.png'), fullPage: true });
  result.screenshots.push('employee-live-chat-before-reload.png');

  const durableEventIds = new Set(newConversationEvents.map(event => event.eventId));
  await page.reload({ waitUntil: 'networkidle' });
  const accessAfterReload = page.getByLabel('Workspace access code');
  if (await accessAfterReload.isVisible().catch(() => false)) {
    // Re-authentication is excluded onboarding; all application writes remain guarded.
    protectWrites = false;
    await accessAfterReload.fill(accessCode);
    await page.getByRole('button', { name: /open workspace/i }).click();
  }
  protectWrites = true;
  await page.getByRole('button', { name: 'Work', exact: true }).click();
  const savedRunPicker = page.locator('#employee-saved-run');
  await savedRunPicker.waitFor({ state: 'visible', timeout: 15000 });
  const freshRunPresent = await savedRunPicker.locator('option').evaluateAll(nodes => nodes.some(option => option.value === runId));
  check('fresh_live_run_survives_reload', freshRunPresent, runId);
  if (!freshRunPresent) throw new Error('Fresh live run was not available in Work after reload.');
  await savedRunPicker.selectOption(runId);
  await page.getByRole('heading', { name: 'Maya' }).waitFor({ state: 'visible', timeout: 15000 });
  const transcriptAfterReload = page.getByRole('log', { name: 'Saved conversation with Maya' });
  for (const turn of turnResults) {
    await transcriptAfterReload.getByText(turn.userText, { exact: true }).last().waitFor({ state: 'visible', timeout: 15000 });
  }
  const afterReloadRun = await fetchRunSnapshot();
  const afterReloadIds = new Set(orderedEvents(afterReloadRun).map(event => event.eventId));
  check('same_conversation_survives_reload', afterReloadRun?.conversation?.conversationId === stableConversationId);
  check('new_turn_event_ids_survive_reload', [...durableEventIds].every(eventId => afterReloadIds.has(eventId)), `${durableEventIds.size} event IDs`);
  check('same_run_still_live_after_reload', afterReloadRun?.runId === runId && afterReloadRun?.mode === 'live', `mode=${afterReloadRun?.mode}`);
  await page.screenshot({ path: path.join(outputDir, 'employee-live-chat-after-reload.png'), fullPage: true });
  result.screenshots.push('employee-live-chat-after-reload.png');
  check('no_other_post_login_writes', result.blockedMutations.length === 0, JSON.stringify(result.blockedMutations));
  check('no_page_errors', result.pageErrors.length === 0, result.pageErrors.join(' | '));
  result.turns = turnResults;
  result.conversationId = stableConversationId;
} catch (error) {
  result.executionError = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
} finally {
  await browser.close();
}

const summary = {
  ...result,
  generatedAt: new Date().toISOString(),
  passed: !result.executionError && !result.failures?.length && result.blockedMutations.length === 0 && result.pageErrors.length === 0 &&
    runCreateCount === 1 && result.allowedMutations.filter(item => item.path?.endsWith('/messages')).length === 2,
};
await fs.writeFile(path.join(outputDir, 'employee-live-chat-smoke-results.json'), `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify(summary, null, 2));
if (!summary.passed) process.exitCode = 1;
