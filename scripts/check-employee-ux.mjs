import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import path from 'node:path';

// Run inside the pinned Azure Playwright image. This check reads saved state
// only; after login, every same-origin non-read request is intercepted.
const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(here, '..');
const requirePresenter = createRequire(path.join(project, 'apps/presenter/package.json'));
const { chromium } = requirePresenter('playwright');
const baseURL = process.env.PRESENTER_URL;
const accessCode = process.env.PRESENTER_ACCESS_CODE;
const outputDir = process.env.EMPLOYEE_UX_OUTPUT_DIR || '/output';
if (!baseURL || !accessCode) throw new Error('Set PRESENTER_URL and PRESENTER_ACCESS_CODE.');
if (new URL(baseURL).protocol !== 'https:') throw new Error('PRESENTER_URL must use HTTPS.');
await fs.mkdir(outputDir, { recursive: true });

const viewports = [
  { name: 'desktop', width: 1280, height: 800 },
  { name: 'tablet', width: 820, height: 1180 },
  { name: 'phone', width: 390, height: 844 },
];
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'], chromiumSandbox: false });
const results = [];

function check(result, key, passed, detail) {
  result.checks[key] = { status: passed ? 'passed' : 'failed', ...(detail ? { detail } : {}) };
  if (!passed) result.failures.push(`${key}${detail ? `: ${detail}` : ''}`);
}

try {
  for (const viewport of viewports) {
    const context = await browser.newContext({ viewport, deviceScaleFactor: 1, hasTouch: true, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const result = { viewport, checks: {}, failures: [], blockedMutations: [], pageErrors: [], screenshots: [] };
    const origin = new URL(baseURL).origin;
    let protectWrites = false;
    page.on('pageerror', error => result.pageErrors.push(error.message));
    await page.goto(baseURL, { waitUntil: 'networkidle' });
    const access = page.getByLabel('Workspace access code');
    await access.waitFor({ state: 'visible', timeout: 15000 });
    await access.fill(accessCode);
    await page.getByRole('button', { name: /open workspace/i }).click();
    const workTab = page.getByRole('button', { name: 'Work', exact: true });
    const chatTab = page.getByRole('button', { name: 'Chat', exact: true });
    await workTab.click();
    const savedRunPicker = page.getByLabel('Open a saved run');
    await savedRunPicker.waitFor({ state: 'visible', timeout: 15000 });

    // Login has completed. Block and report any attempted same-origin write so
    // this acceptance cannot submit chat, approvals, repair, reset, or issues.
    protectWrites = true;
    await page.route('**/*', async route => {
      const request = route.request();
      const method = request.method().toUpperCase();
      if (protectWrites && new URL(request.url()).origin === origin && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        result.blockedMutations.push(`${method} ${new URL(request.url()).pathname}`);
        await route.abort('blockedbyclient');
      } else await route.continue();
    });

    const options = await savedRunPicker.locator('option').evaluateAll(nodes => nodes
      .map(option => ({ value: option.value, label: option.textContent?.trim() || '' }))
      .filter(option => option.value));
    check(result, 'saved_runs_available', options.length > 0, options.length ? `${options.length} saved run(s)` : 'No persisted runs');
    if (!options.length) throw new Error(`No saved runs available at ${viewport.name} viewport.`);

    // Discover incident-bearing persisted replay runs through their rendered
    // employee view. Prefer a resumed run when one is present.
    const replayOptions = options.filter(option => /replay/i.test(option.label));
    check(result, 'persisted_replay_available', replayOptions.length > 0, replayOptions.length ? `${replayOptions.length} replay run(s)` : 'No replay-labelled saved run');
    if (!replayOptions.length) throw new Error(`No saved replay run is available at ${viewport.name} viewport.`);
    let replay = null;
    let replayState = '';
    const candidateDiagnostics = [];
    for (const candidate of replayOptions) {
      await savedRunPicker.selectOption(candidate.value);
      await chatTab.click();
      const card = page.locator('.employee-blocked-card');
      try { await card.waitFor({ state: 'visible', timeout: 2500 }); } catch {
        const state = await page.locator('.employee-task-card').innerText().catch(() => '');
        candidateDiagnostics.push({ label: candidate.label, runStatus: state.match(/Run status[\s\S]{0,70}/i)?.[0] || 'unavailable', incidentCard: false });
        await workTab.click();
        await savedRunPicker.waitFor({ state: 'visible', timeout: 10000 });
        continue;
      }
      const state = await page.locator('.employee-task-card').innerText().catch(() => '');
      candidateDiagnostics.push({ label: candidate.label, runStatus: state.match(/Run status[\s\S]{0,70}/i)?.[0] || 'unavailable', incidentCard: true });
      if (!replay || /resum/i.test(state) || /reproduc/i.test(state)) {
        replay = candidate;
        replayState = state;
      }
      if (/resum/i.test(state)) break;
    }
    if (!replay) {
      result.checks.persisted_incident_replay_selected = { status: 'blocked', detail: 'No saved replay rendered a reproduced incident card.' };
      result.checks.resumed_or_reproduced_preferred = { status: 'blocked', detail: JSON.stringify(candidateDiagnostics) };
      result.blocked = 'The saved replay incident required for this acceptance was not available in the hosted run list.';
      const name = `employee-${viewport.name}-saved-runs.png`;
      await page.screenshot({ path: path.join(outputDir, name), fullPage: true });
      result.screenshots.push(name);
      result.failures.push(result.blocked);
      await context.close();
      results.push(result);
      continue;
    }
    check(result, 'persisted_incident_replay_selected', true, replay.label);
    check(result, 'resumed_or_reproduced_preferred', true, replayState.match(/Run status[^\n]*/i)?.[0] || 'Incident card is derived from incident.status=reproduced');
    await page.getByRole('heading', { name: 'Maya' }).waitFor();
    const loadedIncident = page.locator('.employee-blocked-card');
    await loadedIncident.waitFor({ state: 'visible', timeout: 15000 });
    await page.screenshot({ path: path.join(outputDir, `employee-${viewport.name}-chat.png`), fullPage: true });
    result.screenshots.push(`employee-${viewport.name}-chat.png`);

    const blockedCard = page.getByRole('article', { name: /vibesecur stopped a payment change/i });
    check(result, 'employee_blocked_incident_card', await blockedCard.isVisible().catch(() => false));
    check(result, 'connected_status', await page.locator('.employee-security-mark.is-connected[role="status"]').isVisible().catch(() => false), 'VibeSecur ON connected marker');
    const suggestion = page.getByRole('button', { name: 'Summarize the invoice', exact: true });
    await suggestion.click();
    check(result, 'suggestion_only_fills_composer', await page.getByLabel('Message Maya').inputValue() === 'Summarize the invoice');
    check(result, 'suggestion_does_not_enable_network_write', result.blockedMutations.length === 0);
    await page.getByLabel('Message Maya').fill('');

    const viewIncident = page.getByRole('button', { name: /view what happened/i });
    await viewIncident.click();
    await page.getByRole('heading', { name: /payment change blocked/i }).waitFor({ state: 'visible' });
    check(result, 'control_panel_opened_from_incident', await page.getByText('Control Panel', { exact: true }).isVisible());
    const approved = page.getByText('Approved payment', { exact: true });
    const attempted = page.getByText('Attempted payment', { exact: true });
    const comparison = page.locator('[aria-label="Approved and attempted payment comparison"]');
    const accountValues = await comparison.locator('> div').evaluateAll(nodes => nodes.slice(0, 2).map(node => node.querySelector('dd span')?.textContent?.trim() || ''));
    check(result, 'approved_and_attempted_accounts_shown', await approved.isVisible() && await attempted.isVisible() && accountValues.length === 2 && accountValues.every(Boolean) && accountValues[0] !== accountValues[1], accountValues.join(' vs '));
    check(result, 'attempted_payment_reported_stopped', await page.getByText('Nothing was sent', { exact: true }).isVisible());
    const report = page.locator('details.cp-report > summary');
    check(result, 'saved_report_disclosure_present', await report.isVisible().catch(() => false));
    if (await report.isVisible().catch(() => false)) {
      await report.click();
      const reportBody = page.locator('.cp-report');
      const reportText = await reportBody.innerText().catch(() => '');
      check(result, 'saved_report_has_grounded_prose', reportText.trim().length > 120, `rendered report text ${reportText.trim().length} chars`);
    } else check(result, 'saved_report_has_grounded_prose', false, 'Saved investigation report disclosure missing');

    const planSteps = page.locator('.cp-plan-list li');
    const planCopy = await planSteps.allInnerTexts().catch(() => []);
    check(result, 'saved_plan_prose_present', planCopy.length > 0 && planCopy.join(' ').replace(/[^\p{L}\p{N}]/gu, '').length > 40, planCopy.join(' ').slice(0, 240));
    const linear = page.getByRole('button', { name: /create linear issue/i });
    const jira = page.getByRole('button', { name: /create jira ticket/i });
    await linear.click();
    const linearCopy = await page.locator('.cp-issue-compose').innerText();
    check(result, 'linear_disconnected_honest', /not connected/i.test(linearCopy) && await page.locator('.cp-issue-compose button[type="submit"]').isDisabled());
    await page.getByRole('button', { name: 'Close issue draft' }).click();
    await jira.click();
    const jiraCopy = await page.locator('.cp-issue-compose').innerText();
    check(result, 'jira_disconnected_honest', /not connected/i.test(jiraCopy) && await page.locator('.cp-issue-compose button[type="submit"]').isDisabled());
    await page.getByRole('button', { name: 'Close issue draft' }).click();
    await page.screenshot({ path: path.join(outputDir, `employee-${viewport.name}-control-panel.png`), fullPage: true });
    result.screenshots.push(`employee-${viewport.name}-control-panel.png`);

    const motion = await page.evaluate(() => ({
      preference: matchMedia('(prefers-reduced-motion: reduce)').matches,
      styles: ['.employee-workspace', '.cp-panel'].map(selector => {
        const node = document.querySelector(selector);
        if (!node) return { selector, present: false };
        const style = getComputedStyle(node);
        return { selector, present: true, animationDuration: style.animationDuration, transitionDuration: style.transitionDuration };
      }),
    }));
    const reducedMotionApplied = motion.preference && motion.styles.every(item => item.present &&
      [...item.animationDuration.split(','), ...item.transitionDuration.split(',')].every(part => {
        const value = Number.parseFloat(part);
        const milliseconds = part.trim().endsWith('ms') ? value : value * 1000;
        return milliseconds < 1;
      }));
    check(result, 'reduced_motion_styles_applied', reducedMotionApplied, JSON.stringify(motion));

    // Verify keyboard focus can reach the return action and primary controls
    // remain comfortably touch-sized at each target viewport.
    const back = page.getByRole('button', { name: /back to maya/i }).last();
    await page.keyboard.press('Tab');
    const keyboardFocus = await page.evaluate(() => {
      const node = document.activeElement;
      if (!(node instanceof HTMLElement)) return { visible: false, tag: null };
      const style = getComputedStyle(node);
      return { visible: node.matches(':focus-visible'), tag: node.tagName, text: node.innerText?.trim(), outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth };
    });
    check(result, 'keyboard_focus_visible', keyboardFocus.visible, JSON.stringify(keyboardFocus));
    const targets = await page.evaluate(() => [...document.querySelectorAll('.cp-back, .cp-return-actions button, .cp-phase button')]
      .filter(node => node instanceof HTMLElement && !node.hasAttribute('disabled'))
      .map(node => ({ label: node.innerText.trim(), width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height })));
    const undersized = targets.filter(target => target.width < 44 || target.height < 44);
    check(result, 'principal_touch_targets_at_least_44px', targets.length > 0 && undersized.length === 0, undersized.length ? JSON.stringify(undersized) : `${targets.length} controls checked`);
    await back.click();
    await page.getByRole('heading', { name: 'Maya' }).waitFor();
    check(result, 'return_to_maya', await page.getByRole('button', { name: /view what happened/i }).isVisible());
    await workTab.click();
    await savedRunPicker.waitFor({ state: 'visible', timeout: 10000 });
    const selectedBeforeRefresh = await savedRunPicker.inputValue();
    await page.getByRole('button', { name: 'Refresh saved runs', exact: true }).click();
    await page.waitForFunction(value => document.querySelector('#employee-saved-run')?.value === value, selectedBeforeRefresh, { timeout: 10000 });
    check(result, 'refresh_preserves_selected_incident', await page.getByRole('button', { name: /view what happened/i }).isVisible());

    // Exercise a real reconnect cycle using browser network emulation only.
    await context.setOffline(true);
    await page.getByRole('button', { name: 'Refresh saved runs', exact: true }).click().catch(() => {});
    await context.setOffline(false);
    await page.getByRole('button', { name: 'Refresh saved runs', exact: true }).click();
    let connected = false;
    try {
      await page.locator('.employee-security-mark.is-connected[role="status"]').waitFor({ state: 'visible', timeout: 15000 });
      connected = true;
    } catch {
      const connectionDom = await page.locator('[role="status"]').evaluateAll(nodes => nodes.map(node => ({ text: node.textContent?.trim(), html: node.outerHTML })));
      const name = `employee-${viewport.name}-reconnect-failure.png`;
      await page.screenshot({ path: path.join(outputDir, name), fullPage: true });
      result.screenshots.push(name);
      result.connectionDiagnostic = { statuses: connectionDom, visibleText: (await page.locator('body').innerText()).slice(-1800) };
    }
    const selectedAfterReconnect = await savedRunPicker.inputValue();
    await chatTab.click();
    check(result, 'reconnect_preserves_selected_incident', connected && selectedAfterReconnect === selectedBeforeRefresh && await page.locator('.employee-blocked-card').isVisible().catch(() => false), connected ? undefined : JSON.stringify(result.connectionDiagnostic));

    const layout = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      focusableCount: [...document.querySelectorAll('button, a, input, select, textarea, summary, [tabindex]')]
        .filter(node => node.getClientRects().length && node.getAttribute('tabindex') !== '-1').length,
    }));
    check(result, 'no_horizontal_overflow', !layout.overflow);
    check(result, 'keyboard_reachable_controls_present', layout.focusableCount > 0, `${layout.focusableCount} rendered controls`);
    check(result, 'no_post_login_mutations', result.blockedMutations.length === 0, result.blockedMutations.join(', ') || undefined);
    check(result, 'no_page_errors', result.pageErrors.length === 0, result.pageErrors.join(' | ') || undefined);
    await context.close();
    results.push(result);
  }
} finally {
  await browser.close();
}

const summary = {
  scope: 'Read-only employee UX acceptance against the VibeSecur-owned synthetic hosted demo; login POST is excluded; all same-origin writes after login are blocked.',
  baseURL,
  generatedAt: new Date().toISOString(),
  results,
  passed: results.length === viewports.length && results.every(result => result.failures.length === 0),
};
await fs.writeFile(path.join(outputDir, 'employee-ux-results.json'), `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify(summary, null, 2));
if (!summary.passed) process.exitCode = 1;
