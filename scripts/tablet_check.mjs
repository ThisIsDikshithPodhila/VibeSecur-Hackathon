import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs/promises';

const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(here, '..');
const requirePresenter = createRequire(path.join(project, 'apps/presenter/package.json'));
const { chromium } = requirePresenter('playwright');
const baseURL = process.env.PRESENTER_URL || 'http://127.0.0.1:5173';
const accessCode = process.env.PRESENTER_ACCESS_CODE;
const output = path.join(project, 'docs/design/browser-check');
await fs.mkdir(output, { recursive: true });
const browserOptions = { headless: true, args: ['--no-sandbox'], chromiumSandbox: false };
if (process.env.CHROME_PATH) browserOptions.executablePath = process.env.CHROME_PATH;
const browser = await chromium.launch(browserOptions);
const viewports = [
  { name: 'landscape', width: 1280, height: 800 },
  { name: 'tablet-portrait', width: 820, height: 1180 },
  { name: 'phone', width: 390, height: 844 },
];
let failures = 0;

for (const viewport of viewports) {
  const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height }, deviceScaleFactor: 1, hasTouch: true });
  const page = await context.newPage();
  const errors = [];
  const externalFontRequests = [];
  const unexpectedMutations = [];
  let trackMutations = false;
  const origin = new URL(baseURL).origin;
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => {
    if (/fonts\.(googleapis|gstatic)\.com/i.test(request.url())) externalFontRequests.push(request.url());
    const method = request.method().toUpperCase();
    if (trackMutations && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      const requestUrl = new URL(request.url());
      if (requestUrl.origin === origin) unexpectedMutations.push(`${method} ${requestUrl.pathname}`);
    }
  });
  await page.goto(baseURL, { waitUntil: 'networkidle' });
  await page.screenshot({ path: path.join(output, `${viewport.name}-login-screen.png`) });
  const initialOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2);
  const loginVisible = await page.getByLabel('Presenter access code').isVisible().catch(() => false);
  let authenticated = false;
  let authenticatedOverflow = 'not tested (access code absent)';
  let responsivePresentation = 'not tested (access code absent)';
  let newRunModeSelector = 'not tested (access code absent)';
  let resumedReplayEvidence = 'not tested (no persisted resumed replay selected)';
  let persistence = 'not tested (access code absent)';
  let replayControls = 'not tested (no replay run available)';
  let liveControls = 'not tested (no live run available)';
  let sectionKeyboardNavigation = 'not tested (access code absent)';
  let guidanceCue = 'not tested (access code absent)';
  let guidanceKeyboardNavigation = 'not tested (access code absent)';
  let resetDialog = 'not tested (no saved run selected)';
  let offlineRecovery = 'not tested (access code absent)';
  let reducedMotion = 'not tested (access code absent)';

  if (accessCode && loginVisible) {
    await page.getByLabel('Presenter access code').fill(accessCode);
    await page.getByRole('button', { name: 'Open control room' }).click();
    authenticated = true;
    trackMutations = true;
    const runPicker = page.getByLabel('Select run');
    await runPicker.waitFor({ timeout: 10000 });
    await page.waitForFunction(() => {
      const picker = document.querySelector('select[aria-label="Select run"]');
      return !!picker && [...picker.options].some(option => option.value);
    }, null, { timeout: 15000 });
    const options = await runPicker.locator('option').evaluateAll(items => items.map(option => ({ value: option.value, label: option.textContent || '' })).filter(option => option.value));
    const newRunMode = page.locator('select#mode');
    const initialNewMode = await newRunMode.inputValue();
    const modeOptions = await newRunMode.locator('option').evaluateAll(items => items.map(option => ({ value: option.value, label: option.textContent || '' })));
    const hasLiveOption = modeOptions.some(option => option.value === 'live' && /live agent/i.test(option.label));
    await newRunMode.selectOption('live');
    const liveSelectable = await newRunMode.inputValue() === 'live';
    await newRunMode.selectOption('replay');
    newRunModeSelector = initialNewMode === 'replay' && hasLiveOption && liveSelectable &&
      await newRunMode.inputValue() === 'replay' ? 'passed' : 'failed';

    const resumedReplay = options.find(option => /replay/.test(option.label.toLowerCase()) && /resumed/.test(option.label.toLowerCase()));
    let selected = resumedReplay?.value || await runPicker.inputValue();
    if (!selected) {
      selected = options[0]?.value || '';
      if (!selected) throw new Error('Authenticated run picker populated with no saved runs.');
    }
    if (await runPicker.inputValue() !== selected) await runPicker.selectOption(selected);
    await page.waitForFunction(value => document.querySelector('select[aria-label="Select run"]')?.value === value, selected, { timeout: 5000 });
    const selectedLabel = options.find(option => option.value === selected)?.label.toLowerCase() || '';
    const selectedModeText = selectedLabel.includes('replay') ? 'Deterministic replay' : 'Live agent requested';
    await page.locator('.session-info').getByText(selectedModeText, { exact: true }).waitFor({ timeout: 5000 });

    const selectedResumedReplay = !!resumedReplay && selected === resumedReplay.value && /replay/.test(selectedLabel) && /resumed/.test(selectedLabel);
    if (selectedResumedReplay) {
      const milestones = page.locator('#repair-record .record-milestones');
      await milestones.waitFor({ state: 'visible', timeout: 5000 });
      const rows = await milestones.locator(':scope > div').evaluateAll(items => Object.fromEntries(items.map(item => [
        item.querySelector('dt')?.textContent?.trim() || '', item.querySelector('dd')?.textContent?.trim() || '',
      ])));
      resumedReplayEvidence = rows['Repair output'] === 'Candidate recorded' &&
        rows['Verification'] === 'Passed for this artifact' &&
        rows['Deployment'] === 'Deployment and readiness probe recorded'
        ? 'passed' : 'failed (distinct passing repair, matching verification, and deployment/probe rows not present)';
    } else {
      resumedReplayEvidence = 'failed (no persisted resumed replay was available to select)';
    }

    const guidance = page.getByTestId('presenter-guidance');
    const missionNav = page.getByRole('navigation', { name: 'Mission sections' });
    const missionNavButtons = missionNav.getByRole('button');
    const responsive = await guidance.isVisible() && await missionNav.isVisible() &&
      await missionNavButtons.count() === 3 &&
      await missionNavButtons.nth(0).isVisible() && await missionNavButtons.nth(1).isVisible() &&
      await missionNavButtons.nth(2).isVisible();
    responsivePresentation = responsive && !(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2))
      ? 'passed' : 'failed';
    const guidanceSnapshot = async () => ({
      title: (await guidance.locator('h2').innerText()).trim(),
      savedState: (await guidance.locator('.presenter-guidance__context span').nth(1).innerText()).replace(/^Saved state · /, '').trim(),
      detail: (await guidance.locator('.presenter-guidance__message p').innerText()).trim(),
      next: (await guidance.locator('.presenter-guidance__next').innerText()).trim(),
    });
    const cueBeforeReload = await guidanceSnapshot();
    guidanceCue = Object.values(cueBeforeReload).every(Boolean) ? 'passed' : 'failed';
    const cueNext = guidance.locator('.presenter-guidance__next');
    const assertCueKeyboardNavigation = async (requireReducedMotion = false) => {
      const controlledTarget = await cueNext.getAttribute('aria-controls');
      if (!controlledTarget) return false;
      const protectedReceiptExists = await page.locator('#protected-receipt').count() > 0;
      if (selectedResumedReplay && protectedReceiptExists && controlledTarget !== 'protected-receipt') return false;
      const expectedFocus = await page.evaluate(targetId => {
        const target = document.getElementById(targetId);
        // Disabled resume controls intentionally fall back to the Recovery section.
        return targetId === 'resume-control' && target?.matches(':disabled') ? 'recovery-proof' : targetId;
      }, controlledTarget);
      await cueNext.focus();
      await page.keyboard.press('Enter');
      try {
        await page.waitForFunction(({ controlledTarget, expectedFocus, requireReducedMotion }) => {
          if (requireReducedMotion && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) return false;
          const cueButton = document.querySelector('.presenter-guidance__next');
          if (cueButton?.getAttribute('aria-controls') !== controlledTarget || document.activeElement?.id !== expectedFocus) return false;
          const activeSection = document.activeElement?.closest('.area')?.id;
          if (!activeSection) return true;
          if (controlledTarget === 'protected-receipt') {
            const receipt = document.getElementById('protected-receipt');
            const stickyNav = document.querySelector('.chapter-nav');
            if (!receipt || !stickyNav) return false;
            const receiptRect = receipt.getBoundingClientRect();
            const navRect = stickyNav.getBoundingClientRect();
            if (receiptRect.top < navRect.bottom || receiptRect.top >= window.innerHeight || receiptRect.bottom <= navRect.bottom) return false;
          }
          const selectedLink = document.querySelector('[aria-label="Mission sections"] [aria-current="location"]');
          const label = selectedLink?.textContent || '';
          const selectedSection = label.includes('Business') ? 'business-state' :
            label.includes('Investigation') ? 'evidence-trail' : label.includes('Recovery') ? 'recovery-proof' : '';
          return selectedSection === activeSection;
        }, { controlledTarget, expectedFocus, requireReducedMotion }, { timeout: 1500 });
        return true;
      } catch { return false; }
    };
    guidanceKeyboardNavigation = await assertCueKeyboardNavigation() ? 'passed' : 'failed';

    authenticatedOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2) ? 'failed' : 'passed';
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(250); // Let the short initial value transition settle for visual evidence.
    await page.screenshot({ path: path.join(output, `${viewport.name}-authenticated-screen.png`) });
    const navChecks = [
      { label: 'Business', target: 'business-state' },
      { label: 'Investigation', target: 'evidence-trail' },
      { label: 'Recovery', target: 'recovery-proof' },
    ];
    let navPassed = true;
    for (const item of navChecks) {
      const button = missionNav.getByRole('button', { name: new RegExp(item.label) });
      await button.focus();
      await page.keyboard.press('Enter');
      try {
        await page.waitForFunction(target => document.activeElement?.id === target, item.target, { timeout: 1200 });
      } catch { navPassed = false; }
    }
    sectionKeyboardNavigation = navPassed ? 'passed' : 'failed';

    const workflowToggle = page.getByRole('button', { name: 'Explore workflow' });
    await workflowToggle.click();
    const workflowMap = page.locator('#expanded-flow');
    await workflowMap.waitFor({ state: 'visible', timeout: 5000 });
    await workflowMap.locator('.mission-flow').waitFor({ state: 'visible', timeout: 10000 });
    const stageSelector = viewport.width < 560 ? '.mission-flow__mobile-item' : '.react-flow__node';
    await page.waitForFunction(selector => document.querySelectorAll(selector).length === 5, stageSelector, { timeout: 5000 });
    if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2)) errors.push('Expanded workflow causes page overflow');
    const detailsClosed = await page.locator('details[open]').count() === 0;
    const workflowScreenshot = detailsClosed;
    if (workflowScreenshot) await page.screenshot({ path: path.join(output, `${viewport.name}-workflow-expanded.png`), fullPage: true });
    await page.getByRole('button', { name: 'Close workflow map' }).click();
    let workflowClosed = true;
    try { await workflowMap.waitFor({ state: 'detached', timeout: 500 }); } catch { workflowClosed = false; }
    if (!workflowScreenshot || !workflowClosed) errors.push('Workflow map toggle or collapsed technical details check failed');

    if (selected) {
      for (const modeName of ['replay', 'live']) {
        const existing = options.find(option => option.label.toLowerCase().includes(` · ${modeName} · `));
        if (!existing) continue;
        await runPicker.selectOption(existing.value);
        const expected = modeName === 'live' ? 'Live agent requested' : 'Deterministic replay';
        await page.locator('.session-info').getByText(expected, { exact: true }).waitFor();
        if (modeName === 'replay') replayControls = await page.getByTestId('action-attack').isVisible().then(value => value ? 'passed' : 'failed');
        else liveControls = await page.getByTestId('action-attack').count() === 0 && await page.getByTestId('action-alternate-route').count() === 0 ? 'passed' : 'failed';
      }
      await runPicker.selectOption(selected);
      await page.waitForFunction(value => document.querySelector('select[aria-label="Select run"]')?.value === value, selected);

      const resetButton = page.getByTestId('reset-run');
      await resetButton.scrollIntoViewIfNeeded();
      await resetButton.click();
      const dialog = page.getByTestId('confirmation-dialog');
      await dialog.waitFor({ timeout: 5000 });
      const resetCopy = await dialog.innerText();
      await page.screenshot({ path: path.join(output, `${viewport.name}-reset-confirmation.png`) });
      const explainsPreservation = resetCopy.includes('original run record and ledger remain available in run history');
      const cancelButton = page.getByTestId('cancel-confirmation');
      const confirmButton = dialog.getByRole('button').last();
      await page.waitForFunction(() => document.activeElement?.getAttribute('data-testid') === 'cancel-confirmation', null, { timeout: 500 });
      const initialDialogFocus = await cancelButton.evaluate(button => document.activeElement === button);
      await page.keyboard.press('Shift+Tab');
      const reverseTrap = await confirmButton.evaluate(button => document.activeElement === button);
      await page.keyboard.press('Tab');
      const forwardTrap = await cancelButton.evaluate(button => document.activeElement === button);
      await page.keyboard.press('Escape');
      let closedOnEscape = true;
      try { await dialog.waitFor({ state: 'detached', timeout: 500 }); } catch { closedOnEscape = false; }
      await page.waitForFunction(() => document.activeElement?.getAttribute('data-testid') === 'reset-run', null, { timeout: 500 }).catch(() => {});
      const returnedFocus = await resetButton.evaluate(button => document.activeElement === button);
      resetDialog = explainsPreservation && initialDialogFocus && reverseTrap && forwardTrap && closedOnEscape && returnedFocus ? 'passed' : 'failed';
      await resetButton.click();
      await page.getByTestId('cancel-confirmation').click();
      let closedOnCancel = true;
      try { await dialog.waitFor({ state: 'detached', timeout: 500 }); } catch { closedOnCancel = false; }
      await page.waitForFunction(() => document.activeElement?.getAttribute('data-testid') === 'reset-run', null, { timeout: 500 }).catch(() => {});
      const cancelReturnedFocus = await resetButton.evaluate(button => document.activeElement === button);
      if (!closedOnCancel || !cancelReturnedFocus) resetDialog = 'failed';
    }

    await page.emulateMedia({ reducedMotion: 'reduce' });
    const reducedStyles = await page.evaluate(() => {
      const cueMotion = document.querySelector('.presenter-guidance__message > div');
      const cueStyle = cueMotion ? getComputedStyle(cueMotion) : null;
      const zeroDuration = (value = '') => value.split(',').every(part => Number.parseFloat(part) === 0);
      return {
        preference: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
        scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
        cueTransform: cueStyle?.transform,
        cueTransitionDuration: cueStyle?.transitionDuration,
        cueAnimationDuration: cueStyle?.animationDuration,
        cueMotionReduced: !!cueStyle && cueStyle.transform === 'none' &&
          zeroDuration(cueStyle.transitionDuration) && zeroDuration(cueStyle.animationDuration),
      };
    });
    const reducedNavigation = await assertCueKeyboardNavigation(true);
    reducedMotion = reducedStyles.preference && reducedStyles.scrollBehavior === 'auto' &&
      reducedStyles.cueMotionReduced && reducedNavigation ? 'passed' : 'failed';
    await page.emulateMedia({ reducedMotion: 'no-preference' });

    await page.reload({ waitUntil: 'networkidle' });
    await page.getByLabel('Select run').waitFor({ timeout: 10000 });
    const restored = await page.getByLabel('Select run').inputValue();
    if (selected) {
      await page.waitForFunction(value => document.querySelector('select[aria-label="Select run"]')?.value === value, selected, { timeout: 10000 });
      await page.locator('.session-info').getByText(selectedModeText, { exact: true }).waitFor({ timeout: 10000 });
    }
    const cueAfterReload = await guidanceSnapshot();
    persistence = selected && restored === selected && cueAfterReload.title === cueBeforeReload.title &&
      cueAfterReload.savedState === cueBeforeReload.savedState
      ? 'passed' : selected ? `failed (selected ${selected}, restored ${restored}; cue title/state changed)` : 'not tested (no persisted runs available)';
    await page.screenshot({ path: path.join(output, `${viewport.name}-authenticated-full.png`), fullPage: true });

    const runsPattern = `${origin}/api/runs**`;
    await page.route(runsPattern, route => route.request().method() === 'GET'
      ? route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: 'TEST FIXTURE: simulated temporary service outage for connection-state UX.' }) })
      : route.continue());
    try {
      await page.waitForFunction(() => document.querySelector('[data-testid="connection-status"]')?.textContent?.includes('Offline'), null, { timeout: 15000 });
      await page.unroute(runsPattern);
      await page.waitForFunction(() => document.querySelector('[data-testid="connection-status"]')?.textContent?.includes('Connected'), null, { timeout: 10000 });
      offlineRecovery = 'passed (labelled 503 test fixture; no run result was mocked)';
    } catch {
      await page.unroute(runsPattern);
      offlineRecovery = 'failed (503 test fixture did not show offline then reconnect)';
    }
  }

  const result = {
    viewport, baseURL, loginVisible, authenticated, initialOverflow, authenticatedOverflow, responsivePresentation,
    newRunModeSelector, resumedReplayEvidence, guidanceCue, guidanceKeyboardNavigation, persistence,
    replayControls, liveControls, sectionKeyboardNavigation, resetDialog,
    offlineRecovery, reducedMotion, externalFontRequests, unexpectedMutations, pageErrors: errors,
    note: 'Offline uses an explicitly labelled 503 test fixture. Existing run data only; technical event details remain closed; no run/action/reset/repair commands are submitted.',
  };
  console.log(JSON.stringify(result));
  if (initialOverflow || authenticatedOverflow === 'failed' || responsivePresentation === 'failed' || (!loginVisible && !authenticated) || newRunModeSelector === 'failed' || resumedReplayEvidence.startsWith('failed') || guidanceCue.startsWith('failed') || guidanceKeyboardNavigation.startsWith('failed') || persistence.startsWith('failed') || replayControls.startsWith('failed') || liveControls.startsWith('failed') || sectionKeyboardNavigation.startsWith('failed') || resetDialog.startsWith('failed') || offlineRecovery.startsWith('failed') || reducedMotion.startsWith('failed') || externalFontRequests.length || unexpectedMutations.length || errors.length) failures++;
  await context.close();
}
await browser.close();
if (failures) process.exitCode = 1;
