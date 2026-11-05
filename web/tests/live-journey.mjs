// Explicit live PostgreSQL acceptance. Never loaded by fixture Playwright tests.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

export const MAX_INPUT = 1024;
const PASSWORD = 'DemoMaintenance!2026';
const NEW_PASSWORD = 'Synthetic-Replacement!2026';
const CANARIES = ['PRIVATE_LIVE_REPORTER', 'PRIVATE_LIVE_SITE', 'PRIVATE_LIVE_NARRATIVE'];
export const GATES = ['real_login', 'private_submission', 'real_worker', 'exact_review', 'approved_projection', 'private_denial', 'client_reconnect', 'return_correction', 'rejection_private', 'report_filters_pagination', 'feed_filters_pagination', 'account_create_reset', 'account_scope_sessions', 'password_sessions', 'recipient_revocation'];
const STAGES = new Set(['INPUT', 'BROWSER', 'LOGIN', 'PRIVATE_SUBMISSION', 'WORKER_REVIEW', 'PUBLICATION', 'PERSISTENCE', 'CORRECTION', 'REJECTION', 'PAGINATION', 'ADMINISTRATION', 'PASSWORD', 'REVOCATION', 'COMPLETE']);

export function validateInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'channel_id,url') throw new Error('INPUT');
  if (typeof value.url !== 'string' || typeof value.channel_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.channel_id)) throw new Error('INPUT');
  const url = new URL(value.url);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || Number(url.port) < 1024 || Number(url.port) > 65535 || url.username || url.password || url.pathname !== '/' || url.search || url.hash || value.url !== url.origin) throw new Error('INPUT');
  return { url: url.origin, channel_id: value.channel_id };
}

export function safeFailure(stage) {
  return { ok: false, stage: STAGES.has(stage) ? stage : 'INPUT' };
}

export function assertRecipientIdentity(value, channelId) {
  assert.equal(value?.user?.role, 'recipient');
  assert.equal(value?.user?.channel?.id, channelId);
}

export function assertRecipientBody(value) {
  const text = JSON.stringify(value);
  for (const canary of CANARIES) assert.ok(!text.includes(canary));
  for (const field of ['payload_ciphertext', 'reporter_label', 'site_label', 'narrative', 'report_id', 'revision_id', 'variant_id', 'candidate_hash', 'policy_hash', 'content_digest', 'source_digest', 'author_id', 'submitted_by_id']) assert.ok(!text.includes(`"${field}"`));
}

async function input() {
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > MAX_INPUT) throw new Error('INPUT');
    chunks.push(chunk);
  }
  return validateInput(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}

export async function journey(config) {
  let stage = 'BROWSER', browser;
  const contexts = [], pendingScans = [], scanFailures = [];
  let scannedResponses = 0;
  try {
    const { chromium } = await import('playwright');
    const { expect } = await import('@playwright/test');
    browser = await chromium.launch({ headless: true, timeout: 15000 });
    const newPage = async (recipient = false) => {
      const context = await browser.newContext({ viewport: { width: 1360, height: 900 }, serviceWorkers: 'block' });
      contexts.push(context);
      const page = await context.newPage();
      page.setDefaultTimeout(10000);
      if (recipient) page.on('response', response => {
        if (response.url().startsWith(config.url + '/api/v1/')) {
          const scan = response.json().then(body => { assertRecipientBody(body); scannedResponses++; }).catch(() => { scanFailures.push(true); });
          pendingScans.push(scan);
        }
      });
      await page.goto(config.url + '/workspace', { waitUntil: 'domcontentloaded' });
      return page;
    };
    const login = async (page, username, password = PASSWORD) => {
      await page.getByLabel('Username', { exact: true }).fill(username);
      await page.getByLabel('Password', { exact: true }).fill(password);
      await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
      await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
    };
    // Optional query values pin the wait to the filtered request, so a slower earlier
    // unfiltered list load answering late cannot be mistaken for it.
    const waitResponse = (page, suffix, method = 'GET', params = {}) => page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.pathname.endsWith(suffix) && response.request().method() === method
        && Object.entries(params).every(([key, value]) => url.searchParams.get(key) === value);
    });
    const checkedGet = async (page, suffix, status = 200) => {
      const response = await page.context().request.get(config.url + '/api/v1' + suffix);
      assert.equal(response.status(), status);
      return response.json();
    };
    stage = 'LOGIN';
    const recipient = await newPage(true); await login(recipient, 'recipient');
    // Match the fresh disposable fixture before creating reports or changing
    // accounts. Another local demonstration server has a different channel ID.
    assertRecipientIdentity(await checkedGet(recipient, '/me/'), config.channel_id);
    await expect(recipient.getByRole('heading', { name: 'No approved reports available', exact: true })).toBeVisible();
    const submitter = await newPage(); await login(submitter, 'submitter');
    const oldSession = await newPage(); await login(oldSession, 'submitter');
    const reviewer = await newPage(); await login(reviewer, 'reviewer');
    const administrator = await newPage(); await login(administrator, 'administrator');

    // Every additional source and decision uses the real browser UI. The Python
    // owner has independently pinned this server to its disposable database.
    const submitAdditional = async category => {
      await submitter.getByRole('button', { name: 'New report', exact: true }).first().click();
      const another = submitter.getByRole('button', { name: 'Make another report', exact: true });
      if (await another.isVisible()) await another.click();
      await submitter.getByLabel('Reporter label').fill(CANARIES[0]);
      await submitter.getByLabel('Site label').fill(CANARIES[1]);
      await submitter.getByLabel('Describe the issue').fill(CANARIES[2] + '. Synthetic maintenance follow-up.');
      await submitter.getByLabel('Category', { exact: true }).selectOption(category);
      const response = waitResponse(submitter, '/sync/operations/', 'POST');
      await submitter.getByRole('button', { name: 'Submit report', exact: true }).click();
      const accepted = await response; assert.equal(accepted.status(), 201);
      const receipt = await accepted.json(); assert.equal(receipt.shared, false);
      await expect(submitter.getByRole('heading', { name: 'Your report was received.', exact: true })).toBeVisible();
      return { receipt, source: await checkedGet(submitter, `/reports/${receipt.report_id}/revisions/1/`) };
    };
    const openAdditionalReview = async source => {
      const back = reviewer.getByRole('button', { name: 'Back to review queue', exact: true });
      if (await back.isVisible()) await back.click();
      await reviewer.getByRole('button', { name: 'Review queue', exact: true }).first().click();
      await expect(async () => {
        await reviewer.getByRole('button', { name: 'Refresh queue', exact: true }).click();
        await expect(reviewer.getByRole('button', { name: `Review ${source.report.reference}`, exact: true })).toBeVisible({ timeout: 1000 });
      }).toPass({ timeout: 20000, intervals: [200, 500, 1000] });
      const pending = reviewer.waitForResponse(response => /\/variants\/[^/]+\/review\/$/.test(new URL(response.url()).pathname));
      await reviewer.getByRole('button', { name: `Review ${source.report.reference}`, exact: true }).click();
      const response = await pending; assert.equal(response.status(), 200);
      const review = await response.json(); assertRecipientBody(review.candidate);
      await expect(reviewer.getByRole('heading', { name: 'Original report', exact: true })).toBeVisible();
      return review;
    };
    const decideAdditional = async (review, action) => {
      const opening = { APPROVE: 'Review & approve', RETURN: 'Return for correction', REJECT: 'Reject' };
      const commit = { APPROVE: 'Approve & share', RETURN: 'Return report', REJECT: 'Reject report' };
      await reviewer.getByRole('button', { name: opening[action], exact: true }).click();
      await expect(reviewer.getByRole('button', { name: commit[action], exact: true })).toBeDisabled();
      if (action === 'APPROVE') await reviewer.getByRole('checkbox', { name: 'I have checked the complete candidate, source revision, policy and sharing audience.' }).check();
      else await reviewer.getByLabel('Private reason').fill('Synthetic maintenance acceptance feedback.');
      const pending = reviewer.waitForResponse(response => /\/variants\/[^/]+\/decisions\/$/.test(new URL(response.url()).pathname) && response.request().method() === 'POST');
      await reviewer.getByRole('button', { name: commit[action], exact: true }).click();
      const response = await pending; assert.equal(response.status(), 200);
      const request = response.request().postDataJSON();
      assert.equal(request.action, action); assert.deepEqual(request.expected, review.binding);
      assert.equal(response.request().headers()['idempotency-key'], request.operation_id);
      const result = await response.json(); assert.equal(result.action, action);
      assert.equal(result.publication_ids.length, action === 'APPROVE' ? 1 : 0);
      await expect(reviewer.getByRole('button', { name: 'Return to queue', exact: true })).toBeVisible();
      return result;
    };

    stage = 'PRIVATE_SUBMISSION';
    await submitter.getByRole('button', { name: 'New report', exact: true }).first().click();
    await submitter.getByLabel('Reporter label').fill(CANARIES[0]);
    await submitter.getByLabel('Site label').fill(CANARIES[1]);
    await submitter.getByLabel('Describe the issue').fill(CANARIES[2] + '. A fictional water pump needs repair.');
    await submitter.getByLabel('Category', { exact: true }).selectOption('WATER_SUPPLY');
    const accepted = waitResponse(submitter, '/sync/operations/', 'POST');
    await submitter.getByRole('button', { name: 'Submit report', exact: true }).click();
    const acceptedResponse = await accepted; assert.equal(acceptedResponse.status(), 201);
    const receipt = await acceptedResponse.json();
    assert.equal(receipt.delivery_status, 'RECEIVED'); assert.equal(receipt.shared, false); assert.equal(receipt.processing_status, 'PENDING');
    await expect(submitter.getByRole('heading', { name: 'Your report was received.', exact: true })).toBeVisible();
    const source = await checkedGet(submitter, `/reports/${receipt.report_id}/revisions/1/`);
    assert.equal(source.payload.narrative.includes(CANARIES[2]), true);
    const before = await checkedGet(recipient, `/channels/${config.channel_id}/feed/`); assert.equal(before.count, 0); assertRecipientBody(before);

    stage = 'WORKER_REVIEW';
    await expect(async () => {
      await reviewer.getByRole('button', { name: 'Refresh queue', exact: true }).click();
      await expect(reviewer.getByRole('button', { name: `Review ${source.report.reference}`, exact: true })).toBeVisible({ timeout: 1000 });
    }).toPass({ timeout: 20000, intervals: [200, 500, 1000] });
    const reviewResponse = reviewer.waitForResponse(response => /\/variants\/[^/]+\/review\/$/.test(new URL(response.url()).pathname));
    await reviewer.getByRole('button', { name: `Review ${source.report.reference}`, exact: true }).click();
    const reviewedResponse = await reviewResponse; assert.equal(reviewedResponse.status(), 200);
    const review = await reviewedResponse.json();
    assert.equal(review.source.narrative.includes(CANARIES[2]), true); assertRecipientBody(review.candidate);
    await expect(reviewer.getByRole('heading', { name: 'Original report', exact: true })).toBeVisible();
    await expect(reviewer.getByRole('heading', { name: 'Reduced candidate', exact: true })).toBeVisible();
    await reviewer.getByRole('button', { name: 'Review & approve', exact: true }).click();
    await expect(reviewer.getByRole('button', { name: 'Approve & share', exact: true })).toBeDisabled();
    await reviewer.getByRole('checkbox', { name: 'I have checked the complete candidate, source revision, policy and sharing audience.' }).check();
    const decisionResponse = reviewer.waitForResponse(response => /\/variants\/[^/]+\/decisions\/$/.test(new URL(response.url()).pathname) && response.request().method() === 'POST');
    await reviewer.getByRole('button', { name: 'Approve & share', exact: true }).click();
    const decided = await decisionResponse; assert.equal(decided.status(), 200);
    const decision = decided.request().postDataJSON();
    assert.deepEqual(decision.expected, review.binding); assert.equal(decided.request().headers()['idempotency-key'], decision.operation_id);
    const outcome = await decided.json(); assert.equal(outcome.action, 'APPROVE'); assert.equal(outcome.publication_ids.length, 1);

    stage = 'PUBLICATION';
    await recipient.getByRole('button', { name: 'Refresh now', exact: true }).click();
    await expect(recipient.getByRole('button', { name: review.candidate.title, exact: true })).toBeVisible();
    await recipient.getByRole('button', { name: 'Read update', exact: true }).click();
    await expect(recipient.getByRole('heading', { name: 'Approved reduced representation', exact: true })).toBeVisible();
    const publication = await checkedGet(recipient, `/publications/${outcome.publication_ids[0]}/`);
    assertRecipientBody(publication); assert.deepEqual(publication.projection, review.candidate);
    for (const suffix of [`/reports/${receipt.report_id}/revisions/1/`, new URL(reviewedResponse.url()).pathname.slice('/api/v1'.length)]) {
      const denied = await recipient.context().request.get(config.url + '/api/v1' + suffix);
      assert.ok([403, 404].includes(denied.status())); assertRecipientBody(await denied.json());
    }

    stage = 'PERSISTENCE';
    await recipient.reload();
    await expect(recipient.getByRole('button', { name: review.candidate.title, exact: true })).toBeVisible();
    const reconnect = await newPage(true); await login(reconnect, 'recipient');
    await expect(reconnect.getByRole('button', { name: review.candidate.title, exact: true })).toBeVisible();
    const receiptAfter = await checkedGet(submitter, `/sync/receipts/${receipt.operation_id}/`); assert.deepEqual(receiptAfter, receipt);

    stage = 'CORRECTION';
    const returned = await submitAdditional('INFRASTRUCTURE');
    const returnedReview = await openAdditionalReview(returned.source);
    await decideAdditional(returnedReview, 'RETURN');
    const returnedSource = await checkedGet(submitter, `/reports/${returned.receipt.report_id}/revisions/1/`);
    assert.equal(returnedSource.can_correct, true); assert.equal(returnedSource.workflow.sharing.state, 'NOT_SHARED');
    assert.equal((await checkedGet(recipient, `/channels/${config.channel_id}/feed/`)).count, 1);
    await submitter.getByRole('button', { name: 'Your reports', exact: true }).first().click();
    await submitter.getByRole('combobox', { name: 'Report status', exact: true }).selectOption('RETURNED');
    const returnedList = waitResponse(submitter, '/reports/', 'GET', { status: 'RETURNED', page: '1' });
    await submitter.getByRole('button', { name: 'Apply filters', exact: true }).click();
    assert.equal((await (await returnedList).json()).count, 1);
    await submitter.getByRole('button', { name: `Open ${returned.source.report.reference}`, exact: true }).click();
    await submitter.getByRole('button', { name: 'Correct this report', exact: true }).click();
    await expect(submitter.getByLabel('Describe the issue')).toHaveValue(returned.source.payload.narrative);
    const correctedNarrative = CANARIES[2] + '. Corrected synthetic maintenance description.';
    await submitter.getByLabel('Describe the issue').fill(correctedNarrative);
    const correctionReason = 'Clarified the fictional repair description after the originating reviewer returned it.';
    await submitter.getByLabel('Private correction reason').fill(correctionReason);
    const correctionPending = waitResponse(submitter, '/sync/operations/', 'POST');
    await submitter.getByRole('button', { name: 'Submit correction', exact: true }).click();
    const correctionResponse = await correctionPending; assert.equal(correctionResponse.status(), 201);
    const correctionBody = correctionResponse.request().postDataJSON();
    assert.equal(correctionBody.correction_reason, correctionReason);
    assert.equal(correctionBody.expected_revision, 1);
    const correctedReceipt = await correctionResponse.json();
    assert.equal(correctedReceipt.report_id, returned.receipt.report_id); assert.equal(correctedReceipt.revision_no, 2);
    assert.notEqual(correctedReceipt.operation_id, returned.receipt.operation_id); assert.equal(correctedReceipt.shared, false);
    const correctedSource = await checkedGet(submitter, `/reports/${returned.receipt.report_id}/revisions/2/`);
    assert.equal(correctedSource.payload.narrative, correctedNarrative);
    assert.deepEqual((await checkedGet(submitter, `/reports/${returned.receipt.report_id}/revisions/1/`)).payload, returned.source.payload);
    assert.equal((await checkedGet(recipient, `/channels/${config.channel_id}/feed/`)).count, 1);
    await submitter.getByRole('button', { name: 'View current report status', exact: true }).click();
    await expect(submitter.getByText(correctedNarrative, { exact: true })).toBeVisible();
    await submitter.getByRole('button', { name: 'Revision 1', exact: true }).click();
    await expect(submitter.getByText(returned.source.payload.narrative, { exact: true })).toBeVisible();
    await expect(submitter.getByRole('button', { name: 'Correct this report', exact: true })).toHaveCount(0);
    await submitter.getByRole('button', { name: 'Back to reports', exact: true }).click();
    const correctedReview = await openAdditionalReview(correctedSource);
    assert.equal(correctedReview.binding.revision_no, 2);
    assert.notEqual(correctedReview.binding.revision_id, returnedReview.binding.revision_id);
    const correctedDecision = await decideAdditional(correctedReview, 'APPROVE');
    const correctedPublication = await checkedGet(recipient, `/publications/${correctedDecision.publication_ids[0]}/`);
    assertRecipientBody(correctedPublication); assert.deepEqual(correctedPublication.projection, correctedReview.candidate);

    stage = 'REJECTION';
    const rejected = await submitAdditional('EQUIPMENT');
    const rejectedReview = await openAdditionalReview(rejected.source);
    await decideAdditional(rejectedReview, 'REJECT');
    const rejectedSource = await checkedGet(submitter, `/reports/${rejected.receipt.report_id}/revisions/1/`);
    assert.equal(rejectedSource.report.status, 'REJECTED'); assert.equal(rejectedSource.workflow.sharing.state, 'NOT_SHARED');
    assert.equal(rejectedSource.can_correct, false);
    const afterRejection = await checkedGet(recipient, `/channels/${config.channel_id}/feed/`);
    assert.equal(afterRejection.count, 2); assertRecipientBody(afterRejection);

    stage = 'PAGINATION';
    // Eleven actual UI-approved records cross the UI's smallest page size (10).
    // No database backdoor, fabricated publications, or mocked responses.
    for (let index = 0; index < 9; index++) {
      const item = await submitAdditional('EQUIPMENT');
      await decideAdditional(await openAdditionalReview(item.source), 'APPROVE');
    }
    await submitter.getByRole('button', { name: 'Your reports', exact: true }).first().click();
    await submitter.getByRole('combobox', { name: 'Report status', exact: true }).selectOption('ALL');
    const allReports = waitResponse(submitter, '/reports/', 'GET', { status: 'ALL', page: '1' });
    await submitter.getByRole('button', { name: 'Apply filters', exact: true }).click();
    const allReportsResponse = await allReports; assert.equal(allReportsResponse.status(), 200);
    assert.equal((await allReportsResponse.json()).count, 12);
    const secondReports = waitResponse(submitter, '/reports/', 'GET', { page: '2' });
    await submitter.getByRole('button', { name: 'Next page', exact: true }).click();
    const secondReportPage = await (await secondReports).json();
    assert.equal(secondReportPage.page, 2); assert.equal(secondReportPage.results.length, 2);
    assert.ok(secondReportPage.results.some(item => item.id === receipt.report_id));
    await expect(submitter.getByRole('button', { name: `Open ${source.report.reference}`, exact: true })).toBeVisible();
    await submitter.getByRole('combobox', { name: 'Report status', exact: true }).selectOption('REJECTED');
    const createdDate = rejected.source.report.created_at.slice(0, 10);
    await submitter.getByLabel('Created from (UTC)', { exact: true }).fill(createdDate);
    await submitter.getByLabel('Created to (UTC)', { exact: true }).fill(createdDate);
    const filteredReports = waitResponse(submitter, '/reports/', 'GET', { status: 'REJECTED', date_from: createdDate, date_to: createdDate, page: '1' });
    await submitter.getByRole('button', { name: 'Apply filters', exact: true }).click();
    const filteredReportPage = await (await filteredReports).json();
    assert.equal(filteredReportPage.page, 1); assert.equal(filteredReportPage.count, 1);
    assert.equal(filteredReportPage.results[0].id, rejected.receipt.report_id);
    await expect(submitter.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();
    const feedRefresh = waitResponse(recipient, '/feed/');
    await recipient.getByRole('button', { name: 'Refresh now', exact: true }).click();
    const feedPage = await (await feedRefresh).json(); assert.equal(feedPage.count, 11); assertRecipientBody(feedPage);
    const secondFeed = waitResponse(recipient, '/feed/', 'GET', { page: '2' });
    await recipient.getByRole('button', { name: 'Next page', exact: true }).click();
    const secondFeedPage = await (await secondFeed).json();
    assert.equal(secondFeedPage.page, 2); assert.equal(secondFeedPage.results.length, 1);
    assert.equal(secondFeedPage.results[0].id, outcome.publication_ids[0]); assertRecipientBody(secondFeedPage);
    await expect(recipient.getByRole('button', { name: review.candidate.title, exact: true })).toBeVisible();
    await recipient.getByRole('searchbox', { name: 'Search approved publications', exact: true }).fill(review.candidate.title);
    await recipient.getByRole('combobox', { name: 'Filter approved category', exact: true }).selectOption('WATER_SUPPLY');
    await recipient.getByRole('combobox', { name: 'Filter approved urgency', exact: true }).selectOption('ROUTINE');
    const filteredFeed = waitResponse(recipient, '/feed/', 'GET', { q: review.candidate.title.trim(), category: 'WATER_SUPPLY', urgency: 'ROUTINE', page: '1' });
    await recipient.getByRole('button', { name: 'Apply filters', exact: true }).click();
    const filteredFeedPage = await (await filteredFeed).json();
    assert.equal(filteredFeedPage.page, 1); assert.equal(filteredFeedPage.count, 1); assertRecipientBody(filteredFeedPage);
    assert.equal(filteredFeedPage.results[0].id, outcome.publication_ids[0]);
    await expect(recipient.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();

    stage = 'ADMINISTRATION';
    const issuedName = 'browser.fixture', issuedPassword = 'Fictional-Account!2026', resetPassword = 'Fictional-Reset!2026';
    await expect(administrator.getByRole('button', { name: 'Review queue', exact: true })).toHaveCount(0);
    await administrator.getByRole('button', { name: 'Create account', exact: true }).first().click();
    await administrator.getByRole('textbox', { name: /^Username/ }).fill(issuedName);
    await administrator.getByLabel('Display name', { exact: true }).fill('Synthetic Browser Account');
    await administrator.getByRole('combobox', { name: 'Role', exact: true }).selectOption('recipient');
    await administrator.getByRole('combobox', { name: 'Recipient channel', exact: true }).selectOption(config.channel_id);
    await administrator.getByLabel(/^Password/).fill(issuedPassword);
    await administrator.getByLabel('Confirm password', { exact: true }).fill(issuedPassword);
    await administrator.getByRole('button', { name: 'Create account', exact: true }).last().click();
    const createPending = waitResponse(administrator, '/administration/users/', 'POST');
    await administrator.getByRole('button', { name: 'Confirm account creation', exact: true }).click();
    const createdResponse = await createPending; assert.equal(createdResponse.status(), 201);
    const createdAccount = await createdResponse.json(); assert.equal(createdAccount.role, 'recipient');
    await expect(administrator.locator('input[type="password"]')).toHaveCount(0);
    const issued = await newPage(); await login(issued, issuedName, issuedPassword);
    assertRecipientIdentity(await checkedGet(issued, '/me/'), config.channel_id);
    assertRecipientBody(await checkedGet(issued, `/channels/${config.channel_id}/feed/`));
    await administrator.getByLabel('Search accounts', { exact: true }).fill(issuedName);
    const searchPending = waitResponse(administrator, '/administration/users/', 'GET', { q: issuedName, page: '1' });
    await administrator.getByRole('button', { name: 'Apply filters', exact: true }).click();
    assert.equal((await (await searchPending).json()).count, 1);
    await administrator.getByRole('button', { name: `Reset password for ${issuedName}`, exact: true }).click();
    await administrator.getByLabel(/^Password/).fill(resetPassword);
    await administrator.getByLabel('Confirm password', { exact: true }).fill(resetPassword);
    await administrator.getByRole('button', { name: 'Review password reset', exact: true }).click();
    const resetPending = waitResponse(administrator, `/administration/users/${createdAccount.id}/password/`, 'POST');
    await administrator.getByRole('button', { name: 'Reset password', exact: true }).click();
    assert.equal((await resetPending).status(), 200);
    const resetExpired = await issued.context().request.get(config.url + '/api/v1/me/');
    assert.ok([401, 403].includes(resetExpired.status()));
    await issued.reload();
    await issued.getByLabel('Username', { exact: true }).fill(issuedName);
    await issued.getByLabel('Password', { exact: true }).fill(issuedPassword);
    const previousPassword = waitResponse(issued, '/auth/login/', 'POST');
    await issued.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
    assert.ok([400, 401, 403].includes((await previousPassword).status()));
    await expect(issued.getByLabel('Password', { exact: true })).toHaveValue('');
    await login(issued, issuedName, resetPassword);
    const adminContext = await checkedGet(administrator, '/administration/context/');
    const sourceUnit = adminContext.units.find(unit => unit.code === 'SIM-UNIT-01'); assert.ok(sourceUnit?.active);
    await administrator.getByRole('button', { name: `Manage ${issuedName}`, exact: true }).click();
    await administrator.getByRole('combobox', { name: 'Role', exact: true }).selectOption('submitter');
    await administrator.getByRole('combobox', { name: 'Source unit', exact: true }).selectOption(sourceUnit.id);
    await administrator.getByRole('button', { name: 'Review changes', exact: true }).click();
    const scopePending = waitResponse(administrator, `/administration/users/${createdAccount.id}/`, 'PATCH');
    await administrator.getByRole('button', { name: 'Save account changes', exact: true }).click();
    const scopeResponse = await scopePending; assert.equal(scopeResponse.status(), 200);
    const scopedAccount = await scopeResponse.json(); assert.equal(scopedAccount.role, 'submitter'); assert.equal(scopedAccount.unit_id, sourceUnit.id);
    const scopeExpired = await issued.context().request.get(config.url + '/api/v1/me/'); assert.ok([401, 403].includes(scopeExpired.status()));
    await issued.reload(); await login(issued, issuedName, resetPassword);
    assert.equal((await checkedGet(issued, '/me/')).user.role, 'submitter');
    await expect(issued.getByRole('button', { name: 'New report', exact: true }).first()).toBeVisible();
    const noRecipientGrant = await issued.context().request.get(config.url + `/api/v1/channels/${config.channel_id}/feed/`);
    assert.ok([403, 404].includes(noRecipientGrant.status())); assertRecipientBody(await noRecipientGrant.json());
    await expect(issued.getByRole('button', { name: 'Review queue', exact: true })).toHaveCount(0);
    assert.deepEqual(await administrator.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
    await administrator.getByLabel('Search accounts', { exact: true }).fill('');
    const clearSearch = waitResponse(administrator, '/administration/users/');
    await administrator.getByRole('button', { name: 'Apply filters', exact: true }).click();
    assert.equal((await clearSearch).status(), 200);

    stage = 'PASSWORD';
    await submitter.getByRole('button', { name: 'Account security', exact: true }).click();
    await submitter.getByLabel(/^Current password/).fill(PASSWORD);
    await submitter.getByLabel(/^New password/).fill(NEW_PASSWORD);
    await submitter.getByLabel(/^Confirm new password/).fill(NEW_PASSWORD);
    await submitter.getByRole('button', { name: 'Review password change', exact: true }).click();
    await submitter.getByRole('button', { name: 'Change password', exact: true }).click();
    await expect(submitter.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
    const expired = await oldSession.context().request.get(config.url + '/api/v1/me/'); assert.ok([401, 403].includes(expired.status()));
    await submitter.getByLabel('Username', { exact: true }).fill('submitter');
    await submitter.getByLabel('Password', { exact: true }).fill(PASSWORD);
    const oldLogin = waitResponse(submitter, '/auth/login/', 'POST');
    await submitter.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
    assert.ok([400, 401, 403].includes((await oldLogin).status()));
    await expect(submitter.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeEnabled();
    await expect(submitter.getByLabel('Password', { exact: true })).toHaveValue('');
    await login(submitter, 'submitter', NEW_PASSWORD);
    assert.equal((await checkedGet(submitter, `/reports/${receipt.report_id}/revisions/1/`)).workflow.sharing.state, 'AVAILABLE');

    stage = 'REVOCATION';
    await administrator.getByRole('button', { name: 'Manage recipient', exact: true }).click();
    await administrator.getByRole('checkbox', { name: /Account active/ }).uncheck();
    await administrator.getByRole('button', { name: 'Review changes', exact: true }).click();
    const revokeResponse = administrator.waitForResponse(response => /\/administration\/users\/[^/]+\/$/.test(new URL(response.url()).pathname) && response.request().method() === 'PATCH');
    await administrator.getByRole('button', { name: 'Save account changes', exact: true }).click();
    assert.equal((await revokeResponse).status(), 200);
    await recipient.getByRole('button', { name: 'Refresh now', exact: true }).click();
    await expect(recipient.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
    await expect(recipient.getByRole('button', { name: review.candidate.title, exact: true })).toHaveCount(0);
    const revoked = await reconnect.context().request.get(config.url + `/api/v1/publications/${outcome.publication_ids[0]}/`);
    assert.ok([401, 403].includes(revoked.status())); assertRecipientBody(await revoked.json());
    await Promise.all(pendingScans); assert.equal(scanFailures.length, 0); assert.ok(scannedResponses >= 5);
    stage = 'COMPLETE';
    return { ok: true, stage, scanned_responses: scannedResponses, gates: GATES };
  } catch {
    return safeFailure(stage);
  } finally {
    for (const context of contexts) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let result;
  try {
    if (process.argv.length !== 2) throw new Error('INPUT');
    result = await journey(await input());
  } catch { result = safeFailure('INPUT'); }
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exitCode = result.ok ? 0 : 1;
}
