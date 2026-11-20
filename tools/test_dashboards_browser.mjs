// Splunk Dashboards (Constellation): the Capabilities card, the chat plan card, Create, receipts, and the
// report viewer, against a fake Splunk MCP server that can offer or hide the Constellation tools.
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

import { buildOperatorFixtureBlueprint, OPERATOR_FIXTURE_CREATED_AT, OPERATOR_FIXTURE_TIMESTAMP } from './browser_fixtures.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const srcDir = path.join(repoRoot, 'src');

const SPLUNK_USER = 'analyst.contoso';
const MCP_TOKEN = 'contoso-fixture-token';
const REPORT_NAME = `v2_operator_runbook_${OPERATOR_FIXTURE_TIMESTAMP}.md`;
const REQUEST_ID_RE = /^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$/;

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

async function pathExists(targetPath) {
    try {
        await access(targetPath);
        return true;
    } catch {
        return false;
    }
}

async function resolvePythonCommand() {
    const candidates = [
        process.env.DASHBOARDS_TEST_PYTHON,
        process.env.FRONTEND_BUILD_PYTHON,
        process.platform === 'win32'
            ? path.join(repoRoot, '.venv', 'Scripts', 'python.exe')
            : path.join(repoRoot, '.venv', 'bin', 'python'),
        'python',
    ].filter(Boolean);
    for (const candidate of candidates) {
        if (candidate === 'python' || await pathExists(candidate)) {
            return candidate;
        }
    }
    return 'python';
}

function findFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const address = server.address();
            if (!address || typeof address === 'string') {
                server.close(() => reject(new Error('Failed to allocate a local TCP port.')));
                return;
            }
            const { port } = address;
            server.close((closeError) => (closeError ? reject(closeError) : resolve(port)));
        });
    });
}

function startServer(pythonCommand, port, cwd) {
    const logs = [];
    const child = spawn(
        pythonCommand,
        ['-m', 'uvicorn', 'web_app:app', '--app-dir', srcDir, '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'],
        {
            cwd,
            env: { ...process.env, PYTHONUTF8: process.env.PYTHONUTF8 || '1' },
            stdio: ['ignore', 'pipe', 'pipe'],
        },
    );
    child.stdout.on('data', (chunk) => logs.push(chunk.toString()));
    child.stderr.on('data', (chunk) => logs.push(chunk.toString()));
    return { child, getLogs: () => logs.join('').trim() };
}

async function stopServer(serverHandle) {
    if (!serverHandle?.child || serverHandle.child.exitCode !== null) {
        return;
    }
    const { child } = serverHandle;
    await new Promise((resolve) => {
        child.once('exit', () => resolve());
        if (process.platform === 'win32') {
            const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { stdio: 'ignore' });
            killer.once('exit', () => resolve());
            killer.once('error', () => {
                child.kill();
                resolve();
            });
            return;
        }
        child.kill('SIGTERM');
        setTimeout(() => {
            if (child.exitCode === null) {
                child.kill('SIGKILL');
            }
        }, 2000).unref();
    });
}

async function removeTempDir(targetPath, attempts = 6) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        try {
            await rm(targetPath, { recursive: true, force: true });
            return;
        } catch (error) {
            const retry = ['EBUSY', 'EPERM', 'ENOTEMPTY'].includes(error?.code);
            if (!retry || attempt === attempts - 1) {
                throw error;
            }
            await delay(250 * (attempt + 1));
        }
    }
}

async function waitForServer(baseUrl, timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs;
    let lastError = null;
    while (Date.now() < deadline) {
        try {
            const response = await fetch(baseUrl, { redirect: 'manual' });
            if (response.ok) {
                return;
            }
            lastError = new Error(`Unexpected HTTP ${response.status}`);
        } catch (error) {
            lastError = error;
        }
        await delay(400);
    }
    throw new Error(`Timed out waiting for ${baseUrl}: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}

// A Splunk MCP Server stand-in. The Constellation tools are listed only once `offerConstellation` is set.
function startFakeSplunkMcp(port) {
    const webBase = `https://127.0.0.1:${port}`;
    const state = { offerConstellation: false, calls: [], authorizations: new Set(), requests: {} };
    const schema = (names) => ({
        type: 'object',
        properties: Object.fromEntries(names.map((name) => [name, name === 'schema_version' ? { type: 'string', enum: ['1'] } : { type: 'string' }])),
        required: names,
    });
    const listTools = () => {
        const tools = ['splunk_run_query', 'splunk_get_info', 'splunk_get_indexes', 'splunk_get_user_info']
            .map((name) => ({ name, description: `${name} fixture`, inputSchema: { type: 'object', properties: {} } }));
        if (state.offerConstellation) {
            tools.push({ name: 'constellation_create_dashboard', description: 'Create a dashboard', inputSchema: schema(['schema_version', 'request_id', 'expected_user', 'brief_json']) });
            tools.push({ name: 'constellation_get_creation_status', description: 'Creation status', inputSchema: schema(['schema_version', 'request_id', 'expected_user']) });
        }
        return tools;
    };
    // Splunk MCP Server wraps REST replies as {"results": [reply]} inside a text content item.
    const wrapped = (payload) => ({ content: [{ type: 'text', text: JSON.stringify({ results: [payload] }) }] });
    const server = createServer((request, response) => {
        state.authorizations.add(String(request.headers.authorization || ''));
        let body = '';
        request.on('data', (chunk) => { body += chunk; });
        request.on('end', () => {
            let message = {};
            try {
                message = JSON.parse(body || '{}');
            } catch {
                message = {};
            }
            const reply = (result) => {
                response.writeHead(200, { 'Content-Type': 'application/json' });
                response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id ?? 1, result }));
            };
            if (message.method === 'tools/list') {
                reply({ tools: listTools() });
                return;
            }
            if (message.method !== 'tools/call') {
                reply({});
                return;
            }
            const name = message.params?.name;
            const args = message.params?.arguments || {};
            state.calls.push({ name, args });
            if (name === 'splunk_get_user_info') {
                reply(wrapped({ username: SPLUNK_USER, roles: ['user'] }));
                return;
            }
            if (name === 'constellation_create_dashboard') {
                const brief = JSON.parse(args.brief_json || '{}');
                state.requests[args.request_id] = { brief, statusCalls: 0 };
                reply(wrapped({ schema_version: '1', request_id: args.request_id, status: 'running', stage: 'authoring', poll_after_ms: 500 }));
                return;
            }
            if (name === 'constellation_get_creation_status') {
                const record = state.requests[args.request_id];
                if (!record) {
                    reply(wrapped({ schema_version: '1', request_id: args.request_id, status: 'not_found', warnings: [] }));
                    return;
                }
                record.statusCalls += 1;
                if (record.statusCalls < 2) {
                    reply(wrapped({ schema_version: '1', request_id: args.request_id, status: 'running', stage: 'validating', poll_after_ms: 500 }));
                    return;
                }
                reply(wrapped({
                    schema_version: '1',
                    request_id: args.request_id,
                    status: 'created',
                    title: record.brief.title,
                    message: 'Saved as a private dashboard.',
                    dashboard_id: 'contoso_web_errors',
                    draft_id: 'draft_contoso_1',
                    view_url: `${webBase}/en-US/app/constellation/contoso_web_errors`,
                    edit_url: `${webBase}/en-US/app/constellation/workspace?draft=draft_contoso_1`,
                    warnings: [],
                }));
                return;
            }
            reply({ content: [{ type: 'text', text: JSON.stringify({ results: [] }) }] });
        });
    });
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => resolve({ server, state, webBase }));
    });
}

async function seedOutput(outputDir) {
    await mkdir(outputDir, { recursive: true });
    const blueprint = buildOperatorFixtureBlueprint(OPERATOR_FIXTURE_TIMESTAMP, OPERATOR_FIXTURE_CREATED_AT);
    const reports = {
        [`v2_intelligence_blueprint_${OPERATOR_FIXTURE_TIMESTAMP}.json`]: JSON.stringify(blueprint, null, 2),
        [REPORT_NAME]: '# Operator Runbook\n\n## Action Queue\n1. Validate authentication monitoring coverage (high)\n2. Track failed logins on the contoso web tier.\n',
    };
    for (const [name, content] of Object.entries(reports)) {
        await writeFile(path.join(outputDir, name), content, 'utf8');
    }
    await writeFile(path.join(outputDir, 'discovery_sessions.json'), JSON.stringify([{
        timestamp: OPERATOR_FIXTURE_TIMESTAMP,
        created_at: OPERATOR_FIXTURE_CREATED_AT,
        overview: blueprint.overview,
        report_paths: Object.keys(reports),
        readiness_score: blueprint.readiness_score,
        stats: { discovery_steps: 3, classification_groups: 1, recommendation_count: 1, suggested_use_case_count: 1 },
    }], null, 2), 'utf8');
}

async function requestJson(baseUrl, route, options = {}) {
    const response = await fetch(new URL(route, baseUrl), {
        method: options.method || 'GET',
        headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
        body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await response.json().catch(() => ({}));
    return { status: response.status, data };
}

async function dismissSplash(page) {
    const splash = page.locator('[data-testid="welcome-splash-modal"]');
    await splash.waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
    if (await splash.isVisible().catch(() => false)) {
        await splash.getByRole('button', { name: 'Get Started' }).click();
        await splash.waitFor({ state: 'hidden', timeout: 15000 });
    }
}

async function openCapabilities(page) {
    await page.locator('#workspace-tab-capabilities').click({ force: true });
    const card = page.locator('[data-testid="capability-card"][data-capability="splunk_dashboards"]');
    await card.waitFor({ state: 'visible', timeout: 30000 });
    return card;
}

async function waitForSupport(card, expected, timeoutMs = 20000) {
    const chip = card.getByTestId('dashboard-support-state');
    const deadline = Date.now() + timeoutMs;
    let current = '';
    while (Date.now() < deadline) {
        current = await chip.getAttribute('data-state').catch(() => '');
        if (current === expected) {
            return;
        }
        await delay(250);
    }
    throw new Error(`Expected the dashboard support state ${expected}, got ${current}.`);
}

async function runCapabilityAction(page, card, action) {
    const button = card.locator(`[data-capability-action="${action}"]`);
    await button.waitFor({ state: 'visible', timeout: 10000 });
    await button.click();
    await card.locator(`[data-capability-action="${action}"]`).waitFor({ state: 'detached', timeout: 15000 });
}

// Saves a screenshot of a key step when DASHBOARDS_TEST_SHOTS_DIR is set, for reviewing the cards by eye.
async function snap(page, name, locator = null) {
    const dir = process.env.DASHBOARDS_TEST_SHOTS_DIR;
    if (!dir) {
        return;
    }
    await mkdir(dir, { recursive: true });
    const target = path.join(dir, `${name}.png`);
    if (locator) {
        await locator.screenshot({ path: target }).catch(() => {});
        return;
    }
    await page.screenshot({ path: target, fullPage: true }).catch(() => {});
}

async function setIncognito(page, enabled) {
    await page.getByTestId('header-incognito').click();
    const popover = page.getByTestId('incognito-popover');
    await popover.waitFor({ state: 'visible', timeout: 5000 });
    const toggle = popover.getByTestId('incognito-switch');
    if ((await toggle.getAttribute('aria-checked')) !== String(enabled)) {
        await toggle.click();
        await popover.locator(`[data-testid="incognito-switch"][aria-checked="${enabled}"]`).waitFor({ timeout: 5000 });
    }
    await popover.getByRole('button', { name: 'Close incognito mode details' }).click();
    await popover.waitFor({ state: 'hidden', timeout: 5000 });
}

async function sendChat(page, text) {
    const input = page.getByLabel('Chat message input');
    if (!(await input.isVisible().catch(() => false))) {
        await page.getByRole('button', { name: 'Open chat', exact: true }).click();
        await input.waitFor({ state: 'visible', timeout: 15000 });
    }
    const before = await page.getByTestId('chat-reply-markdown').count();
    await input.fill(text);
    await page.getByRole('button', { name: 'Send chat message' }).click();
    await page.waitForFunction(
        (count) => document.querySelectorAll('[data-testid="chat-reply-markdown"]').length > count,
        before,
        { timeout: 30000 },
    );
    return page.getByTestId('chat-reply-markdown').last();
}

async function main() {
    const pythonCommand = await resolvePythonCommand();
    const appPort = await findFreePort();
    const mcpPort = await findFreePort();
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-dashboards-'));
    const baseUrl = `http://127.0.0.1:${appPort}/`;
    const mcpUrl = `http://127.0.0.1:${mcpPort}/services/mcp`;
    await seedOutput(path.join(tempDir, 'output'));
    const fakeMcp = await startFakeSplunkMcp(mcpPort);
    const serverHandle = startServer(pythonCommand, appPort, tempDir);
    let browser = null;
    let page = null;
    const pageErrors = [];

    try {
        await waitForServer(baseUrl);
        const saved = await requestJson(baseUrl, '/api/config', { method: 'POST', body: { mcp: { url: mcpUrl, token: MCP_TOKEN, verify_ssl: false } } });
        assert(saved.status === 200, `Saving the MCP connection failed with HTTP ${saved.status}: ${JSON.stringify(saved.data)}`);

        const initial = await requestJson(baseUrl, '/api/dashboards/status?refresh=true');
        assert(initial.status === 200, `Dashboard status returned HTTP ${initial.status}.`);
        assert(initial.data.installed === false && initial.data.can_create === false, 'Splunk Dashboards starts not installed.');
        assert(initial.data.support?.state === 'potential', `Without the Constellation tools the connection is a potential one, got ${JSON.stringify(initial.data.support)}.`);

        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
        page = await context.newPage();
        page.on('pageerror', (error) => pageErrors.push(String(error)));
        page.on('dialog', (dialog) => dialog.accept());

        await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
        await dismissSplash(page);

        // Potential capability: the card names what to install in Splunk, with links.
        let card = await openCapabilities(page);
        await waitForSupport(card, 'potential');
        const requirements = card.getByTestId('dashboard-requirements');
        await requirements.waitFor({ state: 'visible', timeout: 10000 });
        const hrefs = await requirements.locator('a').evaluateAll((links) => links.map((link) => link.getAttribute('href')));
        assert(hrefs.includes('https://github.com/LeiterConsulting/constellation/releases') && hrefs.includes('https://splunkbase.splunk.com/app/7931'),
            `The potential card should link to Constellation releases and Splunk MCP Server, got ${hrefs.join(', ')}.`);
        assert((await card.getByTestId('dashboard-support-message').innerText()).includes('does not offer the dashboard tools yet'), 'The card should say the tools are missing.');
        await snap(page, 'capability-potential', card);

        await runCapabilityAction(page, card, 'install');
        await runCapabilityAction(page, card, 'enable');
        await card.locator('[data-capability-action="disable"]').waitFor({ state: 'visible', timeout: 10000 });

        await card.locator('button.ui-link', { hasText: 'Check Again' }).first().click();
        await waitForSupport(card, 'potential');

        // While the tools are missing, a chat request explains what to install instead of drafting a plan.
        let reply = await sendChat(page, 'Create a dashboard of web errors');
        const potentialReply = await reply.innerText();
        assert(potentialReply.includes('does not offer the dashboard tools yet'), `The chat reply should explain the missing tools, got: ${potentialReply}`);
        assert(await reply.locator('a[href="https://github.com/LeiterConsulting/constellation/releases"]').count() === 1, 'The chat reply should link to Constellation releases.');
        assert(await page.getByTestId('chat-dashboard').count() === 0, 'No plan card should appear while the tools are missing.');
        assert(!fakeMcp.state.calls.some((call) => call.name.startsWith('constellation_')), 'Nothing may be sent to Constellation before Create.');
        await page.getByRole('button', { name: 'Close chat' }).first().click();

        // Constellation is installed in Splunk: Check Again finds the tools.
        fakeMcp.state.offerConstellation = true;
        card = await openCapabilities(page);
        await card.locator('button.ui-link', { hasText: 'Check Again' }).first().click();
        await waitForSupport(card, 'available');

        // Admin view: each connection, with the guessed Splunk Web address and a check on what is typed.
        const settings = card.getByTestId('dashboard-connection-settings');
        await settings.locator('summary').click();
        const row = settings.getByTestId('dashboard-connection-row').first();
        await row.waitFor({ state: 'visible', timeout: 15000 });
        assert(await row.getByTestId('dashboard-connection-support').getAttribute('data-state') === 'available', 'The connection row should show the tools were found.');
        const addressInput = row.locator('input[type="url"]');
        assert(await addressInput.getAttribute('placeholder') === fakeMcp.webBase, `The guessed Splunk Web address should be ${fakeMcp.webBase}.`);
        await addressInput.fill('http://splunk.example.com:8000');
        await settings.getByTestId('dashboard-save-web-urls').click();
        await settings.getByTestId('dashboard-web-url-error').getByText('Enter an HTTPS Splunk Web address').waitFor({ timeout: 10000 });
        await snap(page, 'capability-available-settings', card);
        const savedAddress = async () => {
            const listed = await requestJson(baseUrl, '/api/capabilities/splunk_dashboards/connections');
            return listed.data.connections?.[0]?.splunk_web_url;
        };
        assert(await savedAddress() === '', 'A refused address must not be saved.');
        await addressInput.fill('https://splunk.example.com:8000');
        await settings.getByTestId('dashboard-save-web-urls').click();
        await settings.getByTestId('dashboard-web-url-notice').waitFor({ timeout: 10000 });
        assert(await savedAddress() === 'https://splunk.example.com:8000', 'A valid HTTPS address should be saved for the connection.');
        await addressInput.fill('');
        await settings.getByTestId('dashboard-save-web-urls').click();
        await settings.getByTestId('dashboard-web-url-notice').waitFor({ timeout: 10000 });
        assert(await savedAddress() === '', 'Clearing the address should go back to the guessed one.');

        // Chat: the plan card shows the Splunk user, needs an index, and sends nothing until Create.
        reply = await sendChat(page, 'Create a dashboard of web errors');
        assert((await reply.innerText()).includes('Nothing goes to Splunk until you click Create.'), 'The chat reply should introduce the plan.');
        const plan = page.getByTestId('chat-dashboard').last();
        await plan.waitFor({ state: 'visible', timeout: 15000 });
        assert((await plan.getByTestId('chat-dashboard-identity').innerText()).includes(`Splunk user ${SPLUNK_USER}`), 'The plan should name the Splunk user it is created as.');
        assert((await plan.getByTestId('chat-dashboard-title').innerText()) === 'Web errors', 'The starter plan title should come from the request.');
        assert(!fakeMcp.state.calls.some((call) => call.name.startsWith('constellation_')), 'Drafting a plan must not call Constellation.');
        const createButton = plan.getByTestId('chat-dashboard-create');
        if (await plan.getByTestId('chat-dashboard-problems').count()) {
            assert(await createButton.isDisabled(), 'Create should stay disabled while the plan has problems.');
        }
        await plan.getByTestId('chat-dashboard-edit').click();
        const editor = plan.getByTestId('chat-dashboard-editor');
        await editor.getByLabel('Index').fill('contoso_web');
        await editor.getByLabel('Sourcetype (optional)').fill('bad sourcetype');
        await plan.getByTestId('chat-dashboard-problems').getByText('Enter a single sourcetype').waitFor({ timeout: 5000 });
        assert(await createButton.isDisabled(), 'A bad sourcetype should keep Create disabled.');
        await editor.getByLabel('Sourcetype (optional)').fill('access_combined');
        await editor.getByLabel('Time range').selectOption('-7d');
        await editor.getByRole('textbox', { name: 'Panel 1 on page 1', exact: true }).fill('Server errors over time');
        assert(await plan.getByTestId('chat-dashboard-problems').count() === 0, 'A complete plan should have no problems.');
        await snap(page, 'chat-plan-editor', plan);
        await plan.getByTestId('chat-dashboard-edit').click();
        await snap(page, 'chat-plan-summary', plan);
        assert((await plan.getByTestId('chat-dashboard-summary').innerText()).includes('Last 7 days'), 'The summary should show the edited time range.');

        await createButton.click();
        const receipt = page.getByTestId('chat-dashboard-receipt').last();
        await receipt.waitFor({ state: 'visible', timeout: 15000 });
        await page.waitForFunction(
            () => document.querySelector('[data-testid="chat-dashboard-receipt"]')?.getAttribute('data-status') === 'created',
            null,
            { timeout: 30000 },
        );
        assert((await receipt.getByTestId('chat-dashboard-receipt-status').innerText()).includes('Dashboard created'), 'The receipt should say the dashboard was created.');
        await snap(page, 'chat-receipt-created', receipt);
        const openLink = receipt.getByTestId('chat-dashboard-open-dashboard');
        assert(await openLink.getAttribute('href') === `${fakeMcp.webBase}/en-US/app/constellation/contoso_web_errors`, 'Open Dashboard should use the verified view link.');
        assert(await openLink.getAttribute('target') === '_blank' && (await openLink.getAttribute('rel')).includes('noopener'), 'Dashboard links should open in a new tab without an opener.');
        assert(await receipt.getByTestId('chat-dashboard-edit-constellation').getAttribute('href') === `${fakeMcp.webBase}/en-US/app/constellation/workspace?draft=draft_contoso_1`,
            'Edit in Constellation should use the verified draft link.');

        const creates = fakeMcp.state.calls.filter((call) => call.name === 'constellation_create_dashboard');
        assert(creates.length === 1, `Exactly one create call should reach Splunk, got ${creates.length}.`);
        const createArgs = creates[0].args;
        assert(createArgs.schema_version === '1' && createArgs.expected_user === SPLUNK_USER && REQUEST_ID_RE.test(createArgs.request_id),
            `Create arguments do not follow the contract: ${JSON.stringify({ ...createArgs, brief_json: '(omitted)' })}`);
        const sentBrief = JSON.parse(createArgs.brief_json);
        assert(sentBrief.title === 'Web errors' && sentBrief.source?.index === 'contoso_web' && sentBrief.source?.sourcetype === 'access_combined'
            && sentBrief.time_range?.earliest === '-7d' && sentBrief.pages?.[0]?.panels?.[0] === 'Server errors over time',
            `The sent plan should match the edited card: ${createArgs.brief_json}`);
        assert(sentBrief.provenance?.kind === 'conversation', 'A chat plan should say it came from the conversation.');
        const statusCalls = fakeMcp.state.calls.filter((call) => call.name === 'constellation_get_creation_status');
        assert(statusCalls.length >= 2 && statusCalls.every((call) => call.args.expected_user === SPLUNK_USER && call.args.request_id === createArgs.request_id),
            'Status checks should repeat the request ID and Splunk user.');
        assert([...fakeMcp.state.authorizations].every((value) => value === `Bearer ${MCP_TOKEN}`), 'Every MCP call should use the saved connection token.');

        // The card keeps its receipt after a reload.
        await page.reload({ waitUntil: 'domcontentloaded' });
        await dismissSplash(page);
        await page.getByRole('button', { name: 'Open chat', exact: true }).click();
        const restored = page.getByTestId('chat-dashboard-receipt').last();
        await restored.waitFor({ state: 'visible', timeout: 15000 });
        assert(await restored.getAttribute('data-status') === 'created', 'After a reload the card should still show the created dashboard.');
        assert(await restored.getByTestId('chat-dashboard-open-dashboard').count() === 1, 'After a reload Open Dashboard should still be there.');
        await page.getByRole('button', { name: 'Close chat' }).first().click();

        // Capabilities lists the dashboard under recent dashboards.
        card = await openCapabilities(page);
        const recent = card.getByTestId('dashboard-recent');
        await recent.waitFor({ state: 'visible', timeout: 15000 });
        assert((await recent.innerText()).includes('Web errors'), 'Recent dashboards should list the new dashboard.');
        await snap(page, 'capability-recent', card);

        // Report viewer: Create Dashboard drafts a plan from the report, and Cancel sends nothing.
        await page.locator('#workspace-tab-discovery').click({ force: true });
        const reportRow = page.getByTestId('discovery-report-row').filter({ hasText: REPORT_NAME }).first();
        await reportRow.waitFor({ state: 'visible', timeout: 30000 });
        await reportRow.click({ force: true });
        await page.getByTestId('report-create-dashboard').click();
        const reportPlan = page.getByTestId('report-dashboard');
        await reportPlan.waitFor({ state: 'visible', timeout: 30000 });
        assert((await reportPlan.innerText()).includes(`Based on ${REPORT_NAME}`), 'A report plan should say which report it is based on.');
        const reportTitle = await reportPlan.getByTestId('report-dashboard-title').innerText();
        assert(reportTitle === 'Findings from the Operator Runbook report', `The starter plan title should name the report, got ${reportTitle}.`);
        const callsBeforeCancel = fakeMcp.state.calls.filter((call) => call.name.startsWith('constellation_')).length;

        // Incognito mode on: the open plan says why it cannot be created, and the server refuses Create too.
        await setIncognito(page, true);
        await reportPlan.getByTestId('report-dashboard-incognito').waitFor({ state: 'visible', timeout: 5000 });
        assert(await reportPlan.getByTestId('report-dashboard-create').isDisabled(), 'Create should be disabled while incognito mode is on.');
        await snap(page, 'report-plan-incognito', reportPlan);
        const incognitoCreate = await requestJson(baseUrl, '/api/dashboards/create', {
            method: 'POST',
            body: { proposal_id: 'contoso-proposal', binding_key: 'contoso-binding', brief: { title: 'Blocked' } },
        });
        assert(incognitoCreate.status === 409 && String(incognitoCreate.data.detail).includes('incognito mode is on'),
            `Create should be refused while incognito mode is on, got HTTP ${incognitoCreate.status}: ${JSON.stringify(incognitoCreate.data)}.`);
        const incognitoStatus = await requestJson(baseUrl, '/api/dashboards/status');
        assert(incognitoStatus.status === 200 && incognitoStatus.data.can_create === false, 'Status stays readable and reports that creation is blocked.');
        await setIncognito(page, false);
        await reportPlan.getByTestId('report-dashboard-incognito').waitFor({ state: 'detached', timeout: 5000 });
        await reportPlan.getByTestId('report-dashboard-cancel').click();
        await reportPlan.waitFor({ state: 'detached', timeout: 5000 });
        assert(fakeMcp.state.calls.filter((call) => call.name.startsWith('constellation_')).length === callsBeforeCancel, 'Cancel must not send anything to Splunk.');

        // Turned off: chat answers as usual and Create Dashboard leaves the report viewer.
        card = await openCapabilities(page);
        await runCapabilityAction(page, card, 'disable');
        await page.locator('#workspace-tab-discovery').click({ force: true });
        await page.getByTestId('discovery-report-row').filter({ hasText: REPORT_NAME }).first().click({ force: true });
        await page.getByTestId('report-viewer-title').waitFor({ state: 'visible', timeout: 15000 });
        assert(await page.getByTestId('report-create-dashboard').count() === 0, 'Create Dashboard should be hidden while the capability is off.');
        const blocked = await requestJson(baseUrl, '/api/dashboards/propose', { method: 'POST', body: { report_name: REPORT_NAME } });
        assert(blocked.status === 409 && String(blocked.data.detail).includes('turned off'), `Proposing while off should be refused, got HTTP ${blocked.status}.`);

        assert(pageErrors.length === 0, `Page errors: ${pageErrors.join(' | ')}`);
        console.log(`Dashboards browser regression passed: potential card with links, install and enable, chat plan with edits, one create call, ${statusCalls.length} status checks, created receipt with verified links, reload, report plan, incognito block, and turned-off state verified.`);
    } catch (error) {
        if (page && process.env.DASHBOARDS_TEST_SCREENSHOT) {
            await page.screenshot({ path: process.env.DASHBOARDS_TEST_SCREENSHOT, fullPage: true }).catch(() => {});
        }
        const logs = serverHandle.getLogs();
        if (logs) {
            console.error(logs.slice(-4000));
        }
        if (pageErrors.length) {
            console.error(`Page errors: ${pageErrors.join(' | ')}`);
        }
        throw error;
    } finally {
        if (browser) {
            await browser.close();
        }
        await stopServer(serverHandle);
        await new Promise((resolve) => fakeMcp.server.close(() => resolve()));
        await removeTempDir(tempDir);
    }
}

main().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exit(1);
});
