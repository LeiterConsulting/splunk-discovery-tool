import { spawn } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const srcDir = path.join(repoRoot, 'src');

const GOOD_TOKEN = 'troubleshoot-good-token';
const WRONG_TOKEN = 'troubleshoot-wrong-token';

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
        process.env.SETTINGS_PROFILE_TEST_PYTHON,
        process.env.VISUALIZATION_BROWSER_TEST_PYTHON,
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

// Accepts only GOOD_TOKEN, like a Splunk MCP server with token auth.
function startFakeMcpServer(port) {
    const server = createServer((request, response) => {
        request.resume();
        request.on('end', () => {
            if (String(request.headers.authorization || '') !== `Bearer ${GOOD_TOKEN}`) {
                response.writeHead(401, { 'Content-Type': 'application/json' });
                response.end(JSON.stringify({ messages: [{ type: 'ERROR', text: 'Unauthorized' }] }));
                return;
            }
            response.writeHead(200, { 'Content-Type': 'application/json' });
            response.end(JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                result: { tools: [{ name: 'splunk_run_query' }, { name: 'splunk_get_indexes' }] },
            }));
        });
    });
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => resolve(server));
    });
}

// Another copy of the app on a fallback port: 'current' answers the server-status check, 'old' predates it.
function fakeAppCopyHandler(kind) {
    return (request, response) => {
        const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
        const { pathname } = new URL(request.url, 'http://localhost');
        if (pathname === '/api/auth/status') {
            response.writeHead(200, headers);
            response.end(JSON.stringify({ auth_enabled: false, auth_provider: 'local_password', demo_mode: true }));
            return;
        }
        if (pathname === '/api/troubleshoot/server-status' && kind === 'current') {
            response.writeHead(200, headers);
            response.end(JSON.stringify({ stale: false, running_commit: '2a9341d97ddd126c39360927c5fce07d5f817b02' }));
            return;
        }
        response.writeHead(404, headers);
        response.end(JSON.stringify({ detail: 'Not Found' }));
    };
}

// The page looks for other copies on the app's default port and the 20 after it.
async function startFakeAppCopy(kind, firstPort = 8004, lastPort = 8023) {
    for (let port = firstPort; port <= lastPort; port += 1) {
        const server = createServer(fakeAppCopyHandler(kind));
        try {
            await new Promise((resolve, reject) => {
                server.once('error', reject);
                server.listen(port, '127.0.0.1', resolve);
            });
            return { server, port };
        } catch (error) {
            server.close();
            if (!['EADDRINUSE', 'EACCES'].includes(error?.code)) {
                throw error;
            }
        }
    }
    throw new Error(`No free port between ${firstPort} and ${lastPort} for a fake app copy.`);
}
async function openSettings(page) {
    const splash = page.locator('[data-testid="welcome-splash-modal"]');
    await splash.waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
    if (await splash.isVisible().catch(() => false)) {
        await splash.getByRole('button', { name: 'Get Started' }).click();
        await splash.waitFor({ state: 'hidden', timeout: 15000 });
    }
    const statusResponse = page.waitForResponse((response) => response.url().endsWith('/api/troubleshoot/server-status'), { timeout: 30000 });
    await page.getByRole('button', { name: 'Open settings' }).click();
    await page.getByRole('heading', { name: 'Settings' }).waitFor({ timeout: 30000 });
    await statusResponse;
}

async function waitForResults(page) {
    const results = page.getByTestId('troubleshoot-results');
    await results.waitFor({ state: 'visible', timeout: 60000 });
    return results;
}

async function stageStatus(page, stageId) {
    return page.getByTestId(`troubleshoot-stage-${stageId}`).getAttribute('data-status');
}

async function main() {
    const pythonCommand = await resolvePythonCommand();
    const appPort = await findFreePort();
    const mcpPort = await findFreePort();
    const closedPort = await findFreePort();
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-troubleshoot-'));
    const baseUrl = `http://127.0.0.1:${appPort}/`;
    const mcpUrl = `http://127.0.0.1:${mcpPort}/services/mcp`;
    const fakeMcp = await startFakeMcpServer(mcpPort);
    const serverHandle = startServer(pythonCommand, appPort, tempDir);
    let browser = null;
    let page = null;
    const fakeCopies = [];
    const pageErrors = [];
    const dialogs = [];

    try {
        await waitForServer(baseUrl);
        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
        await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: baseUrl });
        page = await context.newPage();
        page.on('pageerror', (error) => pageErrors.push(String(error)));
        page.on('dialog', async (dialog) => {
            dialogs.push(dialog.message());
            await dialog.accept();
        });

        await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
        await openSettings(page);
        assert(await page.getByTestId('settings-tab-troubleshoot').isVisible(), 'Settings should offer a Troubleshoot tab.');
        assert(!(await page.getByTestId('settings-server-stale-banner').isVisible()), 'A freshly started server must not be reported as stale.');

        // A rejected token: the MCP form's Troubleshoot button carries the typed values over and explains the 401.
        await page.getByRole('button', { name: 'Add MCP Server' }).click();
        await page.locator('#mcp-url').fill(mcpUrl);
        await page.locator('#mcp-token').fill(WRONG_TOKEN);
        await page.getByTestId('mcp-troubleshoot').click();
        let results = await waitForResults(page);
        assert(await results.getAttribute('data-status') === 'fail', 'A rejected token should fail the checks.');
        assert(await page.getByTestId('troubleshoot-mcp-url').inputValue() === mcpUrl, 'The troubleshooter should use the URL typed into the form.');
        const summary = await page.getByTestId('troubleshoot-summary').innerText();
        assert(/rejected the token \(HTTP 401\)/.test(summary), `Summary should explain the 401, got: ${summary}`);
        assert(await stageStatus(page, 'network') === 'pass', 'The network stage should pass when the server answers.');
        assert(await stageStatus(page, 'response') === 'fail', 'The response stage should fail on HTTP 401.');
        const reportText = await page.getByTestId('troubleshoot-report-text').textContent();
        assert(reportText.includes('Splunk Discovery Tool troubleshooting report: MCP server'), 'The report text should be shown.');
        assert(!reportText.includes(WRONG_TOKEN), 'The report must not contain the token.');
        await page.getByTestId('troubleshoot-copy-report').click();
        await page.getByTestId('troubleshoot-copy-status').waitFor({ timeout: 5000 });
        const copied = await page.evaluate(() => navigator.clipboard.readText());
        assert(copied.includes('rejected the token') && !copied.includes(WRONG_TOKEN), 'Copy Report should copy the redacted report.');

        // Switching tabs keeps the typed form values and the saved list.
        await page.getByTestId('settings-tab-connections').click();
        assert(await page.locator('#mcp-url').inputValue() === mcpUrl, 'Typed MCP values should survive a tab switch.');
        assert(!(await page.locator('#mcp-configs-list').innerText()).includes('Loading configurations'), 'The saved list should not reset to loading after a tab switch.');

        // The corrected token passes the connection and save checks; nothing is saved.
        await page.getByTestId('settings-tab-troubleshoot').click();
        await page.getByTestId('troubleshoot-mcp-token').fill(GOOD_TOKEN);
        await page.getByTestId('troubleshoot-run').click();
        results = await waitForResults(page);
        assert(await stageStatus(page, 'response') === 'pass', 'A valid token should pass the response stage.');
        assert(await page.getByTestId('troubleshoot-check-test_save').getAttribute('data-status') === 'pass', 'A test save should work in a writable folder.');
        // The test server runs from a temp folder, which the location check rightly flags.
        assert(await page.getByTestId('troubleshoot-check-config_location').getAttribute('data-status') === 'warn', 'Settings outside the install folder should be flagged.');
        assert((await page.getByTestId('troubleshoot-check-tools').innerText()).includes('2 MCP tools'), 'The tool count should be reported.');
        const savedAfterChecks = await (await fetch(new URL('/api/mcp-configs', baseUrl))).json();
        assert(Object.keys(savedAfterChecks).length === 0, 'Troubleshooting must not save anything.');

        // A save that fails with a non-JSON page shows the HTTP status and hands off to the troubleshooter.
        const caBundlePath = path.join(tempDir, 'splunk-ca.pem');
        let saveBody = null;
        await page.route('**/api/mcp-configs', (route) => {
            if (route.request().method() !== 'POST') {
                return route.continue();
            }
            saveBody = route.request().postDataJSON();
            return route.fulfill({ status: 502, contentType: 'text/html', body: '<html><body><h1>502 Bad Gateway</h1></body></html>' });
        });
        await page.getByTestId('settings-tab-connections').click();
        await page.locator('#mcp-ca-bundle').fill(caBundlePath);
        await page.getByRole('button', { name: 'Save as New Configuration' }).click();
        const saveDialog = page.locator('div.fixed.inset-0').filter({ hasText: /Save MCP Configuration/ });
        await saveDialog.waitFor({ state: 'visible', timeout: 10000 });
        await saveDialog.getByPlaceholder('e.g., Production Splunk, Dev Environment').fill('Broken Save');
        const dialogCount = dialogs.length;
        await saveDialog.locator('button', { hasText: /^\s*Save\s+Configuration\s*$/ }).click();
        results = await waitForResults(page);
        const saveMessage = dialogs.slice(dialogCount).join(' | ');
        assert(saveMessage.includes('HTTP 502') && saveMessage.includes('502 Bad Gateway'), `Save failure should show the HTTP status and page text, got: ${saveMessage}`);
        assert(saveMessage.includes('Open Troubleshoot'), 'Save failure should offer the troubleshooter.');
        assert(await page.getByTestId('troubleshoot-name').inputValue() === 'Broken Save', 'The handoff should carry the configuration name.');
        assert(saveBody && saveBody.ca_bundle_path === caBundlePath, `The save request should include the CA bundle path, got: ${JSON.stringify(saveBody && saveBody.ca_bundle_path)}`);
        assert(await page.getByTestId('troubleshoot-mcp-ca-bundle').inputValue() === caBundlePath, 'The handoff should carry the CA bundle path.');
        assert(await saveDialog.count() === 0, 'The save dialog should close when troubleshooting starts.');
        await page.unroute('**/api/mcp-configs');

        // A server older than the page has no troubleshooting endpoints: the banner and the checks say to restart.
        // An up-to-date copy and another old copy run on fallback ports, as after installing again in a new folder.
        const currentCopy = await startFakeAppCopy('current');
        fakeCopies.push(currentCopy.server);
        const oldCopy = await startFakeAppCopy('old', currentCopy.port + 1);
        fakeCopies.push(oldCopy.server);
        const ownTroubleshootRoutes = `${baseUrl}api/troubleshoot/**`;
        await page.route(ownTroubleshootRoutes, (route) => route.fulfill({ status: 404, contentType: 'application/json', body: '{"detail":"Not Found"}' }));
        await page.reload({ waitUntil: 'domcontentloaded' });
        await openSettings(page);
        const staleBanner = page.getByTestId('settings-server-stale-banner');
        await staleBanner.waitFor({ timeout: 10000 });
        const currentCopyLink = page.getByTestId('settings-server-current-copy-link');
        await currentCopyLink.waitFor({ timeout: 10000 });
        const currentCopyOrigin = `http://127.0.0.1:${currentCopy.port}`;
        assert(await currentCopyLink.getAttribute('href') === `${currentCopyOrigin}/`, `The banner should link to the up-to-date copy, got: ${await currentCopyLink.getAttribute('href')}`);
        const bannerText = await staleBanner.innerText();
        assert(bannerText.includes(`port ${appPort} is running an older version`), `The banner should name this server's port, got: ${bannerText}`);
        assert(bannerText.includes('Restarting a copy installed in another folder does not change this one'), 'The banner should explain why restarting a new install does not help.');
        const otherCopiesText = await page.getByTestId('settings-server-other-copies').innerText();
        assert(otherCopiesText.includes(String(oldCopy.port)) && otherCopiesText.includes('older code'), `The banner should list the other old copy, got: ${otherCopiesText}`);
        await page.getByTestId('settings-tab-troubleshoot').click();
        await page.getByTestId('troubleshoot-run').click();
        results = await waitForResults(page);
        const staleSummary = await page.getByTestId('troubleshoot-summary').innerText();
        assert(staleSummary.includes('older than this page') && staleSummary.includes('install.sh --restart'), `An old server should be explained, got: ${staleSummary}`);
        const staleReport = await page.getByTestId('troubleshoot-report-text').textContent();
        assert(staleReport.includes(currentCopyOrigin), 'The report should point to the up-to-date copy.');
        await page.unroute(ownTroubleshootRoutes);

        // A server that has the checks but started before its files changed names its folder in the restart command.
        const staleStatusRoute = `${baseUrl}api/troubleshoot/server-status`;
        await page.route(staleStatusRoute, (route) => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ stale: true, install_dir: '/srv/dt4sms', running_commit: 'aaaaaaa', disk_commit: 'bbbbbbb', restart_hint: 'Restart the app.' }),
        }));
        await page.reload({ waitUntil: 'domcontentloaded' });
        await openSettings(page);
        await staleBanner.waitFor({ timeout: 10000 });
        await page.getByTestId('settings-server-current-copy-link').waitFor({ timeout: 10000 });
        const restartText = await staleBanner.innerText();
        assert(restartText.includes('cd "/srv/dt4sms" && ./install.sh --restart'), `The banner should give the restart command for its folder, got: ${restartText}`);
        await page.unroute(staleStatusRoute);

        // AI provider: a local Ollama endpoint that isn't listening fails at the network stage.
        await page.getByTestId('settings-tab-connections').click();
        await page.getByRole('button', { name: 'Add AI Model' }).click();
        await page.locator('#llm-provider').selectOption('ollama');
        await page.locator('#llm-endpoint-url').fill(`http://127.0.0.1:${closedPort}`);
        await page.getByTestId('llm-troubleshoot').click();
        results = await waitForResults(page);
        assert(await page.getByTestId('troubleshoot-kind-llm').getAttribute('aria-pressed') === 'true', 'The AI provider form should open the AI provider checks.');
        assert(await page.getByTestId('troubleshoot-llm-provider').inputValue() === 'ollama', 'The provider from the form should be used.');
        assert(await stageStatus(page, 'network') === 'fail', 'A closed Ollama port should fail the network stage.');
        assert(await stageStatus(page, 'response') === 'skip', 'The provider check should be skipped when the network fails.');

        assert(pageErrors.length === 0, `Page errors: ${pageErrors.join(' | ')}`);
        console.log('Settings troubleshooting browser regression passed.');
    } catch (error) {
        if (page) {
            const resultText = await page.getByTestId('troubleshoot-results').innerText({ timeout: 1000 }).catch(() => '(no results)');
            console.error(`Troubleshoot results at failure:\n${resultText}`);
            if (process.env.SETTINGS_PROFILE_TEST_SCREENSHOT) {
                await page.screenshot({ path: process.env.SETTINGS_PROFILE_TEST_SCREENSHOT, fullPage: true }).catch(() => {});
            }
        }
        const logs = serverHandle.getLogs();
        if (logs) {
            console.error(logs.slice(-4000));
        }
        if (pageErrors.length) {
            console.error(`Page errors: ${pageErrors.join(' | ')}`);
        }
        if (dialogs.length) {
            console.error(`Dialogs: ${dialogs.join(' | ')}`);
        }
        throw error;
    } finally {
        if (browser) {
            await browser.close();
        }
        await stopServer(serverHandle);
        await new Promise((resolve) => fakeMcp.close(() => resolve()));
        await Promise.all(fakeCopies.map((server) => new Promise((resolve) => server.close(() => resolve()))));
        await removeTempDir(tempDir);
    }
}

main().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exit(1);
});
