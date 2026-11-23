import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
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

const PROFILE_TOKEN = 'browser-profile-token';
const SECOND_TOKEN = 'browser-second-token';

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

function startFakeMcpServer(port) {
    const authorizations = [];
    const server = createServer((request, response) => {
        authorizations.push(String(request.headers.authorization || ''));
        request.resume();
        request.on('end', () => {
            response.writeHead(200, { 'Content-Type': 'application/json' });
            response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [] } }));
        });
    });
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => resolve({ server, authorizations }));
    });
}

async function waitForAuthorization(fakeMcp, previousCount, timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (fakeMcp.authorizations.length > previousCount) {
            return fakeMcp.authorizations[fakeMcp.authorizations.length - 1];
        }
        await delay(100);
    }
    throw new Error('The fake MCP server did not receive a connection test request.');
}

async function getJson(baseUrl, route) {
    const response = await fetch(new URL(route, baseUrl));
    assert(response.ok, `GET ${route} failed with HTTP ${response.status}`);
    return response.json();
}

function buttonWithText(scope, label) {
    // Icon glyphs are part of the accessible name, so match on the visible label instead.
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return scope.locator('button', { hasText: new RegExp(`^\\s*${escaped}\\s*$`) }).first();
}

function profileCard(page, name) {
    return page.locator('#mcp-configs-list > div').filter({ has: page.locator('h5', { hasText: name }) }).first();
}

async function saveProfileFromForm(page, name, options = {}) {
    const dialog = page.locator('div.fixed.inset-0').filter({ hasText: /(Save|Update) MCP Configuration/ });
    await dialog.waitFor({ state: 'visible', timeout: 10000 });
    const nameInput = dialog.getByPlaceholder('e.g., Production Splunk, Dev Environment');
    if (options.expectNameLocked) {
        assert(await nameInput.isDisabled(), 'Updating a configuration should lock its name.');
    } else {
        assert(await nameInput.isEnabled(), 'Saving a new configuration must allow typing a name.');
        await nameInput.fill(name);
    }
    if (options.expectPreviewUrl) {
        await dialog.getByText(options.expectPreviewUrl).waitFor({ timeout: 5000 });
    }
    if (options.expectPreviewToken) {
        await dialog.getByText(options.expectPreviewToken).waitFor({ timeout: 5000 });
    }
    await dialog.locator('button', { hasText: /^\s*(Save|Update)\s+Configuration\s*$/ }).click();
    await dialog.waitFor({ state: 'hidden', timeout: 10000 });
    await profileCard(page, name).waitFor({ timeout: 10000 });
}

async function testProfileCard(page, fakeMcp, name) {
    const before = fakeMcp.authorizations.length;
    await profileCard(page, name).locator('button', { hasText: /^\s*Test\s*$/ }).click();
    return waitForAuthorization(fakeMcp, before);
}

async function main() {
    const pythonCommand = await resolvePythonCommand();
    const appPort = await findFreePort();
    const mcpPort = await findFreePort();
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-profiles-'));
    const baseUrl = `http://127.0.0.1:${appPort}/`;
    const mcpUrl = `http://127.0.0.1:${mcpPort}/services/mcp`;
    const fakeMcp = await startFakeMcpServer(mcpPort);
    const serverHandle = startServer(pythonCommand, appPort, tempDir);
    let browser = null;
    let page = null;
    const pageErrors = [];
    const alerts = [];

    try {
        await waitForServer(baseUrl);
        browser = await chromium.launch({ headless: true });
        page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
        page.on('pageerror', (error) => pageErrors.push(String(error)));
        page.on('dialog', async (dialog) => {
            // The form's Test Connection reports success through an alert; anything else is an error.
            if (dialog.type() === 'alert' && !dialog.message().startsWith('✅')) {
                alerts.push(dialog.message());
            }
            await dialog.accept();
        });

        await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
        // On a fresh install the welcome screen links straight to the connection settings.
        const splash = page.locator('[data-testid="welcome-splash-modal"]');
        await splash.waitFor({ state: 'visible', timeout: 15000 });
        await splash.getByRole('button', { name: 'Set Up Connections' }).click();
        await splash.waitFor({ state: 'hidden', timeout: 15000 });
        await page.getByRole('heading', { name: 'Settings' }).waitFor({ timeout: 30000 });

        // First profile on a fresh install: the dialog previews the typed values and the profile becomes active.
        await page.getByRole('button', { name: 'Add MCP Server' }).click();
        await page.locator('#mcp-url').fill(mcpUrl);
        await page.locator('#mcp-token').fill(PROFILE_TOKEN);
        await page.getByRole('button', { name: 'Save as New Configuration' }).click();
        await saveProfileFromForm(page, 'Prod Splunk', { expectPreviewUrl: mcpUrl, expectPreviewToken: 'New token entered' });
        let config = await getJson(baseUrl, '/api/config');
        assert(config.active_mcp_config_name === 'Prod Splunk', 'The first saved MCP configuration should become active.');
        assert(config.mcp.url === mcpUrl && config.mcp.token === '***', 'The active MCP connection should use the saved profile.');
        assert(await testProfileCard(page, fakeMcp, 'Prod Splunk') === `Bearer ${PROFILE_TOKEN}`, 'Saved profile test should send the saved token.');

        // Updating the loaded profile without retyping the token must keep the saved token.
        await profileCard(page, 'Prod Splunk').locator('button', { hasText: /^\s*Load\s*$/ }).click();
        await page.getByRole('button', { name: 'Update Active Configuration' }).waitFor({ timeout: 10000 });
        const formTestBefore = fakeMcp.authorizations.length;
        await page.getByRole('button', { name: 'Test Connection' }).first().click();
        assert(await waitForAuthorization(fakeMcp, formTestBefore) === `Bearer ${PROFILE_TOKEN}`, 'Form test without a retyped token should use the saved token.');
        await page.getByRole('button', { name: 'Update Active Configuration' }).click();
        await saveProfileFromForm(page, 'Prod Splunk', { expectNameLocked: true, expectPreviewToken: 'Keep saved token' });
        assert(await testProfileCard(page, fakeMcp, 'Prod Splunk') === `Bearer ${PROFILE_TOKEN}`, 'Updating without a token must not replace the saved token.');

        // "Save as New" from a loaded profile must accept a new name and keep using the same server token.
        await buttonWithText(page, 'Save as New').click();
        await saveProfileFromForm(page, 'Prod Copy', { expectPreviewToken: 'Use current token' });
        assert(await testProfileCard(page, fakeMcp, 'Prod Copy') === `Bearer ${PROFILE_TOKEN}`, 'A copy of the active server should keep its token.');
        config = await getJson(baseUrl, '/api/config');
        assert(config.active_mcp_config_name === 'Prod Splunk', 'Saving a second profile must not switch the active connection.');

        // Names with quotes, slashes, and hashes must work for every action.
        for (const name of ["Chris's Lab", 'Lab/Dev #1']) {
            await buttonWithText(page, 'Cancel').click({ timeout: 2000 }).catch(() => {});
            await page.getByRole('button', { name: 'Add MCP Server' }).click();
            await page.locator('#mcp-url').fill(mcpUrl);
            await page.locator('#mcp-token').fill(SECOND_TOKEN);
            await page.getByRole('button', { name: 'Save as New Configuration' }).click();
            await saveProfileFromForm(page, name);
            assert(await testProfileCard(page, fakeMcp, name) === `Bearer ${SECOND_TOKEN}`, `Test should work for "${name}".`);
            await profileCard(page, name).locator('button', { hasText: /^\s*Load\s*$/ }).click();
            await page.getByRole('button', { name: 'Update Active Configuration' }).waitFor({ timeout: 10000 });
            config = await getJson(baseUrl, '/api/config');
            assert(config.active_mcp_config_name === name, `Load should activate "${name}".`);
            await profileCard(page, name).locator('button', { hasText: /^\s*Delete\s*$/ }).click();
            await profileCard(page, name).waitFor({ state: 'detached', timeout: 10000 });
            const saved = await getJson(baseUrl, '/api/mcp-configs');
            assert(!Object.prototype.hasOwnProperty.call(saved, name), `Delete should remove "${name}".`);
        }

        // Keep the library open while another client changes the effective endpoint.
        const output = path.join(tempDir, 'output');
        const sessions = [];
        const activate = async (name, url) => {
            const response = await fetch(new URL('/api/mcp-configs', baseUrl), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, url, token: SECOND_TOKEN, activate: true }),
            });
            assert(response.ok, `Could not activate ${name}: HTTP ${response.status}`);
            return (await getJson(baseUrl, '/connection-info')).workspace;
        };
        const addReport = async (workspace, timestamp, title) => {
            const dir = path.join(output, 'scopes', Buffer.from(workspace.scope_key).toString('base64url'));
            const name = `v2_operator_runbook_${timestamp}.md`;
            await mkdir(dir, { recursive: true });
            await writeFile(path.join(dir, name), `# ${title}\n`);
            sessions.push({ ...workspace, timestamp, created_at: new Date().toISOString(), report_paths: [name] });
            const manifest = path.join(output, 'discovery_sessions.json');
            await writeFile(`${manifest}.tmp`, JSON.stringify(sessions));
            await rename(`${manifest}.tmp`, manifest);
            return name;
        };
        const secondPort = await findFreePort();
        const secondUrl = `http://127.0.0.1:${secondPort}/services/mcp`;
        const secondMcp = await startFakeMcpServer(secondPort);
        try {
            const alpha = await activate('Workspace Alpha', mcpUrl);
            const alphaReport = await addReport(alpha, '20260523_010203', 'Workspace Alpha report');
            const beta = await activate('Workspace Beta', secondUrl);
            const betaReport = await addReport(beta, '20260523_010204', 'Workspace Beta report');
            assert(alpha.scope_key !== beta.scope_key, 'Different MCP endpoints must have different workspaces.');
            await activate('Workspace Alpha', mcpUrl);
            await getJson(baseUrl, `/reports/${alphaReport}`);
            await page.reload({ waitUntil: 'domcontentloaded' });
            const workspaceSplash = page.locator('[data-testid="welcome-splash-modal"]');
            await workspaceSplash.getByRole('button', { name: 'Get Started' }).click();
            const workspaceBadge = page.getByTestId('active-mcp-workspace');
            await workspaceBadge.filter({ hasText: alpha.scope_label }).waitFor();
            await page.getByTestId('workspace-tab-discovery').click({ force: true });
            const alphaRow = page.getByTestId('discovery-report-row').filter({ hasText: alphaReport });
            await alphaRow.first().waitFor({ state: 'visible' });
            const reportOpened = page.waitForResponse((response) => response.url().endsWith(`/reports/${alphaReport}`), { timeout: 10000 });
            await alphaRow.first().press('Enter');
            const reportResponse = await reportOpened;
            assert(reportResponse.ok(), `Alpha report returned HTTP ${reportResponse.status()}: ${await reportResponse.text()}`);
            await page.getByTestId('report-viewer-title').waitFor({ state: 'visible', timeout: 10000 });

            await activate('Workspace Beta', secondUrl);
            await workspaceBadge.filter({ hasText: beta.scope_label }).waitFor();
            await page.getByTestId('report-library-workspace').filter({ hasText: beta.scope_label }).waitFor();
            await page.getByTestId('discovery-report-row').filter({ hasText: betaReport }).first().waitFor({ state: 'visible' });
            assert(await alphaRow.count() === 0, 'Switching the endpoint should remove the Alpha report.');
            assert(await page.getByTestId('report-viewer-title').count() === 0, 'The old report viewer should close.');

            // A worker may update only the polled runtime snapshot when it finishes.
            const finishedTimestamp = '20260523_010205';
            const finishedReport = await addReport(beta, finishedTimestamp, 'Completed worker report');
            await page.route('**/api/discovery/status', (route) => route.fulfill({
                json: { status: 'completed', result_timestamp: finishedTimestamp, report_count: 1 },
            }));
            const finishedRow = page.getByTestId('discovery-report-row').filter({ hasText: finishedReport });
            await finishedRow.first().waitFor({ state: 'visible', timeout: 15000 });
            await page.unroute('**/api/discovery/status');

            await page.getByTestId('workspace-tab-knowledge-base').click({ force: true });
            await page.getByTestId('knowledge-base-workspace').filter({ hasText: beta.scope_label }).waitFor();
            await activate('Workspace Alpha', mcpUrl);
            await page.getByTestId('knowledge-base-workspace').filter({ hasText: alpha.scope_label }).waitFor();
            // Reproduce the signed-in mismatch between the shared default and an account assignment.
            const enableAuth = await page.request.post(new URL('/api/config', baseUrl).href, {
                data: { security: { auth_enabled: true, password_min_length: 14 } },
            });
            assert(enableAuth.ok(), 'Could not enable sign-in in the test app.');
            const login = await page.request.post(new URL('/api/auth/login', baseUrl).href, {
                data: { username: 'admin', password: 'password' },
            });
            assert(login.ok(), 'Could not sign in to the test app.');
            const reset = await page.request.post(new URL('/api/auth/reset-password', baseUrl).href, {
                data: { current_password: 'password', new_password: 'BetterPassword123!', confirm_password: 'BetterPassword123!' },
            });
            assert(reset.ok(), 'Could not reset the test password.');
            const auth = await (await page.request.get(new URL('/api/auth/status', baseUrl).href)).json();
            const assign = await page.request.patch(new URL(`/api/security/users/${auth.user.id}`, baseUrl).href, {
                data: { mcp_config_name: 'Workspace Alpha' },
            });
            assert(assign.ok(), 'Could not seed the previous MCP assignment.');

            await page.reload({ waitUntil: 'domcontentloaded' });
            await workspaceSplash.getByRole('button', { name: 'Get Started' }).click();
            await workspaceBadge.filter({ hasText: alpha.scope_label }).waitFor();
            await page.getByRole('button', { name: 'Open settings' }).click();
            await profileCard(page, 'Workspace Beta').locator('button', { hasText: /^\s*Load\s*$/ }).click();
            await workspaceBadge.filter({ hasText: beta.scope_label }).waitFor();
            await page.getByTestId('settings-effective-mcp').filter({ hasText: 'Workspace Beta' }).waitFor();
            await profileCard(page, 'Workspace Beta').getByTestId('active-mcp-profile').waitFor();
            assert(await profileCard(page, 'Workspace Alpha').getByTestId('active-mcp-profile').count() === 0,
                'The shared default should no longer be marked active for this account.');
            await page.waitForFunction((url) => document.querySelector('#mcp-url')?.value === url, secondUrl);

            await buttonWithText(page, 'Save as New').click();
            const saveDialog = page.getByRole('dialog', { name: 'Save MCP Configuration' });
            await saveDialog.getByLabel('Use this connection for my account after saving').check();
            await saveProfileFromForm(page, 'Personal Beta', { expectPreviewUrl: secondUrl, expectPreviewToken: 'Use current token' });
            await workspaceBadge.filter({ hasText: 'Personal Beta' }).waitFor();
            await page.getByTestId('settings-effective-mcp').filter({ hasText: 'Personal Beta' }).waitFor();
            const savedConfig = await (await page.request.get(new URL('/api/config', baseUrl).href)).json();
            assert(savedConfig.active_mcp_config_name === 'Workspace Alpha', 'Selecting a personal connection should preserve the shared default.');
            assert(savedConfig.effective_mcp.url === secondUrl, 'The selected connection must point to the second MCP endpoint.');

            // The footer Save updates the form's active profile, not the shared MCP default.
            const revisedUrl = secondUrl.replace('127.0.0.1', 'localhost');
            await page.locator('#mcp-url').fill(revisedUrl);
            await page.getByRole('button', { name: 'Save Settings', exact: true }).click();
            await workspaceBadge.filter({ hasText: `Personal Beta · localhost:${secondPort}` }).waitFor();
            const notice = alerts.indexOf('Settings saved successfully!');
            assert(notice >= 0, 'The footer should confirm the save.');
            alerts.splice(notice, 1);
            const afterSave = await (await page.request.get(new URL('/api/config', baseUrl).href)).json();
            assert(afterSave.effective_mcp.url === revisedUrl && afterSave.mcp.url === mcpUrl,
                'The edit must apply to the selected profile and preserve the default endpoint.');
            await page.getByRole('button', { name: 'Open settings' }).click();
            await profileCard(page, 'Workspace Alpha').locator('button', { hasText: /^\s*Load\s*$/ }).click();
            await workspaceBadge.filter({ hasText: alpha.scope_label }).waitFor();
            await profileCard(page, 'Workspace Alpha').getByTestId('active-mcp-profile').waitFor();
        } finally {
            await new Promise((resolve) => secondMcp.server.close(() => resolve()));
        }

        assert(pageErrors.length === 0, `Page errors: ${pageErrors.join(' | ')}`);
        assert(alerts.length === 0, `Unexpected alerts: ${alerts.join(' | ')}`);
        console.log('Settings profile browser regression passed.');
    } catch (error) {
        if (page) {
            const listText = await page.locator('#mcp-configs-list').innerText().catch(() => '(list not found)');
            console.error(`MCP configuration list at failure:\n${listText}`);
            if (process.env.SETTINGS_PROFILE_TEST_SCREENSHOT) {
                await page.screenshot({ path: process.env.SETTINGS_PROFILE_TEST_SCREENSHOT }).catch(() => {});
            }
        }
        const logs = serverHandle.getLogs();
        if (logs) {
            console.error(logs.slice(-4000));
        }
        if (pageErrors.length) {
            console.error(`Page errors: ${pageErrors.join(' | ')}`);
        }
        if (alerts.length) {
            console.error(`Alerts: ${alerts.join(' | ')}`);
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
