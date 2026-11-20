import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
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

const HOUR_MS = 3600 * 1000;
// Recent runs, so the second run's last events are older than the 24-hour quiet threshold but still current.
const BASE = new Date(Math.floor((Date.now() - 4 * 24 * HOUR_MS) / 1000) * 1000);
const T1 = BASE;
const T2 = new Date(BASE.getTime() + 2 * 24 * HOUR_MS);

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
        process.env.ENVIRONMENT_MEMORY_TEST_PYTHON,
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

function runRef(moment) {
    const pad = (value) => String(value).padStart(2, '0');
    return `${moment.getUTCFullYear()}${pad(moment.getUTCMonth() + 1)}${pad(moment.getUTCDate())}_${pad(moment.getUTCHours())}${pad(moment.getUTCMinutes())}${pad(moment.getUTCSeconds())}`;
}

function epoch(moment) {
    return Math.floor(moment.getTime() / 1000);
}

function hoursBefore(moment, hours) {
    return new Date(moment.getTime() - hours * HOUR_MS);
}

// The same runs as RUN1 and RUN2 in tests/test_environment_memory.py.
function blueprint(at, { indexes, sourcetypes = {}, hosts = {}, recent = {}, idle = [] }) {
    const ledger = indexes.map((name) => ({ kind: 'index', data: { name, totalEventCount: 1000, currentDBSizeMB: 12.5 } }));
    for (const [name, last] of Object.entries(sourcetypes)) {
        ledger.push({ kind: 'sourcetype', data: { sourcetype: name, lastTime: epoch(last), totalCount: 40 } });
    }
    for (const [name, last] of Object.entries(hosts)) {
        ledger.push({ kind: 'host', data: { host: name, lastTime: epoch(last), totalCount: 25 } });
    }
    ledger.push({ kind: 'analytics', data: { analytics_id: 'recent_index_activity', data: { recent_event_counts: recent, indexes_without_recent_events: idle } } });
    return {
        generated_at: at.toISOString().replace(/\.\d{3}Z$/, 'Z'),
        finding_ledger: ledger,
        discovery_step_status: Object.fromEntries(['indexes', 'sourcetypes', 'hosts', 'sources'].map((name) => [name, { status: 'ok' }])),
        discovered_inventory: { indexes },
    };
}

async function seedDiscoveryRuns(outputDir) {
    await mkdir(outputDir, { recursive: true });
    const runs = [
        [T1, blueprint(T1, {
            indexes: ['contoso_web', 'contoso_fw', 'contoso_old', '_internal'],
            sourcetypes: { 'contoso:web': hoursBefore(T1, 1), 'contoso:fw': hoursBefore(T1, 2) },
            hosts: { web01: hoursBefore(T1, 1), fw01: hoursBefore(T1, 1) },
            recent: { contoso_web: 5000, contoso_fw: 300, _internal: 90000 },
            idle: ['contoso_old'],
        })],
        [T2, blueprint(T2, {
            indexes: ['contoso_web', 'contoso_fw', 'contoso_new', '_internal'],
            sourcetypes: { 'contoso:web': hoursBefore(T2, 1), 'contoso:new': hoursBefore(T2, 0.5) },
            hosts: { web01: hoursBefore(T2, 1) },
            recent: { contoso_web: 5200, contoso_new: 150, _internal: 91000 },
            idle: ['contoso_fw'],
        })],
    ];
    for (const [at, run] of runs) {
        await writeFile(path.join(outputDir, `v2_intelligence_blueprint_${runRef(at)}.json`), JSON.stringify(run), 'utf-8');
    }
}

async function getJson(baseUrl, pathname) {
    const response = await fetch(new URL(pathname, baseUrl));
    assert(response.ok, `GET ${pathname} returned HTTP ${response.status}`);
    return response.json();
}

async function dismissSplash(page) {
    const splash = page.locator('[data-testid="welcome-splash-modal"]');
    await splash.waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
    if (await splash.isVisible().catch(() => false)) {
        await splash.getByRole('button', { name: 'Get Started' }).click();
        await splash.waitFor({ state: 'hidden', timeout: 15000 });
    }
}

async function changeNames(page) {
    return (await page.getByTestId('environment-change-name').allInnerTexts()).map((name) => name.trim()).sort();
}

async function main() {
    const pythonCommand = await resolvePythonCommand();
    const appPort = await findFreePort();
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-environment-memory-'));
    const baseUrl = `http://127.0.0.1:${appPort}/`;
    await seedDiscoveryRuns(path.join(tempDir, 'output'));
    const serverHandle = startServer(pythonCommand, appPort, tempDir);
    let browser = null;
    let page = null;
    const pageErrors = [];
    const dialogs = [];

    try {
        await waitForServer(baseUrl);
        const initial = await getJson(baseUrl, '/api/environment-memory');
        assert(initial.memory?.has_data, 'The record should be built from the seeded discovery runs.');
        assert(initial.can_manage === true && initial.can_check === false, 'An open app with no MCP connection can manage the record but not check it.');
        assert(initial.memory.change_counts?.went_quiet === 3 && initial.memory.change_counts?.new === 2 && initial.memory.change_counts?.gone === 1,
            `Unexpected change counts: ${JSON.stringify(initial.memory.change_counts)}`);

        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
        page = await context.newPage();
        page.on('pageerror', (error) => pageErrors.push(String(error)));
        page.on('dialog', async (dialog) => {
            dialogs.push(dialog.message());
            await dialog.accept();
        });

        await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
        await dismissSplash(page);
        await page.locator('#workspace-tab-overview').click({ force: true });
        const panel = page.getByTestId('environment-changes-panel');
        await panel.waitFor({ state: 'visible', timeout: 30000 });
        await page.getByTestId('environment-change').first().waitFor({ timeout: 30000 });

        const summary = await page.getByTestId('environment-known-summary').innerText();
        assert(summary.includes('Known for Global: 4 indexes, 3 sourcetypes, and 2 hosts.'), `Unexpected known summary: ${summary}`);
        assert(summary.includes('3 are quiet now.'), `The summary should count quiet items, got: ${summary}`);
        assert(await page.getByTestId('environment-check-now').count() === 0, 'Check Now needs an MCP connection, so it should be hidden.');
        assert(await page.getByTestId('environment-change').count() === 6, 'All six changes from the second run should be listed.');
        assert((await panel.innerText()).includes('Scheduled checks are off.'), 'The panel should say scheduled checks are off by default.');

        await page.getByTestId('environment-filter-went_quiet').click();
        assert(await page.getByTestId('environment-filter-went_quiet').getAttribute('aria-pressed') === 'true', 'The Went quiet filter should be pressed.');
        const quietNames = await changeNames(page);
        assert(JSON.stringify(quietNames) === JSON.stringify(['contoso:fw', 'contoso_fw', 'fw01']), `Went quiet should list the firewall data, got: ${quietNames}`);

        const changeItem = (name) => page.getByTestId('environment-change').filter({ has: page.getByTestId('environment-change-name').getByText(name, { exact: true }) });
        const quietSourcetype = await changeItem('contoso:fw').innerText();
        assert(quietSourcetype.includes('No events since'), `A quiet sourcetype should say when its last event was, got: ${quietSourcetype}`);
        const quietIndex = changeItem('contoso_fw');
        // Discovery counts index events for 24 hours but has no last event time for them.
        assert((await quietIndex.innerText()).includes('No events in the last 24 hours'), 'A quiet index should name the window it had no events in.');
        await quietIndex.getByTestId('environment-change-ask').click();
        const chatInput = page.getByLabel('Chat message input');
        await chatInput.waitFor({ state: 'visible', timeout: 15000 });
        const prompt = await chatInput.inputValue();
        assert(prompt === 'index=contoso_fw went quiet (no events in the last 24 hours). When did it last receive events, and what might have stopped them?',
            `Ask in Chat should fill a focused question, got: ${prompt}`);
        assert(await chatInput.evaluate((element) => document.activeElement === element), 'Ask in Chat should focus the chat input.');

        // Settings: the card saves on its own and checks its numbers.
        await page.getByRole('button', { name: 'Open settings' }).click();
        await page.getByRole('heading', { name: 'Settings' }).waitFor({ timeout: 30000 });
        await page.getByTestId('settings-tab-connections').click();
        const card = page.getByTestId('settings-environment-memory-card');
        await card.waitFor({ state: 'visible', timeout: 15000 });
        const save = page.getByTestId('environment-settings-save');
        assert(!(await page.getByTestId('environment-settings-scheduled-check').isChecked()), 'Scheduled checks should be off by default.');
        assert(await page.getByTestId('environment-settings-learn-from-chat').isChecked(), 'Learning from chat should be on by default.');
        assert(await page.getByTestId('environment-settings-interval').inputValue() === '6', 'The default check interval is 6 hours.');
        assert(await page.getByTestId('environment-settings-quiet-hours').inputValue() === '24', 'The default quiet threshold is 24 hours.');
        assert(await save.isDisabled(), 'Save should wait for a change.');

        await page.getByTestId('environment-settings-quiet-hours').fill('0');
        await save.click();
        await card.getByRole('alert').waitFor({ timeout: 5000 });
        assert((await card.getByRole('alert').innerText()).includes('Quiet after must be a whole number of hours from 1 to 720.'), 'A quiet threshold of 0 should be refused.');
        assert((await getJson(baseUrl, '/api/environment-memory/settings')).settings.quiet_hours === 24, 'A refused value must not be saved.');

        await page.getByTestId('environment-settings-quiet-hours').fill('48');
        await page.getByTestId('environment-settings-scheduled-check').check();
        await page.getByTestId('environment-settings-interval').fill('12');
        await save.click();
        await card.getByText('Environment memory settings saved.').waitFor({ timeout: 10000 });
        const saved = (await getJson(baseUrl, '/api/environment-memory/settings')).settings;
        assert(saved.scheduled_check === true && saved.check_interval_hours === 12 && saved.quiet_hours === 48 && saved.learn_from_chat === true,
            `Saved settings do not match the form: ${JSON.stringify(saved)}`);
        assert(await save.isDisabled(), 'Save should be disabled again once the settings are saved.');

        const dialogCount = dialogs.length;
        await page.getByTestId('environment-settings-clear').click();
        await card.getByText('Cleared what the app learned about Global.').waitFor({ timeout: 10000 });
        assert(dialogs.slice(dialogCount).some((message) => message.startsWith('Forget what the app learned about Global?')), 'Clearing should ask first.');
        const cleared = await getJson(baseUrl, '/api/environment-memory');
        assert(!cleared.memory.has_data, 'The record should be empty after clearing.');

        await page.getByRole('button', { name: 'Close settings' }).click();
        await page.locator('#workspace-tab-overview').click({ force: true });
        await page.getByTestId('environment-changes-empty').waitFor({ timeout: 15000 });
        assert((await page.getByTestId('environment-changes-empty').innerText()).startsWith('Nothing learned yet.'), 'The panel should start over after clearing.');
        await page.getByTestId('environment-refresh').click();
        await delay(500);
        assert(await page.getByTestId('environment-change').count() === 0, 'Refreshing must not rebuild the record from the old runs.');
        assert(!(await panel.innerText()).includes('Scheduled checks'), 'An empty record should not show the check status line.');

        assert(pageErrors.length === 0, `Page errors: ${pageErrors.join(' | ')}`);
        console.log('Environment memory browser regression passed: 6 changes, Went quiet filter, Ask in Chat, settings save, and clear verified.');
    } catch (error) {
        if (page && process.env.ENVIRONMENT_MEMORY_TEST_SCREENSHOT) {
            await page.screenshot({ path: process.env.ENVIRONMENT_MEMORY_TEST_SCREENSHOT, fullPage: true }).catch(() => {});
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
        await removeTempDir(tempDir);
    }
}

main().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exit(1);
});
