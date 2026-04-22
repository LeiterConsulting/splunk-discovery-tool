import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function resolvePythonCommand() {
    return process.env.VISUALIZATION_BROWSER_TEST_PYTHON
        || process.env.FRONTEND_BUILD_PYTHON
        || 'python';
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
            server.close((closeError) => {
                if (closeError) {
                    reject(closeError);
                    return;
                }
                resolve(port);
            });
        });
    });
}

function startServer(port) {
    const logs = { stdout: [], stderr: [] };
    const child = spawn(
        resolvePythonCommand(),
        ['-m', 'uvicorn', 'web_app:app', '--app-dir', 'src', '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'],
        {
            cwd: repoRoot,
            env: {
                ...process.env,
                PYTHONUTF8: process.env.PYTHONUTF8 || '1',
            },
            stdio: ['ignore', 'pipe', 'pipe'],
        },
    );

    child.stdout.on('data', (chunk) => logs.stdout.push(chunk.toString()));
    child.stderr.on('data', (chunk) => logs.stderr.push(chunk.toString()));

    return {
        child,
        getLogs() {
            return `${logs.stdout.join('')}${logs.stderr.join('')}`.trim();
        },
    };
}

async function stopServer(serverHandle) {
    if (!serverHandle?.child || serverHandle.child.exitCode !== null) {
        return;
    }

    const child = serverHandle.child;

    await new Promise((resolve) => {
        const finish = () => resolve();
        child.once('exit', finish);

        if (process.platform === 'win32') {
            const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], {
                stdio: 'ignore',
            });
            killer.once('exit', finish);
            killer.once('error', () => {
                child.kill();
                finish();
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

        await delay(500);
    }

    throw new Error(`Timed out waiting for ${baseUrl}: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}

function findOverlappingLabels(labels) {
    const overlaps = [];

    for (let leftIndex = 0; leftIndex < labels.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < labels.length; rightIndex += 1) {
            const left = labels[leftIndex];
            const right = labels[rightIndex];
            const overlapX = Math.min(left.right, right.right) - Math.max(left.left, right.left);
            const overlapY = Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top);

            if (overlapX > 8 && overlapY > 8) {
                overlaps.push({
                    first: left.text,
                    second: right.text,
                    overlapX,
                    overlapY,
                });
            }
        }
    }

    return overlaps;
}

async function runBrowserRegression(baseUrl) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });

    try {
        await page.goto(`${baseUrl}/?view=visualization-regression`, { waitUntil: 'networkidle' });
        await page.locator('[data-testid="visualization-regression-root"]').waitFor({ state: 'visible' });

        const barRects = page.locator('[data-testid="visualization-regression-bar-rect"]');
        const barHeights = await barRects.evaluateAll((elements) => elements.map((element) => Number(element.getAttribute('height') || 0)));
        assert(barHeights.length === 8, `Expected 8 regression bars, received ${barHeights.length}.`);
        assert(barHeights.every((height) => Number.isFinite(height) && height > 4), `Detected collapsed or invalid bar heights: ${barHeights.join(', ')}`);

        const linePoints = await page.locator('[data-testid="visualization-regression-line-point"]').count();
        assert(linePoints === 8, `Expected 8 line points, received ${linePoints}.`);

        const barLabels = await page.locator('[data-testid="visualization-regression-bar-axis-label"]').evaluateAll((elements) => {
            return elements.map((element) => {
                const rect = element.getBoundingClientRect();
                return {
                    text: (element.textContent || '').trim(),
                    fullLabel: element.dataset.fullLabel || '',
                    truncated: element.dataset.truncated === 'true',
                    left: rect.left,
                    right: rect.right,
                    top: rect.top,
                    bottom: rect.bottom,
                };
            });
        });

        assert(barLabels.length === 8, `Expected 8 bar axis labels, received ${barLabels.length}.`);
        const truncatedLabels = barLabels.filter((label) => label.truncated && label.fullLabel.length > label.text.length);
        assert(truncatedLabels.length >= 6, `Expected dense labels to truncate aggressively, but only ${truncatedLabels.length} labels were truncated.`);

        const overlaps = findOverlappingLabels(barLabels);
        assert(overlaps.length === 0, `Detected overlapping dense bar labels: ${overlaps.map((entry) => `${entry.first} vs ${entry.second}`).join('; ')}`);

        await barRects.first().hover();
        const firstBarBoxHighlight = await page.locator('[data-testid="visualization-regression-bar-data-box"]').first().getAttribute('data-highlighted');
        assert(firstBarBoxHighlight === 'true', 'Hovering the first bar did not highlight the corresponding data box.');

        await page.locator('[data-testid="visualization-regression-bar-data-box"]').nth(1).hover();
        const secondBarHighlight = await page.locator('[data-testid="visualization-regression-bar-rect"]').nth(1).getAttribute('data-highlighted');
        assert(secondBarHighlight === 'true', 'Hovering the second bar data box did not highlight the corresponding bar.');

        await page.locator('[data-testid="visualization-regression-bar-data-box"]').nth(1).click();
        await page.locator('[data-testid="visualization-regression-bar-selection-card"]').waitFor({ state: 'visible' });
        const barSelectionLabel = (await page.locator('[data-testid="visualization-regression-bar-selection-label"]').textContent())?.trim() || '';
        assert(barSelectionLabel.includes('XmlWinEventLog:Microsoft-Windows-Sysmon/Operational-HighVolume'), `Unexpected bar selection card label: ${barSelectionLabel}`);
        const barSplunkActionCount = await page.locator('[data-testid="visualization-regression-bar-open-splunk"]').count();
        assert(barSplunkActionCount === 1, 'Expected the bar selection card to expose the Splunk deeplink action in the regression harness.');
        await page.locator('[data-testid="visualization-regression-bar-selection-close"]').click();

        await page.locator('[data-testid="visualization-regression-line-point-target"]').first().hover();
        const firstLineBoxHighlight = await page.locator('[data-testid="visualization-regression-line-data-box"]').first().getAttribute('data-highlighted');
        assert(firstLineBoxHighlight === 'true', 'Hovering the first line point did not highlight the corresponding data box.');

        await page.locator('[data-testid="visualization-regression-line-data-box"]').nth(2).hover();
        const thirdLinePointHighlight = await page.locator('[data-testid="visualization-regression-line-point"]').nth(2).getAttribute('data-highlighted');
        assert(thirdLinePointHighlight === 'true', 'Hovering the third line data box did not highlight the corresponding line point.');

        await page.locator('[data-testid="visualization-regression-line-point-target"]').nth(2).click();
        await page.locator('[data-testid="visualization-regression-line-selection-card"]').waitFor({ state: 'visible' });
        const lineSelectionLabel = (await page.locator('[data-testid="visualization-regression-line-selection-label"]').textContent())?.trim() || '';
        assert(lineSelectionLabel.includes('2026-04-19 16:00'), `Unexpected line selection card label: ${lineSelectionLabel}`);
        await page.locator('[data-testid="visualization-regression-line-selection-close"]').click();

        return {
            barHeights,
            linePoints,
            truncatedLabels: truncatedLabels.length,
        };
    } finally {
        await page.close();
        await browser.close();
    }
}

async function main() {
    let serverHandle = null;

    try {
        const port = await findFreePort();
        const baseUrl = `http://127.0.0.1:${port}`;
        serverHandle = startServer(port);
        await waitForServer(baseUrl);

        const result = await runBrowserRegression(baseUrl);
        console.log(`Visualization browser regression passed: ${result.barHeights.length} bars, ${result.linePoints} line points, ${result.truncatedLabels} truncated dense labels.`);
    } catch (error) {
        console.error('Visualization browser regression failed.');
        console.error(error instanceof Error ? error.stack || error.message : String(error));

        const logs = serverHandle?.getLogs?.();
        if (logs) {
            console.error('Server output:');
            console.error(logs);
        }

        process.exitCode = 1;
    } finally {
        await stopServer(serverHandle);
    }
}

await main();