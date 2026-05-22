import { spawn } from 'node:child_process';
import { access, readFile, readdir, rm, writeFile } from 'node:fs/promises';
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

function jsonRoutePayload(payload, status = 200) {
    return {
        status,
        contentType: 'application/json',
        body: JSON.stringify(payload),
    };
}

async function routeJson(page, url, payload, status = 200) {
    await page.route(url, async (route) => {
        await route.fulfill(jsonRoutePayload(payload, status));
    });
}

function sseRoutePayload(events, status = 200) {
    return {
        status,
        contentType: 'text/event-stream',
        headers: {
            'cache-control': 'no-cache',
        },
        body: events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(''),
    };
}

async function routeSse(page, url, events, status = 200) {
    await page.route(url, async (route) => {
        await route.fulfill(sseRoutePayload(events, status));
    });
}

async function dismissWelcomeSplashIfPresent(page, options = {}) {
    const welcomeSplash = page.locator('[data-testid="welcome-splash-modal"]');
    const isVisible = await welcomeSplash.isVisible().catch(() => false);
    if (!isVisible) {
        return false;
    }

    await page.getByRole('heading', { name: 'Welcome to DT4SMS' }).waitFor({ timeout: 30000 });
    if (options.dontShowAgain) {
        await welcomeSplash.locator('[data-testid="welcome-splash-dismiss-checkbox"]').check();
    }
    await welcomeSplash.getByRole('button', { name: 'Enter Workspace' }).click();
    await welcomeSplash.waitFor({ state: 'hidden', timeout: 30000 });
    return true;
}

async function pathExists(targetPath) {
    try {
        await access(targetPath);
        return true;
    } catch {
        return false;
    }
}

async function readJsonFile(filePath) {
    return JSON.parse(await readFile(filePath, 'utf8'));
}

function buildCompletedDiscoveryPhasePlan(completedAt) {
    const phases = [
        { key: 'pipeline_boot', label: 'Bootstrap', detail: 'Runtime validation complete.' },
        { key: 'signal_capture', label: 'Signal Capture', detail: 'Environment signal capture complete.' },
        { key: 'evidence_collection', label: 'Evidence Collection', detail: 'Evidence collection complete.' },
        { key: 'classification_map', label: 'Classification Map', detail: 'Classification map generated.' },
        { key: 'recommendation_queue', label: 'Recommendation Queue', detail: 'Recommendations generated.' },
        { key: 'use_case_generation', label: 'Use Case Generation', detail: 'Use cases generated.' },
        { key: 'blueprint_assembly', label: 'Blueprint Assembly', detail: 'Blueprint assembled.' },
        { key: 'artifact_packaging', label: 'Artifact Packaging', detail: 'Artifacts packaged to output.' },
    ];

    return phases.map((phase, index) => ({
        key: phase.key,
        label: phase.label,
        title: phase.label,
        description: phase.detail,
        progress_start: index === 0 ? 0 : Math.round((index / phases.length) * 100),
        progress_end: Math.round(((index + 1) / phases.length) * 100),
        baseline_seconds: 60,
        progress_percent: Math.round(((index + 1) / phases.length) * 100),
        status: 'completed',
        started_at: completedAt,
        completed_at: completedAt,
        last_detail: phase.detail,
    }));
}

async function findLatestSummarySession() {
    const outputDir = path.join(repoRoot, 'output');
    const manifestPath = path.join(outputDir, 'discovery_sessions.json');
    let sessions = [];

    if (await pathExists(manifestPath)) {
        const payload = await readJsonFile(manifestPath);
        if (Array.isArray(payload)) {
            sessions = payload
                .filter((session) => session && typeof session.timestamp === 'string')
                .sort((left, right) => String(right.timestamp).localeCompare(String(left.timestamp)));
        }
    }

    for (const session of sessions) {
        const summaryPath = path.join(outputDir, `v2_ai_summary_${session.timestamp}.json`);
        if (await pathExists(summaryPath)) {
            return {
                timestamp: session.timestamp,
                createdAt: session.created_at || null,
                reportPaths: Array.isArray(session.report_paths) ? session.report_paths : [],
            };
        }
    }

    const outputEntries = await readdir(outputDir, { withFileTypes: true });
    const summaryTimestamps = outputEntries
        .filter((entry) => entry.isFile())
        .map((entry) => {
            const match = /^v2_ai_summary_(\d{8}_\d{6})\.json$/i.exec(entry.name);
            return match ? match[1] : null;
        })
        .filter(Boolean)
        .sort((left, right) => String(right).localeCompare(String(left)));

    assert(summaryTimestamps.length > 0, 'No cached V2 summary artifacts are available in output/.');

    const timestamp = summaryTimestamps[0];
    const reportPaths = outputEntries
        .filter((entry) => entry.isFile() && entry.name.includes(timestamp) && entry.name.startsWith('v2_'))
        .map((entry) => entry.name)
        .sort();

    return {
        timestamp,
        createdAt: null,
        reportPaths,
    };
}

async function seedOperatorRuntimeState() {
    const runtimeStatePath = path.join(repoRoot, 'output', 'runtime_state.json');
    const exportDir = path.join(repoRoot, 'output', 'exports');
    const originalRuntimeState = await pathExists(runtimeStatePath)
        ? await readFile(runtimeStatePath, 'utf8')
        : null;
    const latestSession = await findLatestSummarySession();
    const completedAt = new Date().toISOString();
    const phasePlan = buildCompletedDiscoveryPhasePlan(completedAt);
    const reportCount = latestSession.reportPaths.length;
    const runtimeStatePayload = {
        schema_version: 1,
        saved_at: completedAt,
        discovery_runtime_state: {
            status: 'completed',
            session_id: `operator-regression-${latestSession.timestamp}`,
            pipeline_version: 'v2',
            started_at: latestSession.createdAt || completedAt,
            updated_at: completedAt,
            completed_at: completedAt,
            result_timestamp: latestSession.timestamp,
            report_count: reportCount,
            error: null,
            current_phase_key: 'artifact_packaging',
            current_phase_title: 'Artifact Packaging',
            phase_plan: phasePlan,
            last_run_outcome: {
                status: 'completed',
                title: 'Discovery run completed',
                summary: `Finished at ${completedAt} and produced ${reportCount} report artifact${reportCount === 1 ? '' : 's'}.`,
                completed_at: completedAt,
                result_timestamp: latestSession.timestamp,
                report_count: reportCount,
                phase_title: 'Artifact Packaging',
                error: null,
            },
            progress: {
                percentage: 100,
                current_step: 100,
                total_steps: 100,
                description: 'Artifact packaging complete.',
                eta_seconds: 0,
                eta_method: 'stage_calibrated',
            },
        },
        summarization_progress: {
            [latestSession.timestamp]: {
                session_id: latestSession.timestamp,
                stage: 'complete',
                progress: 100,
                message: 'Summary available from cache.',
                started_at: completedAt,
                updated_at: completedAt,
                completed_at: completedAt,
            },
        },
    };

    await writeFile(runtimeStatePath, JSON.stringify(runtimeStatePayload, null, 2), 'utf8');

    return {
        exportDir,
        latestSession,
        async restore() {
            if (originalRuntimeState === null) {
                await rm(runtimeStatePath, { force: true });
                return;
            }
            await writeFile(runtimeStatePath, originalRuntimeState, 'utf8');
        },
    };
}

async function assertChatPromptContains(page, expectedText) {
    const dialog = page.getByRole('dialog');
    await dialog.waitFor({ state: 'visible' });

    const input = page.getByLabel('Chat message input');
    await input.waitFor({ state: 'visible' });
    const value = await input.inputValue();
    assert(
        value.includes(expectedText),
        `Expected the chat input to include "${expectedText}", but received: ${value}`,
    );
}

async function closeChatModal(page) {
    const closeButton = page.getByRole('button', { name: 'Close chat' });
    if (await closeButton.count()) {
        await closeButton.first().click();
    }
}

async function expandDiscoveryReportHierarchy(page, reportLabel) {
    const toggleOrder = [
        'discovery-report-year-toggle',
        'discovery-report-month-toggle',
        'discovery-report-day-toggle',
        'discovery-report-session-toggle',
    ];

    for (const testId of toggleOrder) {
        if (await page.getByTestId('discovery-report-row').count()) {
            break;
        }

        const toggle = page.getByTestId(testId).first();
        if (await toggle.count()) {
            await toggle.click({ force: true });
        }
    }

    const reportRows = page.getByTestId('discovery-report-row');
    assert(await reportRows.count() > 0, `Report hierarchy did not expose ${reportLabel} after expansion.`);
}

async function runBrowserRegression(baseUrl) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error instanceof Error ? error.message : String(error)));

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

        const barDataBoxCount = await page.locator('[data-testid="visualization-regression-bar-data-box"]').count();
        assert(barDataBoxCount === 8, `Expected 8 bar data boxes, received ${barDataBoxCount}.`);

        await page.locator('[data-testid="visualization-regression-line-point-target"]').first().hover();
        const firstLineBoxHighlight = await page.locator('[data-testid="visualization-regression-line-data-box"]').first().getAttribute('data-highlighted');
        assert(firstLineBoxHighlight === 'true', 'Hovering the first line point did not highlight the corresponding data box.');

        await page.locator('[data-testid="visualization-regression-line-data-box"]').nth(2).hover();
        const thirdLinePointHighlight = await page.locator('[data-testid="visualization-regression-line-point"]').nth(2).getAttribute('data-highlighted');
        assert(thirdLinePointHighlight === 'true', 'Hovering the third line data box did not highlight the corresponding line point.');

        const lineDataBoxCount = await page.locator('[data-testid="visualization-regression-line-data-box"]').count();
        assert(lineDataBoxCount === 8, `Expected 8 line data boxes, received ${lineDataBoxCount}.`);

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

async function runWelcomeSplashRegression(baseUrl) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error instanceof Error ? error.message : String(error)));

    try {
        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        const welcomeSplash = page.locator('[data-testid="welcome-splash-modal"]');
        await welcomeSplash.waitFor({ state: 'visible', timeout: 30000 });
        await page.getByRole('heading', { name: 'Welcome to DT4SMS' }).waitFor({ timeout: 30000 });
        await page.getByText('DT4SMS turns Splunk discovery, investigation, reporting, and operator handoff into one guided workspace.').waitFor({ timeout: 30000 });

        const splashCheckbox = welcomeSplash.locator('[data-testid="welcome-splash-dismiss-checkbox"]');
        assert(!(await splashCheckbox.isChecked()), 'Welcome splash do-not-show checkbox should be off by default.');

        await welcomeSplash.getByRole('button', { name: 'Enter Workspace' }).click();
        await welcomeSplash.waitFor({ state: 'hidden', timeout: 30000 });
        await page.getByRole('button', { name: 'Open settings' }).click();
        await page.getByTestId('settings-reset-welcome-splash').click();
        await page.getByRole('button', { name: 'Close settings' }).click();

        await page.reload({ waitUntil: 'networkidle' });
        await welcomeSplash.waitFor({ state: 'visible', timeout: 30000 });
        await splashCheckbox.check();
        await welcomeSplash.getByRole('button', { name: 'Enter Workspace' }).click();
        await welcomeSplash.waitFor({ state: 'hidden', timeout: 30000 });

        await page.reload({ waitUntil: 'networkidle' });
        await page.getByRole('button', { name: 'Open settings' }).waitFor({ timeout: 30000 });
        const splashStillVisible = await welcomeSplash.isVisible().catch(() => false);
        assert(!splashStillVisible, 'Welcome splash should stay hidden after selecting do-not-show-again.');
        assert(pageErrors.length === 0, `Welcome splash regression encountered page errors: ${pageErrors.join(' | ')}`);

        return { persistedDismissal: true };
    } finally {
        await page.close();
        await browser.close();
    }
}

async function runWorkspaceSmoke(baseUrl) {
    const reportFilename = 'spl_library_report_20260514_120000.md';
    const reportLabel = 'spl_library_report.md';
    const reportQuery = 'search index=reports | stats count by source';
    const libraryQuery = 'search index=_internal | stats count by sourcetype';
    const libraryAssetId = 'spl-library-asset-1';
    const libraryAsset = {
        asset_id: libraryAssetId,
        title: 'Internal Sourcetype Rollup',
        asset_type: 'spl_query_library',
        source_label: 'Report viewer',
        description: 'Reusable SPL for sourcetype rollups.',
        summary: 'Saved SPL query for reusing the main sourcetype rollup pattern.',
        preview: 'Saved SPL query for reusing the main sourcetype rollup pattern.',
        headings: ['Query', 'Context'],
        key_points: ['Summarizes sourcetype counts for the internal index.'],
        focus_terms: ['sourcetype', 'internal', 'counts'],
        usage_guidance: ['Use when validating sourcetype distribution in Splunk Web or chat.'],
        tags: ['spl', 'spl-library', 'report'],
        attributes: {
            spl_query: libraryQuery,
            app: 'search',
            earliest: '-24h',
            latest: 'now',
            origin_kind: 'report_viewer',
            origin_label: reportFilename,
            spl_intelligence: {
                query_intent: 'distribution_analysis',
                environment_fit: {
                    status: 'strong',
                    score: 92,
                    reason: 'The _internal index is present in the discovered environment and ready for validation.',
                },
                validation: {
                    status: 'known_good',
                    execution_count: 4,
                    success_count: 3,
                    failure_count: 1,
                    last_status: 'success',
                },
                reuse: {
                    tier: 'known_good',
                    score: 94,
                    known_good: true,
                    guidance: 'Reuse this query as the baseline internal sourcetype rollup before creating a new search.',
                },
            },
        },
        library_status: 'checked_in',
        checked_out_at: null,
        last_checked_in_at: '2026-05-14T12:05:00Z',
        content_path: 'knowledge_asset_20260514T120000_internal-sourcetype-rollup.md',
        import_method: 'text',
        original_filename: null,
        created_at: '2026-05-14T12:00:00Z',
        updated_at: '2026-05-14T12:05:00Z',
        text_char_count: 188,
        word_count: 27,
    };

    const capabilitiesPayload = {
        summary: {
            total: 2,
            installed: 2,
            enabled: 2,
            ready: 2,
            restart_required: 0,
        },
        capabilities: {
            rag_chromadb: {
                name: 'rag_chromadb',
                title: 'Indexed Artifact Search',
                description: 'Indexed artifact search plus managed knowledge assets for context-rich retrieval.',
                purpose: 'Surface managed context assets and saved SPL queries.',
                intent: 'Give operators a persistent retrieval and context workspace.',
                category: 'rag',
                install_method: 'internal',
                maturity: 'phase4',
                runtime_available: true,
                installed: true,
                enabled: true,
                restart_required: false,
                health_status: 'ready',
                health_message: 'RAG context workspace is ready.',
                version: '1.0.0',
                dependency_packages: ['chromadb'],
                capability_set: ['managed knowledge assets', 'indexed retrieval'],
                config: {
                    storage_dir: 'output/rag/chromadb',
                    asset_dir: 'output/rag/assets',
                },
                index_summary: {
                    document_count: 4,
                    source_file_count: 2,
                    last_indexed_at: '2026-05-14T12:00:00Z',
                    sample_sources: ['output/spl_library_report_20260514_120000.md'],
                    source_type_counts: {
                        discovery_artifact: 1,
                        knowledge_asset: 1,
                    },
                },
                knowledge_asset_summary: {
                    asset_count: 1,
                    checked_in_asset_count: 1,
                    checked_out_asset_count: 0,
                    library_status_counts: {
                        checked_in: 1,
                        checked_out: 0,
                    },
                    asset_type_counts: {
                        spl_query_library: 1,
                    },
                    asset_dir: 'output/rag/assets',
                },
            },
            splunk_deeplink_tools: {
                name: 'splunk_deeplink_tools',
                title: 'Splunk Deeplink Tools',
                description: 'Build Splunk Web deep links for saved queries.',
                purpose: 'Open saved searches directly in Splunk Web.',
                intent: 'Preserve operator flow between DT4SMS and Splunk.',
                category: 'tool_pack',
                install_method: 'internal',
                maturity: 'foundation',
                runtime_available: true,
                installed: true,
                enabled: true,
                restart_required: false,
                health_status: 'ready',
                health_message: 'Splunk deeplinks are ready.',
                version: '1.0.0',
                dependency_packages: [],
                capability_set: ['search deeplinks'],
                resolved_web_base_url: 'https://splunk.example.com',
                default_app: 'search',
                base_url_source: 'config',
                config: {
                    default_app: 'search',
                    default_earliest: '-24h',
                    default_latest: 'now',
                },
            },
        },
    };

    const assetSummaryPayload = {
        message: 'Managed knowledge assets loaded.',
        details: {
            asset_count: 1,
            checked_in_asset_count: 1,
            checked_out_asset_count: 0,
            library_status_counts: {
                checked_in: 1,
                checked_out: 0,
            },
            asset_type_counts: {
                spl_query_library: 1,
            },
            asset_dir: 'output/rag/assets',
            assets: [libraryAsset],
        },
    };

    const assetDetailPayload = {
        message: 'Managed knowledge asset detail loaded.',
        details: {
            asset: libraryAsset,
            stored_path: libraryAsset.content_path,
            stored_sections: [
                {
                    title: 'Overview',
                    content: 'Saved SPL query for reusing the main sourcetype rollup pattern.',
                    items: [],
                    line_count: 1,
                    character_count: 58,
                },
                {
                    title: 'Context',
                    content: `Saved SPL query for reuse in Splunk Web and follow-on chat workflows.\n\n## Query\n${libraryQuery}\n\n## Context\nCaptured from the report viewer.`,
                    items: [],
                    line_count: 5,
                    character_count: 165,
                },
            ],
            context_body: `Saved SPL query for reuse in Splunk Web and follow-on chat workflows.\n\n## Query\n${libraryQuery}\n\n## Context\nCaptured from the report viewer.`,
            context_character_count: 165,
            chunk_count: 1,
            chunk_sections: [
                {
                    document_id: 'spl-library-chunk-1',
                    section: 'Overview',
                    character_count: 165,
                    content: `Saved SPL query for reuse in Splunk Web and follow-on chat workflows. ${libraryQuery}`,
                },
            ],
        },
    };

    const chatStreamEvents = [
        {
            type: 'status',
            action: 'Consulting reusable SPL query context',
        },
        {
            type: 'response',
            data: {
                response: 'Start from the saved internal sourcetype rollup query and adapt it only if the scope changes.',
                capability_usage: [
                    {
                        name: 'rag_chromadb',
                        title: 'Indexed Artifact Search',
                        category: 'rag',
                        used_in: 'llm_prompt',
                        contribution: 'Surfaced 1 reusable SPL candidate.',
                        chunks: [
                            {
                                source: 'output/rag/assets/internal-sourcetype-rollup.md',
                                score: 97,
                                snippet: 'Reusable SPL for internal telemetry analysis.',
                                source_type: 'knowledge_asset',
                            },
                        ],
                        reusable_queries: [
                            {
                                title: 'Internal Sourcetype Rollup',
                                query: libraryQuery,
                                reuse_tier: 'known_good',
                                known_good: true,
                                why_reuse: 'Known good in this environment and already aligned to _internal sourcetype analysis.',
                                environment_fit_status: 'strong',
                                validation_status: 'known_good',
                                success_count: 3,
                                failure_count: 1,
                                app: 'search',
                                earliest: '-24h',
                                latest: 'now',
                            },
                        ],
                    },
                ],
                follow_on_actions: [],
                status_timeline: [],
                iterations: 1,
                execution_time: '0.2s',
            },
        },
    ];

    const reportListPayload = {
        reports: [
            {
                name: reportFilename,
                size: 2048,
                type: 'md',
                modified: '2026-05-14T12:10:00Z',
            },
        ],
        sessions: [],
    };

    const reportDetailPayload = {
        type: 'text',
        content: [
            '# SPL Library Report',
            '',
            'Detected query:',
            '```spl',
            reportQuery,
            '```',
        ].join('\n'),
        spl_queries: [reportQuery],
    };

    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error instanceof Error ? error.message : String(error)));

    try {
        await routeJson(page, `${baseUrl}/api/capabilities/rag/assets/${libraryAssetId}`, assetDetailPayload);
        await routeJson(page, `${baseUrl}/api/capabilities/rag/assets`, assetSummaryPayload);
        await routeJson(page, `${baseUrl}/api/capabilities`, capabilitiesPayload);
        await routeJson(page, `${baseUrl}/reports/${reportFilename}`, reportDetailPayload);
        await routeJson(page, `${baseUrl}/reports`, reportListPayload);
        await routeJson(page, `${baseUrl}/api/v2/artifacts`, { has_data: false, artifacts: [], count: 0 });
        await routeJson(page, `${baseUrl}/api/v2/intelligence`, { has_data: false, message: 'No discovery intelligence fixture needed.' });
        await routeJson(page, `${baseUrl}/api/discovery/dashboard`, { has_data: false, message: 'No dashboard fixture needed.' });

        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        await dismissWelcomeSplashIfPresent(page, { dontShowAgain: true });
        assert(pageErrors.length === 0, `Workspace smoke encountered page errors: ${pageErrors.join(' | ')}`);

        await page.getByTestId('workspace-tab-discovery').click({ force: true });
        await expandDiscoveryReportHierarchy(page, reportLabel);
        const firstReportRow = page.getByTestId('discovery-report-row').first();
        await firstReportRow.waitFor({ state: 'visible' });
        const reportRowLabel = ((await firstReportRow.textContent()) || '').trim();
        assert(reportRowLabel.includes(reportLabel), `Expected the discovery report row to include ${reportLabel}, but received: ${reportRowLabel}`);
        await firstReportRow.click({ force: true });

        await page.getByTestId('report-viewer-spl-blocks').waitFor({ state: 'visible' });
        const reportSplCardCount = await page.getByTestId('report-viewer-spl-card').count();
        assert(reportSplCardCount === 1, `Expected 1 report SPL card, received ${reportSplCardCount}.`);
        await page.getByTestId('report-viewer-spl-card').first().getByRole('button', { name: 'Use in Chat' }).click();
        await assertChatPromptContains(page, reportQuery);
        await closeChatModal(page);

        await page.getByTestId('workspace-tab-context').click({ force: true });
        const contextTabSelected = await page.getByTestId('workspace-tab-context').getAttribute('aria-selected');
        assert(contextTabSelected === 'true', 'Context workspace tab did not become active.');

        await page.getByTestId('context-library-filter-spl_library').waitFor({ state: 'visible' });
        await page.getByTestId('context-library-filter-spl_library').click();
        const firstLibraryCard = page.getByTestId('context-library-spl-asset-card').first();
        await firstLibraryCard.waitFor({ state: 'visible' });
        const libraryCardCount = await page.getByTestId('context-library-spl-asset-card').count();
        assert(libraryCardCount === 1, `Expected 1 SPL library asset card, received ${libraryCardCount}.`);
        const visibleLibraryQuery = firstLibraryCard.getByTestId('context-library-spl-only-query');
        await visibleLibraryQuery.waitFor({ state: 'visible' });
        const visibleLibraryQueryText = ((await visibleLibraryQuery.textContent()) || '').trim();
        assert(visibleLibraryQueryText.includes(libraryQuery), `Expected the Context SPL-only card to include the saved query, but received: ${visibleLibraryQueryText}`);
        const fitBadgeText = ((await firstLibraryCard.getByTestId('context-library-spl-fit-status').textContent()) || '').trim();
        assert(fitBadgeText.includes('Environment Fit: Strong'), `Expected strong environment-fit badge, but received: ${fitBadgeText}`);
        const validationBadgeText = ((await firstLibraryCard.getByTestId('context-library-spl-validation-status').textContent()) || '').trim();
        assert(validationBadgeText.includes('Validation: Known Good'), `Expected known-good validation badge, but received: ${validationBadgeText}`);
        const reuseBadgeText = ((await firstLibraryCard.getByTestId('context-library-spl-reuse-tier').textContent()) || '').trim();
        assert(reuseBadgeText.includes('Reuse: Known Good'), `Expected known-good reuse badge, but received: ${reuseBadgeText}`);
        const feedbackBadgeText = ((await firstLibraryCard.getByTestId('context-library-spl-feedback-counts').textContent()) || '').trim();
        assert(feedbackBadgeText.includes('Observed Runs: 3 success / 1 failure'), `Expected observed-run counts, but received: ${feedbackBadgeText}`);

        await firstLibraryCard.getByTestId('context-library-view-spl-details').click();
        await page.getByTestId('context-library-detail-spl-query').waitFor({ state: 'visible' });
        const detailFitBadgeText = ((await page.getByTestId('context-library-detail-spl-fit-status').textContent()) || '').trim();
        assert(detailFitBadgeText.includes('Environment Fit: Strong'), `Expected detail fit badge to render, but received: ${detailFitBadgeText}`);

        await routeSse(page, `${baseUrl}/chat/stream`, chatStreamEvents);
        await firstLibraryCard.getByRole('button', { name: 'Use in Chat' }).click();
        await assertChatPromptContains(page, libraryQuery);
        await page.getByRole('button', { name: 'Send chat message' }).click();
        const capabilityEvidence = page.getByTestId('chat-capability-evidence');
        await capabilityEvidence.waitFor({ state: 'visible' });
        const evidenceAutoExpanded = await capabilityEvidence.evaluate((element) => element.hasAttribute('open'));
        assert(evidenceAutoExpanded === false, 'Expected capability evidence to stay collapsed by default even when reusable SPL candidates are present.');
        await capabilityEvidence.locator('summary').click();
        const evidenceExpandedAfterClick = await capabilityEvidence.evaluate((element) => element.hasAttribute('open'));
        assert(evidenceExpandedAfterClick === true, 'Expected capability evidence to expand after the user opens it.');
        const reusableQueryCard = page.getByTestId('chat-capability-reusable-query-card').first();
        await reusableQueryCard.waitFor({ state: 'visible' });
        const chatReuseBadgeText = ((await reusableQueryCard.getByTestId('chat-capability-reusable-query-reuse-tier').textContent()) || '').trim();
        assert(chatReuseBadgeText.includes('Reuse: Known Good'), `Expected reusable-query reuse badge, but received: ${chatReuseBadgeText}`);
        const chatFitBadgeText = ((await reusableQueryCard.getByTestId('chat-capability-reusable-query-fit-status').textContent()) || '').trim();
        assert(chatFitBadgeText.includes('Environment Fit: Strong'), `Expected reusable-query fit badge, but received: ${chatFitBadgeText}`);
        const chatValidationBadgeText = ((await reusableQueryCard.getByTestId('chat-capability-reusable-query-validation-status').textContent()) || '').trim();
        assert(chatValidationBadgeText.includes('Validation: Known Good'), `Expected reusable-query validation badge, but received: ${chatValidationBadgeText}`);
        const chatFeedbackBadgeText = ((await reusableQueryCard.getByTestId('chat-capability-reusable-query-feedback-counts').textContent()) || '').trim();
        assert(chatFeedbackBadgeText.includes('Observed Runs: 3 success / 1 failure'), `Expected reusable-query observed-run counts, but received: ${chatFeedbackBadgeText}`);
        const chatReusableQueryText = ((await reusableQueryCard.getByTestId('chat-capability-reusable-query').textContent()) || '').trim();
        assert(chatReusableQueryText.includes(libraryQuery), `Expected reusable-query card to include the saved query, but received: ${chatReusableQueryText}`);

        return {
            reportSplCardCount,
            libraryCardCount,
        };
    } finally {
        await page.close();
        await browser.close();
    }
}

async function runOperatorWorkflowRegression(baseUrl, seededRuntimeState) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    const pageErrors = [];
    const dialogMessages = [];
    const generatedArtifacts = [];
    page.on('pageerror', (error) => pageErrors.push(error instanceof Error ? error.message : String(error)));
    page.on('dialog', async (dialog) => {
        dialogMessages.push(`${dialog.type()}: ${dialog.message()}`);
        await dialog.accept();
    });

    try {
        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        await dismissWelcomeSplashIfPresent(page, { dontShowAgain: true });

        await page.locator('#workspace-tab-mission').click({ force: true });
        await page.getByText('Mission Handoff').waitFor({ state: 'visible' });
        await page.getByText('Discovery run completed').first().waitFor({ state: 'visible' });

        const buildPackageButton = page.getByRole('button', { name: 'Build Report Package' });
        await buildPackageButton.waitFor({ state: 'visible' });
        assert(!(await buildPackageButton.isDisabled()), 'Build Report Package is disabled; export tools are not ready.');

        const buildResponsePromise = page.waitForResponse((response) => {
            return response.url().endsWith('/api/capabilities/exports/build') && response.request().method() === 'POST';
        });
        await buildPackageButton.click();
        const buildResponse = await buildResponsePromise;
        assert(buildResponse.ok(), `Build Report Package returned HTTP ${buildResponse.status()}.`);
        const buildPayload = await buildResponse.json();
        const exportDetails = buildPayload?.details || {};
        const generatedFiles = Array.isArray(exportDetails.generated_files) ? exportDetails.generated_files : [];
        for (const fileName of generatedFiles) {
            generatedArtifacts.push(path.join(seededRuntimeState.exportDir, fileName));
        }

        await page.getByText('Current Report Package').first().waitFor({ state: 'visible' });
        await page.getByText('This package was built from the selected session and the active persona runbook.').waitFor({ state: 'visible' });

        await page.getByTestId('workspace-tab-discovery').click({ force: true });
        await page.getByText('Discovery Stage Ledger').waitFor({ state: 'visible' });

        const summaryAction = page.getByTestId('discovery-ledger-summary-action');
        await summaryAction.waitFor({ state: 'visible' });
        const summaryActionLabel = ((await summaryAction.textContent()) || '').trim();
        assert(summaryActionLabel.length > 0, 'Discovery ledger summary action did not render a usable label.');

        await expandDiscoveryReportHierarchy(page, 'cached summary session');
        const cachedSummaryButtons = page.getByTestId('discovery-report-session-toggle').locator('button').filter({ hasText: 'View Summary' });
        assert(await cachedSummaryButtons.count() > 0, `Expected at least one cached summary path in Discovery, but ledger action was "${summaryActionLabel}" and no View Summary buttons were available.`);
        const summaryResponsePromise = page.waitForResponse((response) => {
            return response.url().endsWith('/summarize-session') && response.request().method() === 'POST';
        });
        await cachedSummaryButtons.first().scrollIntoViewIfNeeded();
        await cachedSummaryButtons.first().click({ force: true });
        const summaryResponse = await summaryResponsePromise;
        assert(summaryResponse.ok(), `View Summary returned HTTP ${summaryResponse.status()}.`);

        const summaryTitle = page.locator('#summary-modal-title');
        await summaryTitle.waitFor({ state: 'visible' });
        await page.getByText('Priority Actions').first().waitFor({ state: 'visible' });
        await page.getByText('Quick Wins').first().waitFor({ state: 'visible' });
        const reviewLoopCount = await page.getByText(/Next Review Loop|Recursive Next Loop/i).count();
        assert(reviewLoopCount > 0, 'Summary dialog did not render a next-review section.');
        const summarySurfaceText = (await page.locator('body').textContent()) || '';
        assert(summarySurfaceText.includes(seededRuntimeState.latestSession.timestamp), 'Summary surface did not identify the seeded session.');

        await page.locator('#summary-tab-context').click();
        await page.locator('#summary-tabpanel-context').waitFor({ state: 'visible' });
        await page.locator('#summary-tab-queries').click();
        await page.locator('#summary-tabpanel-queries').waitFor({ state: 'visible' });
        await page.locator('#summary-tab-tasks').click();
        await page.locator('#summary-tabpanel-tasks').waitFor({ state: 'visible' });
        assert(dialogMessages.length === 0, `Expected first-party summary flow without native dialogs, but received: ${dialogMessages.join(' | ')}`);

        assert(pageErrors.length === 0, `Operator workflow regression encountered page errors: ${pageErrors.join(' | ')}`);

        return {
            bundleName: exportDetails.bundle_name || null,
            dialogCount: dialogMessages.length,
            sessionTimestamp: seededRuntimeState.latestSession.timestamp,
        };
    } finally {
        for (const artifactPath of generatedArtifacts) {
            await rm(artifactPath, { force: true });
        }
        await page.close();
        await browser.close();
    }
}

async function runActiveSummaryWorkerRegression(baseUrl, seededRuntimeState) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    const pageErrors = [];
    const dialogMessages = [];
    const summaryProgressPath = `${baseUrl}/summarize-progress/${seededRuntimeState.latestSession.timestamp}`;
    const summarizeSessionPath = `${baseUrl}/summarize-session`;
    const abortSummaryPath = `${baseUrl}/abort-summary`;
    const activeWorkerProgress = {
        session_id: seededRuntimeState.latestSession.timestamp,
        stage: 'ai_analysis',
        progress: 72,
        message: 'Worker-backed summary analysis is already running.',
        worker_pid: 424242,
        execution_mode: 'worker',
    };
    const abortedWorkerProgress = {
        ...activeWorkerProgress,
        stage: 'aborted',
        message: 'Summary aborted by operator.',
        worker_pid: null,
    };
    let summarizeSessionRequestCount = 0;
    let abortSummaryRequestCount = 0;

    page.on('pageerror', (error) => pageErrors.push(error instanceof Error ? error.message : String(error)));
    page.on('dialog', async (dialog) => {
        dialogMessages.push(`${dialog.type()}: ${dialog.message()}`);
        await dialog.accept();
    });

    try {
        await page.route(summaryProgressPath, async (route) => {
            await route.fulfill(jsonRoutePayload(activeWorkerProgress));
        });

        await page.route(summarizeSessionPath, async (route) => {
            summarizeSessionRequestCount += 1;
            await delay(5000);
            await route.fulfill(jsonRoutePayload({ detail: 'Request was expected to be aborted by the operator.' }, 504));
        });

        await page.route(abortSummaryPath, async (route) => {
            abortSummaryRequestCount += 1;
            await route.fulfill(jsonRoutePayload({ status: 'aborted', progress: abortedWorkerProgress }));
        });

        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        await dismissWelcomeSplashIfPresent(page, { dontShowAgain: true });
        await page.getByTestId('workspace-tab-discovery').click({ force: true });
        await page.getByText('Discovery Stage Ledger').waitFor({ state: 'visible' });

        await expandDiscoveryReportHierarchy(page, 'active summary worker session');
        const cachedSummaryButtons = page.getByTestId('discovery-report-session-toggle').locator('button').filter({ hasText: 'View Summary' });
        assert(await cachedSummaryButtons.count() > 0, 'Expected a cached summary entry for the active-summary worker regression.');
        await cachedSummaryButtons.first().scrollIntoViewIfNeeded();
        await cachedSummaryButtons.first().click({ force: true });

        await page.getByRole('dialog').waitFor({ state: 'visible' });
        await page.getByText('Reconnect to the running summary worker?').waitFor({ state: 'visible' });
        await page.getByText('Use the loading workspace Abort Summary control if you need to stop the worker after reconnecting.').waitFor({ state: 'visible' });

        const resumeSummaryButton = page.getByRole('button', { name: 'Resume Summary' });
        await resumeSummaryButton.click();

        await page.getByText('Analyzing Your Splunk Environment').waitFor({ state: 'visible' });
        await page.getByText('Connected to worker PID 424242. You can close the workspace and resume this summary later, or stop it now.').waitFor({ state: 'visible' });

        const abortSummaryButton = page.getByRole('button', { name: 'Abort Summary' });
        await abortSummaryButton.waitFor({ state: 'visible' });
        await abortSummaryButton.click();

        await page.getByText('Discovery Stage Ledger').waitFor({ state: 'visible' });
        await page.getByText('Reconnect to the running summary worker?').waitFor({ state: 'hidden' });
        assert(summarizeSessionRequestCount === 1, `Expected exactly one summarize-session request, received ${summarizeSessionRequestCount}.`);
        assert(abortSummaryRequestCount === 1, `Expected exactly one abort-summary request, received ${abortSummaryRequestCount}.`);
        assert(dialogMessages.length === 0, `Expected first-party summary worker flow without native dialogs, but received: ${dialogMessages.join(' | ')}`);
        assert(pageErrors.length === 0, `Active summary worker regression encountered page errors: ${pageErrors.join(' | ')}`);

        return {
            sessionTimestamp: seededRuntimeState.latestSession.timestamp,
            summarizeSessionRequestCount,
            abortSummaryRequestCount,
        };
    } finally {
        await page.unroute(summaryProgressPath);
        await page.unroute(summarizeSessionPath);
        await page.unroute(abortSummaryPath);
        await page.close();
        await browser.close();
    }
}

async function main() {
    let serverHandle = null;
    let seededRuntimeState = null;

    try {
        seededRuntimeState = await seedOperatorRuntimeState();
        const port = await findFreePort();
        const baseUrl = `http://127.0.0.1:${port}`;
        serverHandle = startServer(port);
        await waitForServer(baseUrl);

        const visualizationResult = await runBrowserRegression(baseUrl);
        const welcomeSplashResult = await runWelcomeSplashRegression(baseUrl);
        const workspaceResult = await runWorkspaceSmoke(baseUrl);
        const operatorResult = await runOperatorWorkflowRegression(baseUrl, seededRuntimeState);
        const activeSummaryWorkerResult = await runActiveSummaryWorkerRegression(baseUrl, seededRuntimeState);
        console.log(`Visualization browser regression passed: ${visualizationResult.barHeights.length} bars, ${visualizationResult.linePoints} line points, ${visualizationResult.truncatedLabels} truncated dense labels.`);
        console.log(`Welcome splash regression passed: persisted dismissal ${welcomeSplashResult.persistedDismissal ? 'verified' : 'not verified'}.`);
        console.log(`Workspace browser smoke passed: ${workspaceResult.reportSplCardCount} report SPL card and ${workspaceResult.libraryCardCount} SPL library card verified.`);
        console.log(`Operator workflow regression passed: Mission handoff, report package build, and cached summary verified for session ${operatorResult.sessionTimestamp}${operatorResult.bundleName ? ` using ${operatorResult.bundleName}` : ''}.`);
        console.log(`Active summary worker regression passed: resume and abort controls validated for session ${activeSummaryWorkerResult.sessionTimestamp}.`);
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
        if (seededRuntimeState) {
            await seededRuntimeState.restore();
        }
    }
}

await main();