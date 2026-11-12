// Opens every workspace view and dialog in each theme against seeded discovery output and fails when
// any visible text or placeholder falls below WCAG AA contrast (4.5:1, or 3:1 for large text) or
// renders smaller than 12px, when visible text breaks the plain-language rules below, or when a
// button sits inside a label. It also checks that choosing a theme in Settings applies and persists it.
// Set UI_CONTRAST_OUT to keep screenshots and a JSON report; UI_CONTRAST_THEMES limits the themes.
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

import {
    OPERATOR_FIXTURE_CREATED_AT,
    OPERATOR_FIXTURE_TIMESTAMP,
    buildCompletedDiscoveryPhasePlan,
    buildOperatorFixtureBlueprint,
    buildOperatorFixtureSummary,
} from './browser_fixtures.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const srcDir = path.join(repoRoot, 'src');
const outDir = process.env.UI_CONTRAST_OUT || '';
const width = 1440;
const height = 900;

const THEMES = {
    light: { preference: 'light', colorScheme: 'light' },
    dark: { preference: 'dark', colorScheme: 'dark' },
    neo: { preference: 'neo', colorScheme: 'dark' },
    'system-light': { preference: 'system', colorScheme: 'light' },
    'system-dark': { preference: 'system', colorScheme: 'dark' },
};
const themeNames = (process.env.UI_CONTRAST_THEMES || Object.keys(THEMES).join(','))
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean);
// A navigation change that silently skips a surface would otherwise let the gate pass.
const SEEDED_GOAL_TITLE = 'Sensor data gap';
const REQUIRED_SURFACES = [
    'welcome',
    'tab-overview',
    'tab-findings',
    'tab-m26-14',
    'tab-discovery',
    'tab-knowledge-base',
    'tab-capabilities',
    'discovery-report-open',
    'chat',
    'chat-settings',
    'chat-goal-library',
    'chat-goal',
    'connection-details',
    'settings-connections',
    'settings-connection-forms',
    'settings-save-mcp',
    'settings-save-llm',
    'settings-appearance',
];
// Visible text must not show raw identifiers, broken plurals, or retired names and jargon.
const LANGUAGE_RULES = [
    { label: 'old product name', pattern: /\bDT4SMS\b|Splunk MCP Discovery Tool/ },
    { label: 'old theme name', pattern: /\bConstruct\b/ },
    { label: 'raw session timestamp', pattern: /(?<![\w.])\d{8}_\d{6}(?![\w.])/ },
    { label: 'raw ISO timestamp', pattern: /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/ },
    { label: '"(s)" plural', pattern: /[a-z]\((?:s|es)\)/i },
    { label: 'doubled word', pattern: /\b([A-Za-z]{2,})\s+\1\b/i, perPiece: true },
    { label: 'placeholder value', pattern: /\bundefined\b|\bNaN\b|\[object Object\]/ },
    { label: 'jargon', pattern: /header monitor|control surface|asset plane|exec-control|operator-ready|non-authoritative|deterministic|\brecursive\b|\(demo\)|lorem ipsum/i },
];

// Rules marked perPiece run on one text node at a time, so a label next to a value that repeats it
// (an "Indexes" eyebrow above "Indexes added or removed.") is not read as a doubled word.
function languageProblems(pieces) {
    const found = [];
    const joined = pieces.join('\n');
    for (const rule of LANGUAGE_RULES) {
        for (const text of rule.perPiece ? pieces : [joined]) {
            const match = text.match(rule.pattern);
            if (match) {
                const start = Math.max(0, match.index - 40);
                found.push(`${rule.label}: "${text.slice(start, match.index + match[0].length + 40).replace(/\s+/g, ' ').trim()}"`);
                break;
            }
        }
    }
    return found;
}

function resolvePython() {
    return process.env.UI_CONTRAST_TEST_PYTHON
        || process.env.VISUALIZATION_BROWSER_TEST_PYTHON
        || process.env.FRONTEND_BUILD_PYTHON
        || 'python';
}

function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

async function waitForServer(url, logs, child) {
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) break;
        try {
            const response = await fetch(url);
            if (response.ok) return;
        } catch {
            // not up yet
        }
        await delay(300);
    }
    throw new Error(`Server did not start:\n${logs.join('').slice(-3000)}`);
}

async function seedOutput(outputDir) {
    const timestamp = OPERATOR_FIXTURE_TIMESTAMP;
    const createdAt = OPERATOR_FIXTURE_CREATED_AT;
    const completedAt = new Date().toISOString();
    const blueprint = buildOperatorFixtureBlueprint(timestamp, createdAt);
    const reports = {
        [`v2_intelligence_blueprint_${timestamp}.json`]: JSON.stringify(blueprint, null, 2),
        [`v2_insights_brief_${timestamp}.md`]: '# Intelligence Brief\n\n## Highest Value Gaps\n- Admin login failures are not tied to an explicit alert.\n',
        [`v2_operator_runbook_${timestamp}.md`]: '# Operator Runbook\n\n## Action Queue\n1. Validate authentication monitoring coverage (high)\n',
        [`v2_developer_handoff_${timestamp}.md`]: '# Developer Handoff\n\n## What this bundle contains\n- `intelligence_blueprint.json`\n  - **Readiness:** 78 of 100\n\n| Area | Status |\n| --- | --- |\n| Authentication | Needs an alert |\n\n> Advisory only.\n\n```spl\nindex=_internal | stats count by sourcetype\n```\n',
        [`v2_ai_summary_${timestamp}.json`]: JSON.stringify(buildOperatorFixtureSummary(timestamp), null, 2),
    };
    await mkdir(path.join(outputDir, 'exports'), { recursive: true });
    for (const [name, content] of Object.entries(reports)) {
        await writeFile(path.join(outputDir, name), content, 'utf8');
    }
    const reportPaths = Object.keys(reports);
    await writeFile(path.join(outputDir, 'discovery_sessions.json'), JSON.stringify([{
        timestamp,
        created_at: createdAt,
        overview: blueprint.overview,
        report_paths: reportPaths,
        readiness_score: blueprint.readiness_score,
        stats: { discovery_steps: 3, classification_groups: 1, recommendation_count: 1, suggested_use_case_count: 1 },
    }], null, 2), 'utf8');

    const activity = [
        ['banner', { title: 'Discovery run', subtitle: 'Environment analysis', start_time: '2026-05-22 01:02:03' }],
        ['phase', { title: 'Evidence Collection' }],
        ['info', { message: 'Collecting index and sourcetype inventory.' }],
        ['success', { message: 'Evidence collection complete.' }],
        ['warning', { message: 'One index returned no recent events.' }],
        ['error', { message: 'A saved search could not be read.' }],
        ['completion', { duration: '0:01:00', report_paths: reportPaths }],
    ].map(([type, data], index) => ({ id: `fixture-${index}`, type, data, timestamp: completedAt }));
    await writeFile(path.join(outputDir, 'runtime_state.json'), JSON.stringify({
        schema_version: 1,
        saved_at: completedAt,
        discovery_runtime_state: {
            status: 'completed',
            session_id: `contrast-${timestamp}`,
            pipeline_version: 'v2',
            started_at: createdAt,
            updated_at: completedAt,
            completed_at: completedAt,
            result_timestamp: timestamp,
            report_count: reportPaths.length,
            error: null,
            current_phase_key: 'artifact_packaging',
            current_phase_title: 'Save reports',
            phase_plan: buildCompletedDiscoveryPhasePlan(completedAt),
            activity_log: activity,
            last_run_outcome: {
                status: 'completed',
                title: 'Discovery run completed',
                summary: `Produced ${reportPaths.length} reports.`,
                completed_at: completedAt,
                result_timestamp: timestamp,
                report_count: reportPaths.length,
                phase_title: 'Save reports',
                error: null,
            },
            progress: { percentage: 100, current_step: 100, total_steps: 100, description: 'Complete.', eta_seconds: 0 },
        },
    }, null, 2), 'utf8');
}

// Runs in the page. Returns text and placeholder colors that fall below WCAG AA.
function auditContrast(rootSelector) {
    const roots = rootSelector ? [...document.querySelectorAll(rootSelector)].filter((node) => node.getClientRects().length) : [document.body];
    const root = roots[roots.length - 1] || document.body;
    const parse = (value) => {
        const match = String(value || '').match(/rgba?\(([^)]+)\)/);
        if (!match) return null;
        const parts = match[1].split(/[\s,/]+/).filter(Boolean).map(Number);
        return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
    };
    const white = { r: 255, g: 255, b: 255, a: 1 };
    const blend = (top, bottom) => {
        const alpha = top.a + bottom.a * (1 - top.a);
        if (alpha === 0) return { r: 0, g: 0, b: 0, a: 0 };
        const mix = (key) => (top[key] * top.a + bottom[key] * bottom.a * (1 - top.a)) / alpha;
        return { r: mix('r'), g: mix('g'), b: mix('b'), a: alpha };
    };
    const channel = (value) => {
        const v = value / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    const luminance = (c) => 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
    const contrast = (a, b) => {
        const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
        return (hi + 0.05) / (lo + 0.05);
    };
    const hex = (c) => `#${[c.r, c.g, c.b].map((v) => Math.round(v).toString(16).padStart(2, '0')).join('')}`;
    const backgrounds = (element) => {
        const layers = [];
        let base = null;
        for (let node = element; node && node.nodeType === 1; node = node.parentElement) {
            const style = getComputedStyle(node);
            const color = parse(style.backgroundColor);
            const image = style.backgroundImage;
            if (image && image.includes('gradient')) {
                const stops = (image.match(/rgba?\([^)]+\)/g) || []).map(parse).filter(Boolean);
                // Faint glows layered over an opaque gradient do not decide legibility; the opaque stops do.
                const opaque = stops.filter((stop) => stop.a >= 0.99);
                if (opaque.length) {
                    base = opaque;
                    break;
                }
            }
            if (color && color.a > 0) {
                if (color.a >= 1) {
                    base = [color];
                    break;
                }
                layers.push(color);
            }
        }
        if (!base) base = [white];
        return base.map((start) => layers.slice().reverse().reduce((acc, layer) => blend(layer, acc), start));
    };
    const opacity = (element) => {
        let value = 1;
        for (let node = element; node && node.nodeType === 1; node = node.parentElement) {
            value *= Number(getComputedStyle(node).opacity || 1);
        }
        return value;
    };
    const describe = (element) => {
        const parts = [];
        for (let node = element; node && node.nodeType === 1 && parts.length < 4; node = node.parentElement) {
            const testId = node.getAttribute('data-testid');
            let label = node.tagName.toLowerCase();
            if (testId) label += `[data-testid=${testId}]`;
            else if (node.id) label += `#${node.id}`;
            else if (typeof node.className === 'string' && node.className.trim()) label += `.${node.className.trim().split(/\s+/).slice(0, 3).join('.')}`;
            parts.unshift(label);
            if (testId || node.id) break;
        }
        return parts.join(' > ');
    };
    const visible = (element) => {
        if (element.checkVisibility && !element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
        const rect = element.getBoundingClientRect();
        return rect.width > 1 && rect.height > 1;
    };
    const failures = [];
    const small = [];
    let checked = 0;
    const check = (element, text, foreground, extra = {}) => {
        const style = getComputedStyle(element);
        const size = parseFloat(style.fontSize);
        const weight = Number(style.fontWeight) || 400;
        const large = size >= 24 || (size >= 18.66 && weight >= 700);
        const required = large ? 3 : 4.5;
        const fg = parse(foreground);
        if (!fg) return;
        fg.a *= opacity(element);
        const colors = backgrounds(element);
        const ratios = colors.map((color) => contrast(blend(fg, color), color));
        const ratio = Math.min(...ratios);
        const worst = colors[ratios.indexOf(ratio)];
        checked += 1;
        if (size < 12) small.push({ text: text.slice(0, 60), size, where: describe(element) });
        if (ratio < required) {
            failures.push({
                text: text.slice(0, 90),
                ratio: Math.round(ratio * 100) / 100,
                required,
                fg: hex(blend(fg, worst)),
                bg: hex(worst),
                size,
                weight,
                // WCAG exempts inactive controls from the contrast minimum.
                disabled: Boolean(element.closest('[disabled], [aria-disabled="true"]')),
                where: describe(element),
                ...extra,
            });
        }
    };
    const seen = new Set();
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
        const node = walker.currentNode;
        const text = (node.textContent || '').replace(/\s+/g, ' ').trim();
        const element = node.parentElement;
        if (!text || !element || seen.has(element) || ['SCRIPT', 'STYLE', 'NOSCRIPT', 'OPTION'].includes(element.tagName)) continue;
        seen.add(element);
        if (!visible(element)) continue;
        const style = getComputedStyle(element);
        check(element, text, element instanceof SVGElement ? style.fill : style.color);
    }
    for (const field of root.querySelectorAll('input[placeholder], textarea[placeholder]')) {
        if (field.value || !visible(field)) continue;
        check(field, `placeholder: ${field.placeholder}`, getComputedStyle(field, '::placeholder').color, { placeholder: true });
    }
    // Report bodies and code blocks show saved data as written, so only app copy is checked for wording.
    const copy = [];
    const copyWalker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (copyWalker.nextNode()) {
        const node = copyWalker.currentNode;
        const element = node.parentElement;
        const piece = (node.textContent || '').replace(/\s+/g, ' ').trim();
        if (!piece || !element || element.closest('pre, code, textarea, script, style, noscript')) continue;
        if (!visible(element.closest('select') || element)) continue;
        copy.push(piece);
    }
    // A label that wraps a button gives the button the label's name and clicks it when the label is clicked.
    const nestedControls = [...root.querySelectorAll('label button, label a[href]')].filter(visible).map(describe);
    return { checked, failures, small, copy, nestedControls, text: (root.innerText || '').replace(/\n{3,}/g, '\n\n').trim() };
}

async function settle(page, ms = 700) {
    await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
    await delay(ms);
}

async function clickIfPresent(locator, options = {}) {
    if (await locator.count() && await locator.first().isVisible().catch(() => false)) {
        await locator.first().click(options);
        return true;
    }
    return false;
}

// A goal with one answered and one open question and a saved chat, so the goal bar, its checklist, and the Goal Library are audited.
async function seedChatGoal(baseUrl) {
    const send = async (method, route, body) => {
        const response = await fetch(`${baseUrl}${route}`, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        if (!response.ok) throw new Error(`Could not seed the chat goal (${method} ${route}): HTTP ${response.status}`);
        return response.json();
    };
    const { goal } = await send('POST', '/api/chat/goals', { goal: 'Find out why sensor data stopped arriving', title: SEEDED_GOAL_TITLE });
    const goalRoute = `/api/chat/goals/${encodeURIComponent(goal.id)}`;
    const firstItem = goal.items[0];
    await send('PATCH', `${goalRoute}/items/${encodeURIComponent(firstItem.id)}`, { status: 'answered', note: 'The sensors index holds the data.' });
    await send('POST', `${goalRoute}/items`, { text: 'When did the last sensor event arrive?' });
    await send('PUT', `${goalRoute}/chats/chat_contrast_seed`, {
        messages: [
            { id: 1, type: 'user', content: 'Which index holds the sensor data?' },
            { id: 2, type: 'assistant', content: 'Sensor data is in the sensors index.' },
        ],
    });
}

async function closeDialogs(page) {
    for (let attempt = 0; attempt < 4; attempt += 1) {
        if (!(await page.locator('[role="dialog"]:visible').count())) return;
        await page.keyboard.press('Escape');
        await delay(250);
        const closers = page.locator('[role="dialog"]:visible button[aria-label^="Close"], [role="dialog"]:visible button:has-text("Close")');
        await clickIfPresent(closers.last()).catch(() => {});
        await delay(250);
    }
}

async function auditTheme(browser, baseUrl, themeName) {
    const theme = THEMES[themeName];
    if (!theme) throw new Error(`Unknown theme "${themeName}". Known: ${Object.keys(THEMES).join(', ')}`);
    const context = await browser.newContext({ viewport: { width, height }, colorScheme: theme.colorScheme, deviceScaleFactor: 1 });
    await context.addInitScript(({ preference }) => {
        window.localStorage.setItem('dt4sms_theme_preference', preference);
    }, theme);
    const page = await context.newPage();
    const pageErrors = [];
    const surfaces = [];
    page.on('pageerror', (error) => pageErrors.push(String(error)));
    page.on('dialog', (dialog) => dialog.dismiss().catch(() => {}));
    const capture = async (surface, rootSelector = null, fullPage = false) => {
        if (outDir) {
            await page.screenshot({ path: path.join(outDir, `${themeName}__${surface}.png`), fullPage }).catch(() => {});
        }
        surfaces.push({ theme: themeName, surface, ...(await page.evaluate(auditContrast, rootSelector)) });
    };

    try {
        await page.goto(`${baseUrl}/`, { waitUntil: 'domcontentloaded' });
        const splash = page.locator('[data-testid="welcome-splash-modal"]');
        await splash.waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
        await settle(page);
        if (await splash.isVisible().catch(() => false)) {
            await capture('welcome', '[data-testid="welcome-splash-modal"]');
            await splash.getByRole('button', { name: 'Get Started' }).click();
            await splash.waitFor({ state: 'hidden', timeout: 15000 }).catch(() => {});
        }

        for (const tab of ['overview', 'findings', 'm26-14', 'discovery', 'knowledge-base', 'capabilities']) {
            if (await clickIfPresent(page.locator(`#workspace-tab-${tab}`))) {
                await settle(page, 1200);
                await capture(`tab-${tab}`, null, true);
            }
        }

        await clickIfPresent(page.locator('#workspace-tab-discovery'));
        await settle(page);
        for (const testId of ['discovery-report-year-toggle', 'discovery-report-month-toggle', 'discovery-report-day-toggle', 'discovery-report-session-toggle']) {
            if (await page.getByTestId('discovery-report-row').count()) break;
            await clickIfPresent(page.getByTestId(testId), { force: true });
            await delay(300);
        }
        if (await clickIfPresent(page.getByTestId('discovery-report-row'))) {
            await settle(page, 1200);
            await capture('discovery-report-open', null, true);
        }
        if (await clickIfPresent(page.getByTestId('discovery-report-row').filter({ hasText: 'Developer handoff' }))) {
            await settle(page, 1200);
            await capture('discovery-report-markdown', null, true);
        }

        if (await clickIfPresent(page.locator('button', { hasText: 'View Summary' }))) {
            await settle(page, 1500);
            const summaryTabs = page.locator('[role="tablist"][aria-label="Summary views"] [role="tab"]');
            const count = await summaryTabs.count();
            for (let index = 0; index < count; index += 1) {
                const label = ((await summaryTabs.nth(index).innerText()) || `tab-${index}`).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '');
                await summaryTabs.nth(index).click();
                await settle(page, 800);
                await capture(`summary-${label}`, '[role="dialog"]');
            }
            await closeDialogs(page);
        }

        await clickIfPresent(page.locator('#workspace-tab-overview'));
        await settle(page);
        if (await clickIfPresent(page.getByRole('button', { name: 'Open chat', exact: true }))) {
            await settle(page, 1000);
            await capture('chat', '[role="dialog"]');
            if (await clickIfPresent(page.getByRole('button', { name: 'Open chat settings' }))) {
                await settle(page, 600);
                await capture('chat-settings', '[role="dialog"]');
            }
            await closeDialogs(page);
        }
        if (await clickIfPresent(page.getByRole('button', { name: 'Open chat', exact: true }))) {
            await settle(page, 1000);
            if (await clickIfPresent(page.getByRole('button', { name: 'Open the goal library' }))) {
                await settle(page, 800);
                await clickIfPresent(page.getByTestId('chat-goal-library').getByRole('button', { name: new RegExp(SEEDED_GOAL_TITLE) }));
                await settle(page, 800);
                await capture('chat-goal-library', '[data-testid="chat-goal-library"]');
                if (await clickIfPresent(page.getByTestId('chat-goal-library').getByRole('button', { name: 'Use in chat' }))) {
                    await settle(page, 800);
                    await clickIfPresent(page.getByTestId('chat-goal-progress-toggle'));
                    await settle(page, 400);
                    await capture('chat-goal', '[role="dialog"]');
                }
            }
            await closeDialogs(page);
        }

        if (await clickIfPresent(page.getByTestId('header-connection-status'))) {
            await settle(page, 600);
            await capture('connection-details', '.connection-popover');
            await closeDialogs(page);
            await page.mouse.click(5, height - 5);
        }

        if (await clickIfPresent(page.getByRole('button', { name: 'Open settings' }))) {
            await settle(page, 800);
            for (const tab of ['connections', 'users', 'access', 'appearance', 'troubleshoot']) {
                if (await clickIfPresent(page.getByTestId(`settings-tab-${tab}`))) {
                    await settle(page, 800);
                    await capture(`settings-${tab}`, '.settings-modal-shell');
                }
            }
            if (await clickIfPresent(page.getByTestId('settings-tab-connections'))) {
                await settle(page, 600);
                await clickIfPresent(page.getByRole('button', { name: 'Add MCP Server' }));
                await clickIfPresent(page.getByRole('button', { name: 'Add AI Model' }));
                await settle(page, 600);
                await capture('settings-connection-forms', '.settings-modal-shell');
                await page.locator('#mcp-url').fill('https://splunk.example.com:8089/services/mcp').catch(() => {});
                for (const [surface, button, titleId] of [
                    ['settings-save-mcp', 'Save as New Configuration', 'mcp-save-title'],
                    ['settings-save-llm', 'Save Connection', 'credential-save-title'],
                ]) {
                    if (await clickIfPresent(page.getByRole('button', { name: button, exact: true }))) {
                        await settle(page, 500);
                        await capture(surface, `[aria-labelledby="${titleId}"]`);
                        await clickIfPresent(page.locator(`[aria-labelledby="${titleId}"] button[aria-label="Close"]`));
                        await delay(250);
                    }
                }
            }
            await closeDialogs(page);
        }
    } finally {
        await context.close();
    }
    return { surfaces, pageErrors };
}

async function checkThemeSwitching(browser, baseUrl) {
    const problems = [];
    const context = await browser.newContext({ viewport: { width, height }, colorScheme: 'dark' });
    await context.addInitScript(() => {
        if (!window.sessionStorage.getItem('sdt-contrast-seeded')) {
            window.localStorage.setItem('dt4sms_theme_preference', 'light');
            window.sessionStorage.setItem('sdt-contrast-seeded', '1');
        }
    });
    const page = await context.newPage();
    const themeState = () => page.evaluate(() => ({
        theme: document.documentElement.getAttribute('data-theme'),
        scheme: document.documentElement.getAttribute('data-color-scheme'),
        saved: window.localStorage.getItem('dt4sms_theme_preference'),
    }));
    const expectState = async (label, expected) => {
        await page.waitForFunction(
            (theme) => document.documentElement.getAttribute('data-theme') === theme,
            expected.theme,
            { timeout: 5000 },
        ).catch(() => {});
        const state = await themeState();
        for (const [key, value] of Object.entries(expected)) {
            if (state[key] !== value) problems.push(`theme switching: after ${label}, ${key} is "${state[key]}" (expected "${value}")`);
        }
    };
    const dismissSplash = async () => {
        const splash = page.locator('[data-testid="welcome-splash-modal"]');
        await splash.waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
        if (await splash.isVisible().catch(() => false)) {
            await splash.getByRole('button', { name: 'Get Started' }).click();
            await splash.waitFor({ state: 'hidden', timeout: 15000 }).catch(() => {});
        }
    };
    try {
        await page.goto(`${baseUrl}/`, { waitUntil: 'domcontentloaded' });
        await dismissSplash();
        await expectState('loading with Light saved', { theme: 'light', scheme: 'light', saved: 'light' });
        await page.getByRole('button', { name: 'Open settings' }).click();
        await page.getByTestId('settings-tab-appearance').click();
        await page.getByTestId('settings-theme-option-neo').click();
        await expectState('choosing Neo', { theme: 'neo', scheme: 'dark', saved: 'neo' });
        await page.reload({ waitUntil: 'domcontentloaded' });
        await dismissSplash();
        await expectState('reloading with Neo saved', { theme: 'neo', scheme: 'dark', saved: 'neo' });
        await page.getByRole('button', { name: 'Open settings' }).click();
        await page.getByTestId('settings-tab-appearance').click();
        await page.getByTestId('settings-theme-option-system').click();
        await expectState('choosing System on a dark computer', { theme: 'dark', scheme: 'dark', saved: 'system' });
        const resolved = (await page.getByTestId('settings-theme-resolved').innerText().catch(() => '')).trim();
        if (!resolved.includes('Dark')) problems.push(`theme switching: System label reads "${resolved}" (expected it to name Dark)`);
        await page.emulateMedia({ colorScheme: 'light' });
        await expectState('the computer switching to light', { theme: 'light', scheme: 'light', saved: 'system' });
    } finally {
        await context.close();
    }
    return problems;
}
async function main() {
    const port = await freePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const workDir = await mkdtemp(path.join(os.tmpdir(), 'sdt-ui-contrast-'));
    await seedOutput(path.join(workDir, 'output'));
    if (outDir) {
        await rm(outDir, { recursive: true, force: true });
        await mkdir(outDir, { recursive: true });
    }
    const logs = [];
    const server = spawn(resolvePython(), ['-m', 'uvicorn', 'web_app:app', '--app-dir', srcDir, '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'], {
        cwd: workDir,
        env: { ...process.env, PYTHONUTF8: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    server.stdout.on('data', (chunk) => logs.push(chunk.toString()));
    server.stderr.on('data', (chunk) => logs.push(chunk.toString()));
    server.on('error', (error) => logs.push(`Failed to start server: ${error.message}\n`));

    const report = [];
    const problems = [];
    let browser = null;
    try {
        await waitForServer(`${baseUrl}/`, logs, server);
        // Turning on the M-26-14 module adds its tab, so the module tab and its page are audited too.
        for (const action of ['install', 'enable']) {
            const response = await fetch(`${baseUrl}/api/capabilities/m26_14_advisor/${action}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
            if (!response.ok) throw new Error(`Could not ${action} the M-26-14 module: HTTP ${response.status}`);
        }
        await seedChatGoal(baseUrl);
        browser = await chromium.launch({ headless: true });
        problems.push(...await checkThemeSwitching(browser, baseUrl));
        for (const themeName of themeNames) {
            const { surfaces, pageErrors } = await auditTheme(browser, baseUrl, themeName);
            report.push(...surfaces);
            const captured = new Set(surfaces.map((entry) => entry.surface));
            for (const surface of REQUIRED_SURFACES) {
                if (!captured.has(surface)) problems.push(`${themeName}: surface "${surface}" was not reached`);
            }
            if (!surfaces.some((entry) => entry.surface.startsWith('summary-'))) {
                problems.push(`${themeName}: summary dialog was not reached`);
            }
            for (const error of pageErrors) problems.push(`${themeName}: page error ${error}`);
            for (const entry of surfaces) {
                const enabled = entry.failures.filter((failure) => !failure.disabled);
                console.log(`${themeName.padEnd(12)} ${entry.surface.padEnd(30)} checked ${String(entry.checked).padStart(4)}  failures ${enabled.length}`);
                for (const failure of enabled) {
                    problems.push(`${themeName}/${entry.surface}: ${failure.ratio}:1 (needs ${failure.required}) ${failure.fg} on ${failure.bg} "${failure.text}" at ${failure.where}`);
                }
                for (const item of entry.small) {
                    problems.push(`${themeName}/${entry.surface}: ${item.size}px text "${item.text}" at ${item.where}`);
                }
                for (const issue of languageProblems(entry.copy || [])) {
                    problems.push(`${themeName}/${entry.surface}: ${issue}`);
                }
                for (const where of entry.nestedControls || []) {
                    problems.push(`${themeName}/${entry.surface}: control inside a label at ${where}`);
                }
            }
        }
    } finally {
        if (browser) await browser.close();
        server.kill('SIGTERM');
        await delay(500);
        await rm(workDir, { recursive: true, force: true }).catch(() => {});
    }

    if (outDir) {
        await writeFile(path.join(outDir, 'report.json'), JSON.stringify(report, null, 2));
    }
    if (problems.length) {
        console.error(`\nUI contrast check failed with ${problems.length} problem(s):`);
        for (const problem of problems) console.error(`- ${problem}`);
        process.exitCode = 1;
        return;
    }
    console.log(`\nUI contrast check passed: ${report.length} surfaces across ${themeNames.length} themes.`);
}

main().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exitCode = 1;
});
