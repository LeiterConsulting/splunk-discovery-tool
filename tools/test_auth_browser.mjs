import { spawn } from 'node:child_process';
import { createSign, generateKeyPairSync, randomUUID } from 'node:crypto';
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

const LOCAL_ADMIN_USERNAME = 'admin';
const LOCAL_ADMIN_INITIAL_PASSWORD = 'password';
const LOCAL_ADMIN_NEW_PASSWORD = 'Adm1nResetPass!';
const OIDC_CLIENT_ID = 'dt4sms-browser-client';
const OIDC_CLIENT_SECRET = 'dt4sms-browser-secret';
const OIDC_TEST_USER = {
    sub: 'oidc-admin-subject',
    preferred_username: 'oidc-admin',
    email: 'oidc-admin@example.com',
    roles: ['admin'],
};

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
        process.env.ACCOUNT_FUNCTION_TEST_PYTHON,
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

function startServer(pythonCommand, port, cwd) {
    const logs = { stdout: [], stderr: [] };
    const child = spawn(
        pythonCommand,
        ['-m', 'uvicorn', 'web_app:app', '--app-dir', srcDir, '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'],
        {
            cwd,
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

async function removeTempDir(targetPath, attempts = 6) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        try {
            await rm(targetPath, { recursive: true, force: true });
            return;
        } catch (error) {
            const errorCode = error && typeof error === 'object' ? error.code : '';
            const shouldRetry = errorCode === 'EBUSY' || errorCode === 'EPERM' || errorCode === 'ENOTEMPTY';
            if (!shouldRetry || attempt === attempts - 1) {
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

function runCommand(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            cwd: options.cwd || repoRoot,
            env: {
                ...process.env,
                PYTHONUTF8: process.env.PYTHONUTF8 || '1',
            },
            stdio: 'inherit',
        });

        child.once('error', reject);
        child.once('exit', (code) => {
            if (code === 0) {
                resolve();
                return;
            }
            reject(new Error(`${command} exited with code ${code ?? 'unknown'}`));
        });
    });
}

async function bootstrapSecurityConfig(tempDir, securityUpdate) {
    const python = await resolvePythonCommand();
    const payloadJson = JSON.stringify(securityUpdate);
    const script = [
        'import json, sys',
        `sys.path.insert(0, ${JSON.stringify(srcDir)})`,
        'from pathlib import Path',
        'from config_manager import ConfigManager',
        `root = Path(${JSON.stringify(tempDir)})`,
        `payload = json.loads(${JSON.stringify(payloadJson)})`,
        'manager = ConfigManager(str(root / "config.encrypted"))',
        'manager.update_security(**payload)',
    ].join('\n');

    await runCommand(python, ['-c', script], { cwd: tempDir });
}

function base64urlEncode(value) {
    const buffer = Buffer.isBuffer(value)
        ? value
        : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function signJwt(privateKey, payload, kid) {
    const header = { alg: 'RS256', typ: 'JWT', kid };
    const encodedHeader = base64urlEncode(header);
    const encodedPayload = base64urlEncode(payload);
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signer = createSign('RSA-SHA256');
    signer.update(signingInput);
    signer.end();
    const signature = signer.sign(privateKey);
    return `${signingInput}.${base64urlEncode(signature)}`;
}

async function readRequestBody(request) {
    return await new Promise((resolve, reject) => {
        let body = '';
        request.setEncoding('utf8');
        request.on('data', (chunk) => {
            body += chunk;
        });
        request.on('end', () => resolve(body));
        request.on('error', reject);
    });
}

function createJsonResponder(response, statusCode, payload) {
    response.writeHead(statusCode, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(payload));
}

async function startMockOidcProvider(port) {
    const issuerUrl = `http://127.0.0.1:${port}`;
    const keyId = 'dt4sms-browser-key';
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    const signingKey = {
        ...jwk,
        use: 'sig',
        alg: 'RS256',
        kid: keyId,
    };
    const authCodes = new Map();
    const accessTokens = new Map();
    const requestCounts = {
        authorize: 0,
        token: 0,
        userinfo: 0,
        endsession: 0,
    };

    const server = createServer(async (request, response) => {
        const url = new URL(request.url || '/', issuerUrl);

        if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
            createJsonResponder(response, 200, {
                issuer: issuerUrl,
                authorization_endpoint: `${issuerUrl}/authorize`,
                token_endpoint: `${issuerUrl}/token`,
                userinfo_endpoint: `${issuerUrl}/userinfo`,
                jwks_uri: `${issuerUrl}/jwks`,
                end_session_endpoint: `${issuerUrl}/endsession`,
            });
            return;
        }

        if (request.method === 'GET' && url.pathname === '/jwks') {
            createJsonResponder(response, 200, { keys: [signingKey] });
            return;
        }

        if (request.method === 'GET' && url.pathname === '/authorize') {
            requestCounts.authorize += 1;
            const state = url.searchParams.get('state') || '';
            const redirectUri = url.searchParams.get('redirect_uri') || '';
            const clientId = url.searchParams.get('client_id') || '';
            const nonce = url.searchParams.get('nonce') || '';
            assert(clientId === OIDC_CLIENT_ID, `Unexpected OIDC client_id: ${clientId || 'missing'}`);
            assert(redirectUri, 'OIDC authorize request did not include redirect_uri.');

            const code = randomUUID();
            authCodes.set(code, { clientId, nonce });

            const callbackUrl = new URL(redirectUri);
            callbackUrl.searchParams.set('code', code);
            callbackUrl.searchParams.set('state', state);
            response.writeHead(302, { Location: callbackUrl.toString() });
            response.end();
            return;
        }

        if (request.method === 'POST' && url.pathname === '/token') {
            requestCounts.token += 1;
            const body = await readRequestBody(request);
            const form = new URLSearchParams(body);
            const code = form.get('code') || '';
            const clientId = form.get('client_id') || '';
            const clientSecret = form.get('client_secret') || '';
            const state = authCodes.get(code);

            if (!state || clientId !== OIDC_CLIENT_ID || clientSecret !== OIDC_CLIENT_SECRET) {
                createJsonResponder(response, 400, { error: 'invalid_grant' });
                return;
            }

            authCodes.delete(code);
            const accessToken = randomUUID();
            accessTokens.set(accessToken, OIDC_TEST_USER);
            const now = Math.floor(Date.now() / 1000);
            const idToken = signJwt(
                privateKey,
                {
                    iss: issuerUrl,
                    sub: OIDC_TEST_USER.sub,
                    aud: [OIDC_CLIENT_ID],
                    exp: now + 300,
                    iat: now,
                    nonce: state.nonce,
                },
                keyId,
            );

            createJsonResponder(response, 200, {
                access_token: accessToken,
                token_type: 'Bearer',
                expires_in: 300,
                id_token: idToken,
            });
            return;
        }

        if (request.method === 'GET' && url.pathname === '/userinfo') {
            requestCounts.userinfo += 1;
            const authorization = request.headers.authorization || '';
            const accessToken = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : '';
            const claims = accessTokens.get(accessToken);
            if (!claims) {
                createJsonResponder(response, 401, { error: 'invalid_token' });
                return;
            }

            createJsonResponder(response, 200, claims);
            return;
        }

        if ((request.method === 'GET' || request.method === 'POST') && url.pathname === '/endsession') {
            requestCounts.endsession += 1;
            const redirectTarget = url.searchParams.get('post_logout_redirect_uri');
            if (redirectTarget) {
                response.writeHead(302, { Location: redirectTarget });
                response.end();
                return;
            }

            createJsonResponder(response, 200, { status: 'signed_out' });
            return;
        }

        response.writeHead(404);
        response.end('Not found');
    });

    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
    });

    return {
        issuerUrl,
        requestCounts,
        async close() {
            await new Promise((resolve, reject) => {
                server.close((error) => {
                    if (error) {
                        reject(error);
                        return;
                    }
                    resolve();
                });
            });
        },
    };
}

async function getAuthStatus(page) {
    return await page.evaluate(async () => {
        const response = await fetch('/api/auth/status', {
            headers: { Accept: 'application/json' },
        });
        return await response.json();
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

async function openSecurityAccessTab(page) {
    await page.getByRole('button', { name: 'Open settings' }).click();
    await page.getByRole('heading', { name: 'Settings' }).waitFor({ timeout: 30000 });
    await page.getByRole('button', { name: 'Users' }).click();
    await page.getByRole('heading', { name: 'Local Users' }).waitFor({ timeout: 30000 });
    await page.getByRole('button', { name: 'MCP/API & Tokens' }).click();
    await page.getByText('Install-wide Security Controls').waitFor({ timeout: 30000 });
    await page.getByRole('heading', { name: 'Access Tokens' }).waitFor({ timeout: 30000 });
}

async function openSecuritySettingsAndVerify(page) {
    await openSecurityAccessTab(page);
    await page.getByRole('button', { name: 'Close settings' }).click();
}

async function verifyHeaderAuthIndicator(page, options = {}) {
    const indicator = page.getByTestId('header-auth-indicator');
    const logoutButton = page.getByTestId('header-logout-button');

    await indicator.waitFor({ state: 'visible', timeout: 30000 });
    await logoutButton.waitFor({ state: 'visible', timeout: 30000 });

    const indicatorText = String((await indicator.textContent()) || '');
    assert(indicatorText.includes(`Signed in as ${options.username}`), `Header auth indicator did not include username '${options.username}'.`);
    if (options.role) {
        assert(indicatorText.includes(`${options.role} access`), `Header auth indicator did not include role '${options.role}'.`);
    }
    if (options.providerLabel) {
        assert(indicatorText.includes(options.providerLabel), `Header auth indicator did not include provider label '${options.providerLabel}'.`);
    }
}

async function verifyAuthEnableGuideFlow(page) {
    await openSecurityAccessTab(page);

    const authToggle = page.locator('[data-testid="settings-auth-enable-toggle"]');
    const authInfoButton = page.locator('[data-testid="settings-auth-enable-info-button"]');
    const authGuideModal = page.locator('[data-testid="auth-enable-info-modal"]');

    await authToggle.click();
    await authGuideModal.waitFor({ state: 'visible', timeout: 30000 });
    await page.getByRole('heading', { name: 'Review authentication methods before enabling access control' }).waitFor({ timeout: 30000 });
    await authGuideModal.getByRole('button', { name: 'Exit' }).first().click();
    await authGuideModal.waitFor({ state: 'hidden', timeout: 30000 });
    assert((await authToggle.getAttribute('aria-pressed')) === 'false', 'Auth toggle should remain off after exiting the guide.');

    await authInfoButton.click();
    await authGuideModal.waitFor({ state: 'visible', timeout: 30000 });
    await page.getByRole('button', { name: 'Mark as reviewed' }).click();
    await authGuideModal.waitFor({ state: 'hidden', timeout: 30000 });

    await authToggle.click();
    assert((await authToggle.getAttribute('aria-pressed')) === 'true', 'Auth toggle should turn on after the guide has been reviewed.');

    await page.getByRole('button', { name: 'Close settings' }).click();
}

async function runDemoModeAuthGuideScenario() {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-auth-guide-'));
    const port = await findFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const python = await resolvePythonCommand();
    let serverHandle = null;

    try {
        await bootstrapSecurityConfig(tempDir, {
            auth_enabled: false,
            auth_provider: 'local_password',
            session_timeout_minutes: 60,
            password_min_length: 12,
            require_password_reset_on_first_login: true,
        });

        serverHandle = startServer(python, port, tempDir);
        await waitForServer(baseUrl);

        await withBrowser(async (context) => {
            const page = await context.newPage();
            await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
            await dismissWelcomeSplashIfPresent(page, { dontShowAgain: true });
            await page.getByRole('button', { name: 'Open settings' }).waitFor({ timeout: 30000 });
            await verifyAuthEnableGuideFlow(page);
        });

        console.log('[auth-browser] Demo-mode auth guide flow passed.');
    } catch (error) {
        const serverLogs = serverHandle?.getLogs ? serverHandle.getLogs() : '';
        throw new Error(`Demo-mode auth guide flow failed: ${error instanceof Error ? error.message : String(error)}${serverLogs ? `\n${serverLogs}` : ''}`);
    } finally {
        await stopServer(serverHandle);
        await removeTempDir(tempDir);
    }
}

async function withBrowser(run) {
    const browser = await chromium.launch({ headless: true });
    try {
        const context = await browser.newContext({ viewport: { width: 1440, height: 980 } });
        try {
            return await run(context);
        } finally {
            await context.close();
        }
    } finally {
        await browser.close();
    }
}

async function runLocalPasswordScenario() {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-auth-local-'));
    const port = await findFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const python = await resolvePythonCommand();
    let serverHandle = null;

    try {
        await bootstrapSecurityConfig(tempDir, {
            auth_enabled: true,
            auth_provider: 'local_password',
            session_timeout_minutes: 60,
            password_min_length: 12,
            require_password_reset_on_first_login: true,
        });

        serverHandle = startServer(python, port, tempDir);
        await waitForServer(baseUrl);

        await withBrowser(async (context) => {
            const page = await context.newPage();
            await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
            await page.getByRole('heading', { name: 'DT4SMS Sign In' }).waitFor({ timeout: 30000 });
            await page.locator('#username').fill(LOCAL_ADMIN_USERNAME);
            await page.locator('#password').fill(LOCAL_ADMIN_INITIAL_PASSWORD);
            await page.getByRole('button', { name: 'Sign In' }).click();

            await page.getByRole('heading', { name: 'Reset Password' }).waitFor({ timeout: 30000 });
            await page.locator('#current_password').fill(LOCAL_ADMIN_INITIAL_PASSWORD);
            await page.locator('#new_password').fill(LOCAL_ADMIN_NEW_PASSWORD);
            await page.locator('#confirm_password').fill(LOCAL_ADMIN_NEW_PASSWORD);
            await page.getByRole('button', { name: 'Update Password' }).click();

            await page.getByRole('button', { name: 'Open settings' }).waitFor({ timeout: 30000 });
            await dismissWelcomeSplashIfPresent(page, { dontShowAgain: true });
            await openSecuritySettingsAndVerify(page);
            await verifyHeaderAuthIndicator(page, {
                username: LOCAL_ADMIN_USERNAME,
                role: 'admin',
                providerLabel: 'Local account',
            });

            const authStatus = await getAuthStatus(page);
            assert(authStatus.authenticated, 'Local auth flow did not create an authenticated session.');
            assert(authStatus.user?.username === LOCAL_ADMIN_USERNAME, 'Local auth flow did not retain the bootstrap admin user.');
            assert(authStatus.password_reset_required === false, 'Password reset should be cleared after updating the bootstrap password.');

            await page.getByTestId('header-logout-button').click();
            await page.getByRole('heading', { name: 'DT4SMS Sign In' }).waitFor({ timeout: 30000 });
            const postLogoutStatus = await getAuthStatus(page);
            assert(!postLogoutStatus.authenticated, 'Local logout should clear the session cookie.');
        });

        console.log('[auth-browser] Local-password browser flow passed.');
    } catch (error) {
        const serverLogs = serverHandle?.getLogs ? serverHandle.getLogs() : '';
        throw new Error(`Local-password browser flow failed: ${error instanceof Error ? error.message : String(error)}${serverLogs ? `\n${serverLogs}` : ''}`);
    } finally {
        await stopServer(serverHandle);
        await removeTempDir(tempDir);
    }
}

async function runOidcScenario() {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'dt4sms-auth-oidc-'));
    const appPort = await findFreePort();
    const providerPort = await findFreePort();
    const baseUrl = `http://127.0.0.1:${appPort}`;
    const python = await resolvePythonCommand();
    let serverHandle = null;
    let provider = null;

    try {
        provider = await startMockOidcProvider(providerPort);
        await bootstrapSecurityConfig(tempDir, {
            auth_enabled: true,
            auth_provider: 'oidc',
            session_timeout_minutes: 60,
            password_min_length: 12,
            oidc: {
                issuer_url: provider.issuerUrl,
                client_id: OIDC_CLIENT_ID,
                client_secret: OIDC_CLIENT_SECRET,
                scopes: ['openid', 'profile', 'email'],
                username_claim: 'preferred_username',
                email_claim: 'email',
                role_claim: 'roles',
                default_role: 'viewer',
                mcp_assignment_claim: '',
            },
        });

        serverHandle = startServer(python, appPort, tempDir);
        await waitForServer(baseUrl);

        await withBrowser(async (context) => {
            const page = await context.newPage();
            await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
            await page.getByRole('heading', { name: 'DT4SMS Sign In' }).waitFor({ timeout: 30000 });
            await page.locator('a.button').click();

            await page.getByRole('button', { name: 'Open settings' }).waitFor({ timeout: 30000 });
            await dismissWelcomeSplashIfPresent(page, { dontShowAgain: true });
            await openSecuritySettingsAndVerify(page);
            await verifyHeaderAuthIndicator(page, {
                username: OIDC_TEST_USER.preferred_username,
                role: 'admin',
                providerLabel: 'OpenID Connect',
            });

            const authStatus = await getAuthStatus(page);
            assert(authStatus.authenticated, 'OIDC flow did not create an authenticated session.');
            assert(authStatus.user?.username === OIDC_TEST_USER.preferred_username, 'OIDC flow did not provision the expected username.');
            assert(authStatus.user?.role === 'admin', 'OIDC flow did not apply the admin role claim.');

            await page.getByTestId('header-logout-button').click();
            await page.getByRole('heading', { name: 'DT4SMS Sign In' }).waitFor({ timeout: 30000 });
            const postLogoutStatus = await getAuthStatus(page);
            assert(!postLogoutStatus.authenticated, 'OIDC logout should clear the DT4SMS session cookie.');
        });

        assert(provider.requestCounts.authorize >= 1, 'OIDC browser flow never reached the authorize endpoint.');
        assert(provider.requestCounts.token >= 1, 'OIDC browser flow never exchanged an authorization code.');
        assert(provider.requestCounts.userinfo >= 1, 'OIDC browser flow never queried the userinfo endpoint.');
        assert(provider.requestCounts.endsession >= 1, 'OIDC browser flow never reached the provider end-session endpoint during header sign-out.');
        console.log('[auth-browser] OIDC browser flow passed.');
    } catch (error) {
        const serverLogs = serverHandle?.getLogs ? serverHandle.getLogs() : '';
        throw new Error(`OIDC browser flow failed: ${error instanceof Error ? error.message : String(error)}${serverLogs ? `\n${serverLogs}` : ''}`);
    } finally {
        await stopServer(serverHandle);
        if (provider) {
            await provider.close();
        }
        await removeTempDir(tempDir);
    }
}

async function main() {
    await runDemoModeAuthGuideScenario();
    await runLocalPasswordScenario();
    await runOidcScenario();
    console.log('[auth-browser] Browser auth matrix passed.');
}

main().catch((error) => {
    console.error(`[auth-browser] ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
});