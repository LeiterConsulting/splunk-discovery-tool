import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

const ACCOUNT_FUNCTION_UNIT_TESTS = [
    'tests.test_security_access.SecurityManagerTests',
    'tests.test_security_access.WebAppLocalAuthTests.test_demo_mode_leaves_config_access_available',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_config_can_be_enabled_when_ready',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_flow_provisions_session_backed_user',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_reuses_cached_jwks_across_repeated_sign_ins',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_refreshes_cached_jwks_after_signing_key_rotation',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_ignores_non_verify_jwks_keys_without_use',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_accepts_ps256_signed_id_token',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_accepts_es256_signed_id_token',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_accepts_eddsa_signed_id_token',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_encrypted_id_token_before_jwks_or_userinfo',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_symmetric_id_token_before_jwks_or_userinfo',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_logout_returns_provider_logout_guidance_when_supported',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_unsupported_token_type',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_id_token_with_mismatched_nonce',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_unsecured_id_token_algorithm',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_id_token_with_invalid_signature',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_rejects_userinfo_subject_mismatch_with_id_token',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_relogin_without_explicit_claims_preserves_existing_role_and_assignment',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_relogin_with_empty_or_unsupported_claims_preserves_existing_role_and_assignment',
    'tests.test_security_access.WebAppLocalAuthTests.test_oidc_callback_username_collision_provisions_distinct_external_user',
    'tests.test_security_access.WebAppLocalAuthTests.test_admin_can_link_local_user_to_oidc_identity_before_callback_login',
    'tests.test_security_access.WebAppLocalAuthTests.test_auth_enabled_requires_login_then_password_reset_before_normal_access',
    'tests.test_security_access.WebAppLocalAuthTests.test_admin_user_crud_and_mcp_assignment_flow',
    'tests.test_security_access.WebAppLocalAuthTests.test_runtime_mcp_selection_uses_assignment_for_runtime_endpoints',
    'tests.test_security_access.WebAppLocalAuthTests.test_admin_token_lifecycle_endpoints',
    'tests.test_security_access.WebAppLocalAuthTests.test_security_config_rejects_invalid_ranges',
    'tests.test_security_access.WebAppLocalAuthTests.test_admin_security_endpoints_reject_invalid_assignments_and_non_admin_token_access',
];

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

function runCommand(command, args, label) {
    return new Promise((resolve, reject) => {
        console.log(`\n[account-tests] ${label}`);
        console.log(`> ${command} ${args.join(' ')}`);

        const child = spawn(command, args, {
            cwd: repoRoot,
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
            reject(new Error(`${label} failed with exit code ${code ?? 'unknown'}`));
        });
    });
}

async function main() {
    const args = new Set(process.argv.slice(2));
    const unitOnly = args.has('--unit-only');
    const browserOnly = args.has('--browser-only');

    if (unitOnly && browserOnly) {
        throw new Error('Choose either --unit-only or --browser-only, not both.');
    }

    const python = await resolvePythonCommand();

    if (!browserOnly) {
        await runCommand(
            python,
            ['-m', 'unittest', ...ACCOUNT_FUNCTION_UNIT_TESTS],
            'Running security/auth unittest matrix',
        );
    }

    if (!unitOnly) {
        await runCommand(
            process.execPath,
            [path.join(repoRoot, 'tools', 'test_auth_browser.mjs')],
            'Running browser auth flows',
        );
    }

    console.log('\n[account-tests] Account-function matrix passed.');
}

main().catch((error) => {
    console.error(`\n[account-tests] ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
});