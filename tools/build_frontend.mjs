import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { transform } from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, '..');
const staticRoot = join(repoRoot, 'src', 'static');
const vendorRoot = join(staticRoot, 'vendor');
const packageJson = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const runtimeScriptRefs = [
  '/static/vendor/react/react.production.min.js',
  '/static/vendor/react/react-dom.production.min.js',
  '/static/app.js',
];
const runtimeStyleRefs = [
  '/static/vendor/tailwind/tailwind.min.css',
  '/static/vendor/fontawesome/css/all.min.css',
];

function normalizeLineEndings(text) {
  return String(text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function sha256Text(text) {
  return createHash('sha256').update(normalizeLineEndings(text), 'utf8').digest('hex');
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function clearPath(path) {
  rmSync(path, { recursive: true, force: true });
}

function copyDirectory(sourceDir, destinationDir) {
  ensureDir(destinationDir);
  for (const entry of readdirSync(sourceDir)) {
    const sourcePath = join(sourceDir, entry);
    const destinationPath = join(destinationDir, entry);
    const sourceStats = statSync(sourcePath);
    if (sourceStats.isDirectory()) {
      copyDirectory(sourcePath, destinationPath);
      continue;
    }
    copyFileSync(sourcePath, destinationPath);
  }
}

function getBuildPython() {
  const candidates = [
    process.env.FRONTEND_BUILD_PYTHON,
    join(repoRoot, '.venv', 'Scripts', 'python.exe'),
    join(repoRoot, '.venv', 'bin', 'python'),
    'python',
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ['--version'], {
        cwd: repoRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return candidate;
    } catch {
      // Try the next candidate.
    }
  }

  throw new Error('Unable to find a Python executable for frontend rendering.');
}

function renderLegacyHtml() {
  const python = getBuildPython();
  return normalizeLineEndings(execFileSync(python, ['tools/render_frontend_template.py'], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 50 * 1024 * 1024,
  }));
}

function extractInlineScript(html) {
  const match = html.match(/<script type="text\/babel">([\s\S]*?)<\/script>\s*<\/body>/i);
  if (!match) {
    throw new Error('Unable to locate the inline Babel app source in the rendered frontend HTML.');
  }
  return match[1].trim();
}

function renderStaticIndex(html) {
  return html
    .replace(
      '<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>',
      '<script src="/static/vendor/react/react.production.min.js"></script>',
    )
    .replace(
      '<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>',
      '<script src="/static/vendor/react/react-dom.production.min.js"></script>',
    )
    .replace(/\s*<script src="https:\/\/unpkg.com\/@babel\/standalone\/babel\.min\.js"><\/script>\s*/i, '\n')
    .replace(
      '<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">',
      '<link href="/static/vendor/tailwind/tailwind.min.css" rel="stylesheet">',
    )
    .replace(
      '<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">',
      '<link href="/static/vendor/fontawesome/css/all.min.css" rel="stylesheet">',
    )
    .replace(/<script type="text\/babel">[\s\S]*?<\/script>/i, '    <script src="/static/app.js"></script>');
}

function resolvePackageAsset(relativePath) {
  return join(repoRoot, 'node_modules', ...relativePath.split('/'));
}

async function buildAppScript(appSource) {
  const transformed = await transform(appSource, {
    loader: 'jsx',
    jsxFactory: 'React.createElement',
    jsxFragment: 'React.Fragment',
    format: 'iife',
    target: 'es2019',
    charset: 'utf8',
  });
  return transformed.code;
}

async function main() {
  const html = renderLegacyHtml();
  const appSource = extractInlineScript(html);
  const appCode = await buildAppScript(appSource);
  const staticIndex = renderStaticIndex(html);
  const buildManifest = {
    built_at_utc: new Date().toISOString(),
    source: {
      legacy_html_sha256: sha256Text(html),
      app_source_sha256: sha256Text(appSource),
    },
    artifacts: {
      index_html_sha256: sha256Text(staticIndex),
      app_js_sha256: sha256Text(appCode),
    },
    runtime: {
      script_refs: runtimeScriptRefs,
      style_refs: runtimeStyleRefs,
    },
    toolchain: {
      react: packageJson.devDependencies.react,
      react_dom: packageJson.devDependencies['react-dom'],
      tailwindcss: packageJson.devDependencies.tailwindcss,
      fontawesome: packageJson.devDependencies['@fortawesome/fontawesome-free'],
      esbuild: packageJson.devDependencies.esbuild,
    },
  };

  clearPath(staticRoot);
  ensureDir(staticRoot);
  ensureDir(vendorRoot);
  ensureDir(join(vendorRoot, 'react'));
  ensureDir(join(vendorRoot, 'tailwind'));
  ensureDir(join(vendorRoot, 'fontawesome', 'css'));

  copyFileSync(
    resolvePackageAsset('react/umd/react.production.min.js'),
    join(vendorRoot, 'react', 'react.production.min.js'),
  );
  copyFileSync(
    resolvePackageAsset('react-dom/umd/react-dom.production.min.js'),
    join(vendorRoot, 'react', 'react-dom.production.min.js'),
  );
  copyFileSync(
    resolvePackageAsset('tailwindcss/dist/tailwind.min.css'),
    join(vendorRoot, 'tailwind', 'tailwind.min.css'),
  );
  copyFileSync(
    resolvePackageAsset('@fortawesome/fontawesome-free/css/all.min.css'),
    join(vendorRoot, 'fontawesome', 'css', 'all.min.css'),
  );
  copyDirectory(
    resolvePackageAsset('@fortawesome/fontawesome-free/webfonts'),
    join(vendorRoot, 'fontawesome', 'webfonts'),
  );

  writeFileSync(join(staticRoot, 'app.js'), appCode, 'utf8');
  writeFileSync(join(staticRoot, 'index.html'), staticIndex, 'utf8');
  writeFileSync(join(staticRoot, 'build-manifest.json'), `${JSON.stringify(buildManifest, null, 2)}\n`, 'utf8');

  process.stdout.write('Frontend build complete. Generated src/static assets.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});