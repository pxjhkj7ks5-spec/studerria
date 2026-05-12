#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');

function runGit(args, options = {}) {
  try {
    return execFileSync('git', args, {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', options.allowFailure ? 'pipe' : 'inherit'],
    });
  } catch (err) {
    if (options.allowFailure) {
      return '';
    }
    throw err;
  }
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), 'utf8'));
}

function fileExists(relativePath) {
  return fs.existsSync(path.join(repoRoot, relativePath));
}

function listTrackedFiles() {
  return runGit(['ls-files'])
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

function listIgnoredFiles() {
  return runGit(['status', '--ignored', '--short'], { allowFailure: true })
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('!! '))
    .map((line) => line.slice(3));
}

function countMatches(relativePath, patterns) {
  const absolutePath = path.join(repoRoot, relativePath);
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    return 0;
  }
  const source = fs.readFileSync(absolutePath, 'utf8');
  return patterns.reduce((count, pattern) => count + (source.match(pattern) || []).length, 0);
}

function classifyIgnoredArtifacts(ignoredFiles) {
  const protectedPatterns = [
    /^docker\/local\/\.env$/,
    /^docker\/local\/db\/init\/.*\.sql$/,
  ];
  const cleanupPatterns = [
    /(^|\/)\.DS_Store$/,
    /^\.local\//,
    /^output\//,
    /(^|\/)\.next\/?$/,
    /(^|\/)next-env\.d\.ts$/,
    /(^|\/)prisma\/.*\.db$/,
  ];

  return ignoredFiles.map((item) => {
    const protectedByPolicy = protectedPatterns.some((pattern) => pattern.test(item));
    const cleanupCandidate = !protectedByPolicy && cleanupPatterns.some((pattern) => pattern.test(item));
    return {
      path: item,
      cleanupCandidate,
      protectedByPolicy,
    };
  });
}

function auditServicePackages() {
  const servicesDir = path.join(repoRoot, 'services');
  if (!fs.existsSync(servicesDir)) {
    return [];
  }
  return fs.readdirSync(servicesDir)
    .filter((name) => fileExists(path.join('services', name, 'package.json')))
    .sort()
    .map((name) => {
      const packagePath = path.join('services', name, 'package.json');
      const lockPath = path.join('services', name, 'package-lock.json');
      const pkg = readJson(packagePath);
      const lock = fileExists(lockPath) ? readJson(lockPath) : null;
      const rootLockPackage = lock && lock.packages && lock.packages[''] ? lock.packages[''] : null;
      const issues = [];
      if (!lock) {
        issues.push('package-lock missing');
      } else {
        if (lock.name !== pkg.name) issues.push(`lock root name mismatch: ${lock.name} != ${pkg.name}`);
        if (rootLockPackage && rootLockPackage.name !== pkg.name) {
          issues.push(`lock package name mismatch: ${rootLockPackage.name} != ${pkg.name}`);
        }
        if (lock.version !== pkg.version) issues.push(`lock root version mismatch: ${lock.version} != ${pkg.version}`);
        if (rootLockPackage && rootLockPackage.version !== pkg.version) {
          issues.push(`lock package version mismatch: ${rootLockPackage.version} != ${pkg.version}`);
        }
      }
      return {
        service: name,
        packagePath,
        lockPath: fileExists(lockPath) ? lockPath : null,
        scripts: pkg.scripts || {},
        issues,
      };
    });
}

function auditTrackedStaleFiles(trackedFiles) {
  const stale = [];
  trackedFiles.forEach((file) => {
    if (!fileExists(file)) {
      return;
    }
    if (/CLAUDE\.md$/.test(file)) {
      stale.push({ path: file, reason: 'assistant-specific instruction file; review whether it belongs in this repo' });
    }
    if (/docker\/studerria\//.test(file)) {
      stale.push({ path: file, reason: 'older service-local deployment scaffold; current deploy target is docker/local' });
    }
  });
  if (fileExists('README.md') && !fs.readFileSync(path.join(repoRoot, 'README.md'), 'utf8').includes('/tg')) {
    stale.push({ path: 'README.md', reason: 'root README does not list every live sidecar route' });
  }
  return stale;
}

function auditLegacySurface(trackedFiles) {
  const legacyPatterns = [
    /\blegacy_/g,
    /\blegacy\b/gi,
    /compatibility/gi,
    /fallback/gi,
  ];
  return trackedFiles
    .filter((file) => /^(app\.js|lib\/|routes\/|middleware\/|views\/|migrations\/|scripts\/)/.test(file))
    .map((file) => ({
      path: file,
      matchCount: countMatches(file, legacyPatterns),
    }))
    .filter((item) => item.matchCount > 0)
    .sort((left, right) => right.matchCount - left.matchCount || left.path.localeCompare(right.path));
}

function buildReport() {
  const trackedFiles = listTrackedFiles();
  const ignoredFiles = listIgnoredFiles();
  const servicePackages = auditServicePackages();
  const ignoredArtifacts = classifyIgnoredArtifacts(ignoredFiles);
  const cleanupCandidates = ignoredArtifacts.filter((item) => item.cleanupCandidate);
  const protectedArtifacts = ignoredArtifacts.filter((item) => item.protectedByPolicy);
  const staleTrackedFiles = auditTrackedStaleFiles(trackedFiles);
  const legacySurface = auditLegacySurface(trackedFiles);

  return {
    generatedAt: new Date().toISOString(),
    mode: 'read-only',
    summary: {
      trackedFiles: trackedFiles.length,
      ignoredArtifacts: ignoredArtifacts.length,
      cleanupCandidates: cleanupCandidates.length,
      protectedArtifacts: protectedArtifacts.length,
      serviceCount: servicePackages.length,
      serviceIssues: servicePackages.reduce((count, service) => count + service.issues.length, 0),
      staleTrackedCandidates: staleTrackedFiles.length,
      legacyFilesWithMatches: legacySurface.length,
    },
    ignoredArtifacts,
    staleTrackedFiles,
    servicePackages,
    legacySurface: legacySurface.slice(0, 40),
    nextSteps: [
      'Delete only cleanupCandidate ignored artifacts; keep protected artifacts such as .env and SQL dumps.',
      'Review staleTrackedFiles before deleting any tracked file.',
      'Use scripts/legacy-archive.js --dry-run before planning destructive legacy migrations.',
    ],
  };
}

function printHuman(report) {
  console.log('Repo cleanup audit');
  console.log(`Generated: ${report.generatedAt}`);
  console.log('');
  console.log('Summary');
  Object.entries(report.summary).forEach(([key, value]) => {
    console.log(`- ${key}: ${value}`);
  });
  console.log('');
  console.log('Cleanup candidates');
  report.ignoredArtifacts
    .filter((item) => item.cleanupCandidate)
    .forEach((item) => console.log(`- ${item.path}`));
  console.log('');
  console.log('Protected ignored artifacts');
  report.ignoredArtifacts
    .filter((item) => item.protectedByPolicy)
    .forEach((item) => console.log(`- ${item.path}`));
  console.log('');
  console.log('Service package issues');
  report.servicePackages
    .filter((service) => service.issues.length)
    .forEach((service) => console.log(`- ${service.service}: ${service.issues.join('; ')}`));
  console.log('');
  console.log('Top legacy surface');
  report.legacySurface.slice(0, 12).forEach((item) => console.log(`- ${item.path}: ${item.matchCount}`));
}

const report = buildReport();
if (process.argv.includes('--json')) {
  console.log(JSON.stringify(report, null, 2));
} else {
  printHuman(report);
}
