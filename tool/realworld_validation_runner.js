#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const workspaceRoot = path.resolve(__dirname, '..');
const cliPrefix = path.join(workspaceRoot, 'vscode-extension');
const runStamp = new Date().toISOString().replace(/[:.]/g, '-');
const runRoot = path.join(workspaceRoot, 'validation_runs', `realworld_${runStamp}`);
const repoRoot = path.join(runRoot, 'repositories');
const outputRoot = path.join(runRoot, 'outputs');
const manifestJsonPath = path.join(runRoot, 'copied_repositories_for_future_deletion.json');
const manifestMdPath = path.join(runRoot, 'copied_repositories_for_future_deletion.md');
const desktopReportPath = path.join(os.homedir(), 'Desktop', 'sast_test_report.md');
const npmCache = '/tmp/flutter-supabase-helper-npm-cache';

const cloneTimeoutMs = 6 * 60 * 1000;
const scanTimeoutMs = 5 * 60 * 1000;
const validateTimeoutMs = 3 * 60 * 1000;

const repos = [
  {
    category: 'Flutter / Dart',
    name: 'AppFlowy',
    url: 'https://github.com/AppFlowy-IO/AppFlowy.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'localsend',
    url: 'https://github.com/localsend/localsend.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'supabase-flutter',
    url: 'https://github.com/supabase/supabase-flutter.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'flutterfire',
    url: 'https://github.com/firebase/flutterfire.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'melos',
    url: 'https://github.com/invertase/melos.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'flutter-permission-handler',
    url: 'https://github.com/Baseflow/flutter-permission-handler.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'flutter-geolocator',
    url: 'https://github.com/Baseflow/flutter-geolocator.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'plus_plugins',
    url: 'https://github.com/fluttercommunity/plus_plugins.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'Best-Flutter-UI-Templates',
    url: 'https://github.com/mitesh77/Best-Flutter-UI-Templates.git',
  },
  {
    category: 'Flutter / Dart',
    name: 'fl_chart',
    url: 'https://github.com/imaNNeo/fl_chart.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'express',
    url: 'https://github.com/expressjs/express.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'fastify',
    url: 'https://github.com/fastify/fastify.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'axios',
    url: 'https://github.com/axios/axios.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'socket.io',
    url: 'https://github.com/socketio/socket.io.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'nest',
    url: 'https://github.com/nestjs/nest.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'remix',
    url: 'https://github.com/remix-run/remix.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'vue-core',
    url: 'https://github.com/vuejs/core.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'react',
    url: 'https://github.com/facebook/react.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'preact',
    url: 'https://github.com/preactjs/preact.git',
  },
  {
    category: 'Node.js / JavaScript',
    name: 'webpack',
    url: 'https://github.com/webpack/webpack.git',
  },
  {
    category: 'Python',
    name: 'django',
    url: 'https://github.com/django/django.git',
  },
  {
    category: 'Python',
    name: 'flask',
    url: 'https://github.com/pallets/flask.git',
  },
  {
    category: 'Python',
    name: 'fastapi',
    url: 'https://github.com/fastapi/fastapi.git',
  },
  {
    category: 'Python',
    name: 'requests',
    url: 'https://github.com/psf/requests.git',
  },
  {
    category: 'Python',
    name: 'scrapy',
    url: 'https://github.com/scrapy/scrapy.git',
  },
  {
    category: 'Python',
    name: 'celery',
    url: 'https://github.com/celery/celery.git',
  },
  {
    category: 'Python',
    name: 'pip',
    url: 'https://github.com/pypa/pip.git',
  },
  {
    category: 'Python',
    name: 'sqlalchemy',
    url: 'https://github.com/sqlalchemy/sqlalchemy.git',
  },
  {
    category: 'Python',
    name: 'django-rest-framework',
    url: 'https://github.com/encode/django-rest-framework.git',
  },
  {
    category: 'Python',
    name: 'pytest',
    url: 'https://github.com/pytest-dev/pytest.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'supabase',
    url: 'https://github.com/supabase/supabase.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'appwrite',
    url: 'https://github.com/appwrite/appwrite.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'cal.com',
    url: 'https://github.com/calcom/cal.com.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'mattermost',
    url: 'https://github.com/mattermost/mattermost.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'outline',
    url: 'https://github.com/outline/outline.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'formbricks',
    url: 'https://github.com/formbricks/formbricks.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'twenty',
    url: 'https://github.com/twentyhq/twenty.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'actual',
    url: 'https://github.com/actualbudget/actual.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'novu',
    url: 'https://github.com/novuhq/novu.git',
  },
  {
    category: 'Mixed / full-stack',
    name: 'nocodb',
    url: 'https://github.com/nocodb/nocodb.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'OWASP-NodeGoat',
    url: 'https://github.com/OWASP/NodeGoat.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'juice-shop',
    url: 'https://github.com/juice-shop/juice-shop.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'WebGoat',
    url: 'https://github.com/WebGoat/WebGoat.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'OWASP-railsgoat',
    url: 'https://github.com/OWASP/railsgoat.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'OWASP-SecurityShepherd',
    url: 'https://github.com/OWASP/SecurityShepherd.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'dvna',
    url: 'https://github.com/appsecco/dvna.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'DVWA',
    url: 'https://github.com/digininja/DVWA.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'DSVW',
    url: 'https://github.com/stamparm/DSVW.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'vulhub',
    url: 'https://github.com/vulhub/vulhub.git',
  },
  {
    category: 'Intentionally vulnerable',
    name: 'OWASP-Vulnerable-Web-Application',
    url: 'https://github.com/OWASP/Vulnerable-Web-Application.git',
  },
];

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function quote(value) {
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) {
    return value;
  }
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function commandLine(command, args, env = {}) {
  const envPrefix = Object.entries(env)
    .map(([key, value]) => `${key}=${quote(value)}`)
    .join(' ');
  const base = [command, ...args].map(quote).join(' ');
  return envPrefix ? `${envPrefix} ${base}` : base;
}

function runCommand({ command, args, cwd, stdoutPath, stderrPath, timeoutMs, env = {} }) {
  return new Promise((resolve) => {
    ensureDir(path.dirname(stdoutPath));
    const stdout = fs.createWriteStream(stdoutPath);
    const stderr = fs.createWriteStream(stderrPath);
    const startedAt = Date.now();
    let settled = false;
    let timedOut = false;
    let spawnError = null;

    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    }, timeoutMs);

    child.stdout.pipe(stdout);
    child.stderr.pipe(stderr);

    child.on('error', (err) => {
      spawnError = err;
    });

    child.on('close', (code, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      stdout.end();
      stderr.end();
      resolve({
        commandLine: commandLine(command, args, env),
        cwd,
        exitCode: code,
        signal,
        timedOut,
        durationMs: Date.now() - startedAt,
        stdoutPath,
        stderrPath,
        error: spawnError ? spawnError.message : null,
      });
    });
  });
}

function readFileIfExists(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function parseJsonOutput(text) {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false, value: null, error: 'empty stdout' };
  }
  try {
    return { ok: true, value: JSON.parse(trimmed), error: null };
  } catch (strictError) {
    const first = trimmed.indexOf('{');
    const last = trimmed.lastIndexOf('}');
    if (first !== -1 && last > first) {
      try {
        return {
          ok: true,
          value: JSON.parse(trimmed.slice(first, last + 1)),
          error: `strict JSON parse failed, parsed JSON object inside stdout: ${strictError.message}`,
        };
      } catch (fallbackError) {
        return { ok: false, value: null, error: fallbackError.message };
      }
    }
    return { ok: false, value: null, error: strictError.message };
  }
}

function countBy(items, keyFn) {
  const counts = {};
  for (const item of items) {
    const key = keyFn(item) || 'unknown';
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function topEntries(counts, limit, ascending = false) {
  return Object.entries(counts)
    .sort((a, b) => ascending ? a[1] - b[1] || a[0].localeCompare(b[0]) : b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit);
}

function formatJson(value) {
  return JSON.stringify(value || {});
}

function findingLabel(finding) {
  const location = finding.filePath ? `${finding.filePath}${finding.line ? `:${finding.line}` : ''}` : 'unknown location';
  const confidence = finding.confidence ? `, confidence=${finding.confidence}` : '';
  return `[${finding.severity || 'unknown'}${confidence}] ${finding.code || 'unknown'} ${location} - ${finding.message || ''}`;
}

function avg(values) {
  if (values.length === 0) {
    return 0;
  }
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function pct(numerator, denominator) {
  if (!denominator) {
    return '0%';
  }
  return `${Math.round((numerator / denominator) * 1000) / 10}%`;
}

function noisePathMatch(filePath) {
  if (!filePath) {
    return false;
  }
  return /(^|\/)(test|tests|spec|specs|fixture|fixtures|example|examples|demo|demos|sample|samples|docs|documentation|benchmark|benchmarks)(\/|$)/i.test(filePath);
}

function buildReport(results, failures, manifest) {
  const successful = results.filter((r) => r.scanSuccess);
  const allFindings = successful.flatMap((r) => r.findings || []);
  const totalFindings = successful.reduce((sum, r) => sum + r.stats.totalIssues, 0);
  const totalHigh = successful.reduce((sum, r) => sum + r.stats.high, 0);
  const totalMedium = successful.reduce((sum, r) => sum + r.stats.medium, 0);
  const totalLow = successful.reduce((sum, r) => sum + r.stats.low, 0);
  const avgFindingsAllRepos = repos.length ? totalFindings / repos.length : 0;
  const avgAstSuccess = avg(successful.map((r) => Number(r.stats.astSuccessRate || 0)));
  const byRule = countBy(allFindings, (f) => f.code);
  const byConfidence = countBy(allFindings, (f) => f.confidence);
  const highConfidence = byConfidence.high || 0;
  const lowConfidence = byConfidence.low || 0;
  const highLowRatio = lowConfidence === 0 ? `${highConfidence}:0` : `${Math.round((highConfidence / lowConfidence) * 100) / 100}:1`;
  const noiseCandidates = allFindings.filter((f) => noisePathMatch(f.filePath));
  const validationFailures = results.filter((r) => r.validate && r.validate.exitCode !== 0).length;
  const astFailureAggregate = {};
  for (const result of successful) {
    for (const [language, count] of Object.entries(result.stats.astFailuresByLanguage || {})) {
      astFailureAggregate[language] = (astFailureAggregate[language] || 0) + count;
    }
  }
  const topHighConfidenceRules = topEntries(countBy(allFindings.filter((f) => f.confidence === 'high'), (f) => f.code), 5);
  const topRules = topEntries(byRule, 10);
  const leastRules = topEntries(byRule, 10, true);

  const lines = [];
  lines.push('# Flutter Supabase Helper Real-World SAST Validation Report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`CLI package path: ${cliPrefix}`);
  lines.push(`Run artifacts: ${runRoot}`);
  lines.push(`Deletion manifest JSON: ${manifestJsonPath}`);
  lines.push(`Deletion manifest Markdown: ${manifestMdPath}`);
  lines.push('');
  lines.push('## 1. Summary');
  lines.push('');
  lines.push(`- total repos tested: ${repos.length}`);
  lines.push(`- successful scans: ${successful.length}`);
  lines.push(`- total findings across all repos: ${totalFindings}`);
  lines.push(`- high findings: ${totalHigh}`);
  lines.push(`- medium findings: ${totalMedium}`);
  lines.push(`- low findings: ${totalLow}`);
  lines.push(`- average findings per repo: ${Math.round(avgFindingsAllRepos * 100) / 100}`);
  lines.push(`- average AST success rate: ${Math.round(avgAstSuccess * 100) / 100}%`);
  lines.push(`- error count: ${failures.length}`);
  lines.push(`- validation command failures: ${validationFailures}`);
  lines.push(`- validation requirement, at least 50 repos processed: ${results.length >= 50 ? 'PASS' : 'FAIL'} (${results.length})`);
  lines.push(`- validation requirement, at least 40 successful scans: ${successful.length >= 40 ? 'PASS' : 'FAIL'} (${successful.length})`);
  lines.push('');
  lines.push('Category coverage:');
  const categoryCounts = countBy(results, (r) => r.category);
  for (const [category, count] of Object.entries(categoryCounts)) {
    lines.push(`- ${category}: ${count}`);
  }
  lines.push('');
  lines.push('## 2. Per-Repo Results');
  lines.push('');

  for (const result of results) {
    lines.push(`### Repo: ${result.name}`);
    lines.push(`Category: ${result.category}`);
    lines.push(`URL: ${result.url}`);
    lines.push(`Commit: ${result.commit || 'FAILED'}`);
    lines.push(`Local Copy: ${result.localPath}`);
    lines.push('');
    if (result.scanSuccess) {
      lines.push(`Files: ${result.stats.totalFiles}`);
      lines.push(`Issues: ${result.stats.totalIssues}`);
      lines.push(`High: ${result.stats.high}`);
      lines.push(`Medium: ${result.stats.medium}`);
      lines.push(`Low: ${result.stats.low}`);
      lines.push('');
      lines.push(`AST Success Rate: ${result.stats.astSuccessRate}%`);
      lines.push(`AST Failures: ${formatJson(result.stats.astFailuresByLanguage)}`);
      lines.push('');
      lines.push('Top Findings:');
      const topFindings = (result.findings || []).slice(0, 5);
      if (topFindings.length === 0) {
        lines.push('- None');
      } else {
        for (const finding of topFindings) {
          lines.push(`- ${findingLabel(finding)}`);
        }
      }
      lines.push('');
      lines.push(`Scan Time: ${result.stats.scanDurationMs} ms`);
      lines.push(`Scan CLI Wall Time: ${result.scan.durationMs} ms`);
      lines.push(`Raw Scan Stdout: ${result.scan.stdoutPath}`);
      lines.push(`Raw Scan Stderr: ${result.scan.stderrPath}`);
    } else {
      lines.push('Files: FAILED');
      lines.push('Issues: FAILED');
      lines.push('High: FAILED');
      lines.push('Medium: FAILED');
      lines.push('Low: FAILED');
      lines.push('');
      lines.push('AST Success Rate: FAILED');
      lines.push('AST Failures: FAILED');
      lines.push('');
      lines.push('Top Findings:');
      lines.push('- FAILED');
      lines.push('');
      lines.push('Scan Time: FAILED');
      if (result.scan) {
        lines.push(`Raw Scan Stdout: ${result.scan.stdoutPath}`);
        lines.push(`Raw Scan Stderr: ${result.scan.stderrPath}`);
      }
    }
    lines.push('');
    lines.push('Validation Mode:');
    if (result.validate) {
      lines.push(`- Exit Code: ${result.validate.exitCode}`);
      lines.push(`- Duration: ${result.validate.durationMs} ms`);
      lines.push(`- Timed Out: ${result.validate.timedOut ? 'yes' : 'no'}`);
      lines.push(`- Raw Validate Stdout: ${result.validate.stdoutPath}`);
      lines.push(`- Raw Validate Stderr: ${result.validate.stderrPath}`);
    } else {
      lines.push('- Not run because clone or commit step failed.');
    }
    lines.push('');
    lines.push('Notes:');
    const notes = [];
    if (result.clone && result.clone.exitCode !== 0) {
      notes.push('repo clone failed');
    }
    if (result.revParse && result.revParse.exitCode !== 0) {
      notes.push('commit hash command failed');
    }
    if (result.scan && result.scan.timedOut) {
      notes.push('scan timed out');
    }
    if (result.scan && result.scan.exitCode !== 0) {
      notes.push(`scan exited non-zero (${result.scan.exitCode})`);
    }
    if (result.scanJsonError) {
      notes.push(`scan JSON parse note/error: ${result.scanJsonError}`);
    }
    if (result.scanSuccess && result.stats.scanDurationMs > 30000) {
      notes.push('performance issue: scanner-reported duration exceeded 30000 ms');
    }
    if (result.scanSuccess && result.scan.durationMs > 30000) {
      notes.push('performance issue: CLI wall time exceeded 30000 ms');
    }
    if (result.scanSuccess && (result.findings || []).some((f) => noisePathMatch(f.filePath))) {
      notes.push('suspicious noise candidate: at least one finding is in a docs/test/example/demo/fixture/sample path');
    }
    if (result.validate && result.validate.exitCode !== 0) {
      notes.push(`validation command exited non-zero (${result.validate.exitCode})`);
    }
    if (result.validate && result.validate.timedOut) {
      notes.push('validation command timed out');
    }
    if (notes.length === 0) {
      notes.push('none');
    }
    for (const note of notes) {
      lines.push(`- ${note}`);
    }
    lines.push('');
  }

  lines.push('## 3. Failure Log');
  lines.push('');
  if (failures.length === 0) {
    lines.push('- None');
  } else {
    for (const failure of failures) {
      lines.push(`- Repo: ${failure.repo}; Step: ${failure.step}; Detail: ${failure.detail}`);
      if (failure.stdoutPath) {
        lines.push(`  Stdout: ${failure.stdoutPath}`);
      }
      if (failure.stderrPath) {
        lines.push(`  Stderr: ${failure.stderrPath}`);
      }
    }
  }
  lines.push('');

  lines.push('## 4. Accuracy Observations');
  lines.push('');
  lines.push('Based only on captured CLI outputs and finding paths:');
  lines.push(`- Noise pattern candidate: ${noiseCandidates.length} of ${allFindings.length} findings (${pct(noiseCandidates.length, allFindings.length)}) were located under docs/test/example/demo/fixture/sample-like paths.`);
  if (topRules.length > 0) {
    lines.push(`- Most common detection pattern: ${topRules[0][0]} produced ${topRules[0][1]} findings.`);
  } else {
    lines.push('- Most common detection pattern: no findings were emitted.');
  }
  if (topHighConfidenceRules.length > 0) {
    lines.push(`- Strong detections by high-confidence count: ${topHighConfidenceRules.map(([rule, count]) => `${rule} (${count})`).join(', ')}.`);
  } else {
    lines.push('- Strong detections by high-confidence count: no high-confidence findings were emitted.');
  }
  lines.push(`- Weak/operational area observed: aggregate AST failures by language were ${formatJson(astFailureAggregate)}.`);
  lines.push(`- Validation-mode behavior observed: ${validationFailures} repositories had a non-zero validation command exit.`);
  lines.push(`- Confidence distribution observed: ${formatJson(byConfidence)}.`);
  lines.push('');

  lines.push('## 5. Rule Performance');
  lines.push('');
  lines.push('Most triggered rules:');
  if (topRules.length === 0) {
    lines.push('- None');
  } else {
    for (const [rule, count] of topRules) {
      lines.push(`- ${rule}: ${count}`);
    }
  }
  lines.push('');
  lines.push('Least triggered rules among rules that appeared at least once:');
  if (leastRules.length === 0) {
    lines.push('- None');
  } else {
    for (const [rule, count] of leastRules) {
      lines.push(`- ${rule}: ${count}`);
    }
  }
  lines.push('');
  lines.push(`High-confidence findings: ${highConfidence}`);
  lines.push(`Low-confidence findings: ${lowConfidence}`);
  lines.push(`High-confidence vs low-confidence ratio: ${highLowRatio}`);
  lines.push('');

  lines.push('## Copied Repository Deletion List');
  lines.push('');
  lines.push('Delete only these local copy paths when cleaning up this validation run:');
  for (const item of manifest.repositories) {
    lines.push(`- ${item.localPath}`);
  }
  lines.push('');

  return lines.join('\n');
}

function saveManifest(manifest) {
  fs.writeFileSync(manifestJsonPath, JSON.stringify(manifest, null, 2), 'utf8');
  const lines = [
    '# Copied Repositories For Future Deletion',
    '',
    `Run root: ${runRoot}`,
    '',
    'Delete only the following local copy paths:',
    '',
    ...manifest.repositories.map((item) => `- ${item.localPath} (${item.url})`),
    '',
  ];
  fs.writeFileSync(manifestMdPath, lines.join('\n'), 'utf8');
}

async function main() {
  if (repos.length !== 50) {
    throw new Error(`Expected 50 repositories in the test list, found ${repos.length}`);
  }

  ensureDir(repoRoot);
  ensureDir(outputRoot);
  ensureDir(npmCache);
  ensureDir(path.dirname(desktopReportPath));

  const manifest = {
    generatedAt: new Date().toISOString(),
    runRoot,
    repositories: repos.map((repo, index) => {
      const localPath = path.join(repoRoot, `${String(index + 1).padStart(2, '0')}-${slugify(repo.category)}-${slugify(repo.name)}`);
      return {
        index: index + 1,
        category: repo.category,
        name: repo.name,
        url: repo.url,
        localPath,
      };
    }),
  };
  saveManifest(manifest);

  const results = [];
  const failures = [];

  for (const item of manifest.repositories) {
    const repo = repos[item.index - 1];
    const outputDir = path.join(outputRoot, `${String(item.index).padStart(2, '0')}-${slugify(repo.name)}`);
    ensureDir(outputDir);

    const result = {
      index: item.index,
      category: repo.category,
      name: repo.name,
      url: repo.url,
      localPath: item.localPath,
      commit: null,
      clone: null,
      revParse: null,
      scan: null,
      validate: null,
      scanSuccess: false,
      scanJsonError: null,
      stats: null,
      findings: [],
    };

    console.log(`[${item.index}/50] Cloning ${repo.name} (${repo.category})`);
    result.clone = await runCommand({
      command: 'git',
      args: ['clone', '--depth', '1', '--no-tags', repo.url, item.localPath],
      cwd: repoRoot,
      stdoutPath: path.join(outputDir, 'clone.stdout.txt'),
      stderrPath: path.join(outputDir, 'clone.stderr.txt'),
      timeoutMs: cloneTimeoutMs,
    });
    fs.writeFileSync(path.join(outputDir, 'clone.command.json'), JSON.stringify(result.clone, null, 2), 'utf8');

    if (result.clone.exitCode !== 0 || result.clone.timedOut || result.clone.error) {
      failures.push({
        repo: repo.name,
        step: 'clone',
        detail: result.clone.timedOut ? 'clone timed out' : `exitCode=${result.clone.exitCode}; error=${result.clone.error || 'none'}`,
        stdoutPath: result.clone.stdoutPath,
        stderrPath: result.clone.stderrPath,
      });
      results.push(result);
      saveManifest(manifest);
      continue;
    }

    console.log(`[${item.index}/50] Reading commit hash for ${repo.name}`);
    result.revParse = await runCommand({
      command: 'git',
      args: ['rev-parse', 'HEAD'],
      cwd: item.localPath,
      stdoutPath: path.join(outputDir, 'rev-parse.stdout.txt'),
      stderrPath: path.join(outputDir, 'rev-parse.stderr.txt'),
      timeoutMs: 30 * 1000,
    });
    fs.writeFileSync(path.join(outputDir, 'rev-parse.command.json'), JSON.stringify(result.revParse, null, 2), 'utf8');
    const commitText = readFileIfExists(result.revParse.stdoutPath).trim();
    if (result.revParse.exitCode === 0 && /^[0-9a-f]{40}$/i.test(commitText)) {
      result.commit = commitText;
      item.commit = commitText;
    } else {
      failures.push({
        repo: repo.name,
        step: 'rev-parse',
        detail: `exitCode=${result.revParse.exitCode}; stdout=${commitText || '<empty>'}`,
        stdoutPath: result.revParse.stdoutPath,
        stderrPath: result.revParse.stderrPath,
      });
    }
    saveManifest(manifest);

    console.log(`[${item.index}/50] Running scan for ${repo.name}`);
    result.scan = await runCommand({
      command: 'npx',
      args: ['--prefix', cliPrefix, 'flutter-supabase-helper', 'scan', '.', '--json'],
      cwd: item.localPath,
      stdoutPath: path.join(outputDir, 'scan.stdout.json'),
      stderrPath: path.join(outputDir, 'scan.stderr.txt'),
      timeoutMs: scanTimeoutMs,
      env: { NPM_CONFIG_CACHE: npmCache },
    });
    fs.writeFileSync(path.join(outputDir, 'scan.command.json'), JSON.stringify(result.scan, null, 2), 'utf8');

    const scanStdout = readFileIfExists(result.scan.stdoutPath);
    const parsedScan = parseJsonOutput(scanStdout);
    if (parsedScan.error) {
      result.scanJsonError = parsedScan.error;
    }
    if (result.scan.exitCode !== 0 || result.scan.timedOut || result.scan.error) {
      failures.push({
        repo: repo.name,
        step: 'scan',
        detail: result.scan.timedOut ? 'scan timed out' : `exitCode=${result.scan.exitCode}; error=${result.scan.error || 'none'}`,
        stdoutPath: result.scan.stdoutPath,
        stderrPath: result.scan.stderrPath,
      });
    } else if (!parsedScan.ok || !parsedScan.value || !parsedScan.value.stats) {
      failures.push({
        repo: repo.name,
        step: 'scan-output',
        detail: `invalid JSON output: ${parsedScan.error || 'missing stats'}`,
        stdoutPath: result.scan.stdoutPath,
        stderrPath: result.scan.stderrPath,
      });
    } else {
      result.scanSuccess = true;
      result.stats = parsedScan.value.stats;
      result.findings = parsedScan.value.findings || [];
      fs.writeFileSync(path.join(outputDir, 'scan.parsed-summary.json'), JSON.stringify({
        stats: result.stats,
        topFindings: result.findings.slice(0, 5),
      }, null, 2), 'utf8');
    }

    console.log(`[${item.index}/50] Running validation mode for ${repo.name}`);
    result.validate = await runCommand({
      command: 'npx',
      args: ['--prefix', cliPrefix, 'flutter-supabase-helper', 'validate', '.'],
      cwd: item.localPath,
      stdoutPath: path.join(outputDir, 'validate.stdout.json'),
      stderrPath: path.join(outputDir, 'validate.stderr.txt'),
      timeoutMs: validateTimeoutMs,
      env: { NPM_CONFIG_CACHE: npmCache },
    });
    fs.writeFileSync(path.join(outputDir, 'validate.command.json'), JSON.stringify(result.validate, null, 2), 'utf8');
    if (result.validate.exitCode !== 0 || result.validate.timedOut || result.validate.error) {
      failures.push({
        repo: repo.name,
        step: 'validate',
        detail: result.validate.timedOut ? 'validate timed out' : `exitCode=${result.validate.exitCode}; error=${result.validate.error || 'none'}`,
        stdoutPath: result.validate.stdoutPath,
        stderrPath: result.validate.stderrPath,
      });
    }

    results.push(result);
    fs.writeFileSync(path.join(outputDir, 'repo-result.json'), JSON.stringify(result, null, 2), 'utf8');
    saveManifest(manifest);
  }

  const report = buildReport(results, failures, manifest);
  fs.writeFileSync(path.join(runRoot, 'sast_test_report.md'), report, 'utf8');
  fs.writeFileSync(desktopReportPath, report, 'utf8');
  fs.writeFileSync(path.join(runRoot, 'all-results.json'), JSON.stringify({ results, failures, manifest }, null, 2), 'utf8');

  const successfulScans = results.filter((result) => result.scanSuccess).length;
  console.log(`Completed. Processed ${results.length}/50 repositories.`);
  console.log(`Successful scans: ${successfulScans}`);
  console.log(`Failure events: ${failures.length}`);
  console.log(`Report: ${desktopReportPath}`);
  console.log(`Artifacts: ${runRoot}`);

  if (results.length < 50 || successfulScans < 40) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
