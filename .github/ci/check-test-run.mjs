// Fails the CI job unless every test/*.test.js file ran, and ran cleanly.
//
// The expected files come from reading the directory here, not from the glob
// in `npm test`, so a glob that matches nothing (a shell quoting quirk, a
// renamed folder) cannot hide by also shrinking the expectation.
//
// Usage: node .github/ci/check-test-run.mjs <test-run.json> <test dir>

import fs from 'node:fs';
import path from 'node:path';

const [summaryPath = 'test-run.json', testDir = 'test'] = process.argv.slice(2);

const expected = fs
  .readdirSync(testDir)
  .filter((name) => name.endsWith('.test.js'))
  .sort();

let summary;
try {
  summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
} catch {
  fail([`No test summary at ${summaryPath}: the test runner never reported, so no tests ran.`]);
}

// Key results by path relative to the test directory, e.g. "race.test.js".
const results = {};
for (const [file, counts] of Object.entries(summary.files)) {
  results[path.relative(path.resolve(testDir), file)] = counts;
}

const problems = [];
if (expected.length === 0) problems.push(`No *.test.js files found in ${testDir}/.`);

const rows = [];
const total = { passed: 0, failed: 0, skipped: 0, todo: 0 };

for (const name of expected) {
  const counts = results[name] ?? { passed: 0, failed: 0, skipped: 0, todo: 0 };
  for (const key of Object.keys(total)) total[key] += counts[key];
  rows.push([name, counts]);

  if (counts.passed + counts.failed === 0) problems.push(`${name} ran no tests.`);
  if (counts.failed > 0) problems.push(`${name}: ${counts.failed} failed.`);
  // A skip or todo is a test that proves nothing. The suite has none, so one
  // appearing should be a decision someone makes here, not something CI waves through.
  if (counts.skipped > 0) problems.push(`${name}: ${counts.skipped} skipped.`);
  if (counts.todo > 0) problems.push(`${name}: ${counts.todo} marked todo.`);
}

const ran = rows.filter(([, c]) => c.passed + c.failed > 0).length;
const width = Math.max(...expected.map((name) => name.length), 4);

for (const [name, c] of rows) {
  console.log(
    `  ${name.padEnd(width)}  ${String(c.passed).padStart(3)} passed  ${c.failed} failed  ${c.skipped} skipped`
  );
}

const line =
  `${ran}/${expected.length} test files ran on Node ${summary.node}: ` +
  `${total.passed} tests passed, ${total.failed} failed, ${total.skipped} skipped, ${total.todo} todo`;

writeStepSummary(rows, line);

if (problems.length > 0) fail(problems, line);
console.log(`Test run verified: ${line}`);

function fail(messages, context) {
  if (context) console.log(context);
  for (const message of messages) console.log(`::error title=Test run check::${message}`);
  process.exit(1);
}

function writeStepSummary(table, headline) {
  if (!process.env.GITHUB_STEP_SUMMARY) return;
  const lines = [
    `### ${headline}`,
    '',
    '| File | Passed | Failed | Skipped |',
    '| --- | ---: | ---: | ---: |',
    ...table.map(([name, c]) => `| \`${name}\` | ${c.passed} | ${c.failed} | ${c.skipped} |`),
    ''
  ];
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join('\n')}\n`);
}
