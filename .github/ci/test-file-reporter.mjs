// A node:test reporter that records which file every test came from, so CI can
// prove each test file ran rather than trusting a green exit code. The test
// runner exits 0 when a glob matches nothing, so "passed" alone proves nothing.
//
// Used by CI only, through NODE_OPTIONS, alongside the normal spec output:
//   --test-reporter=./.github/ci/test-file-reporter.mjs
//   --test-reporter-destination=test-run.json
// check-test-run.mjs then reads the JSON and fails the job if anything is missing.

import path from 'node:path';

export default async function* testFileReporter(source) {
  const files = {};

  const tally = (file) =>
    (files[file ?? '(unknown file)'] ??= { passed: 0, failed: 0, skipped: 0, todo: 0 });

  for await (const event of source) {
    if (event.type !== 'test:pass' && event.type !== 'test:fail') continue;

    const { data } = event;
    // Suites are containers, not tests; count only the tests inside them.
    if (data.details?.type === 'suite') continue;

    const counts = tally(data.file);

    // With nothing to report, the runner stands in for a file with one entry
    // named after the file itself. A pass there means the file defined no
    // tests, which must not count as a test; a fail means it crashed on load.
    const isFileEntry =
      data.nesting === 0 && data.file && path.resolve(data.name) === path.resolve(data.file);
    if (isFileEntry) {
      if (event.type === 'test:fail') counts.failed += 1;
      continue;
    }

    if (data.skip !== undefined && data.skip !== false) counts.skipped += 1;
    else if (data.todo !== undefined && data.todo !== false) counts.todo += 1;
    else if (event.type === 'test:pass') counts.passed += 1;
    else counts.failed += 1;
  }

  yield `${JSON.stringify({ node: process.version, files }, null, 2)}\n`;
}
