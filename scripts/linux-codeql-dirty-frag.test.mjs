import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const script = readFileSync(new URL('./linux-codeql-dirty-frag.sh', import.meta.url), 'utf8');
const countFunction = script.match(/^count_query_rows\(\) \{[\s\S]*?^\}/m)[0];

function countRows({ csv = 'header\nrow\n', queryExit = 0, decodeExit = 0 } = {}) {
  // Exercise the real helper and shell pipeline; only the external CodeQL process is a fixture.
  const program = `set -euo pipefail
codeql_fixture() {
  case "$1 $2" in
    "query run") return "$QUERY_EXIT" ;;
    "bqrs decode") printf '%s' "$CSV"; return "$DECODE_EXIT" ;;
    *) return 99 ;;
  esac
}
${countFunction}
codeql_bin=codeql_fixture
database_dir=/unused-fixture
count="$(count_query_rows /unused/query.ql /unused/query.bqrs)"
printf '%s' "$count"
`;
  return spawnSync('bash', ['-c', program], {
    encoding: 'utf8',
    env: { ...process.env, CSV: csv, QUERY_EXIT: String(queryExit), DECODE_EXIT: String(decodeExit) },
  });
}

test('CSV streaming counts data rows without the header or blank lines', () => {
  const rows = countRows({ csv: 'header\none\n\ntwo\n' });
  assert.equal(rows.status, 0, rows.stderr);
  assert.equal(rows.stdout, '2');
  const empty = countRows({ csv: 'header\n' });
  assert.equal(empty.status, 0, empty.stderr);
  assert.equal(empty.stdout, '0');
});

test('query failure is retained inside command substitution', () => {
  const result = countRows({ queryExit: 9 });
  assert.equal(result.status, 9, result.stderr);
  assert.equal(result.stdout, '');
});

test('decoder failure is retained through the counting pipeline', () => {
  const result = countRows({ decodeExit: 7 });
  assert.equal(result.status, 7, result.stderr);
  assert.equal(result.stdout, '');
});

test('scratch cleanup cannot delete another directory through the kernel ref', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'foxguard-codeql-test-'));
  try {
    const scripts = path.join(root, 'scripts');
    const bin = path.join(root, 'bin');
    const queries = path.join(root, 'rules/kernel/dirty-frag-class/queries');
    const foreign = path.join(queries, 'unowned');
    mkdirSync(scripts);
    mkdirSync(bin);
    mkdirSync(foreign, { recursive: true });
    writeFileSync(path.join(foreign, 'keep'), 'unrelated data');
    const entry = path.join(scripts, 'linux-codeql-dirty-frag.sh');
    writeFileSync(entry, script);
    // Stop before cloning/building anything; the real EXIT trap must still run.
    writeFileSync(path.join(bin, 'git'), '#!/bin/sh\nexit 7\n', { mode: 0o700 });
    writeFileSync(path.join(bin, 'codeql'), '#!/bin/sh\nexit 99\n', { mode: 0o700 });
    const result = spawnSync('bash', [entry], {
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
        CODEQL: path.join(bin, 'codeql'),
        KERNEL_REF: '../../unowned',
        WORKDIR: path.join(root, 'work'),
        OUT_DIR: path.join(root, 'output'),
      },
    });
    assert.equal(result.status, 7, result.stderr);
    assert.equal(readFileSync(path.join(foreign, 'keep'), 'utf8'), 'unrelated data');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
