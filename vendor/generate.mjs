import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const vendor = dirname(fileURLToPath(import.meta.url));
const grammars = [
  ['tree-sitter-bash', false],
  ['tree-sitter-c', false],
  ['tree-sitter-javascript', true],
  ['tree-sitter-typescript/typescript', true],
  ['tree-sitter-typescript/tsx', true],
];

for (const [directory, ecmascript] of grammars) {
  const cwd = join(vendor, directory);
  execFileSync('npm', [
    'exec', '--yes', '--package', 'tree-sitter-cli@0.25.10', '--',
    'tree-sitter', 'generate', '--abi', '14',
  ], { cwd, stdio: 'inherit' });

  if (!ecmascript) continue;

  // This generator excludes NUL from otherwise-permitted character classes,
  // conflating a source byte with EOF. Correct its generated lexical guards;
  // never rewrite the input being scanned. Identifier/whitespace character sets
  // still exclude NUL, so this does not make it legal outside literals/comments.
  const path = join(cwd, 'src/parser.c');
  const source = readFileSync(path, 'utf8');
  const start = source.indexOf('static bool ts_lex(');
  const end = source.indexOf('static bool ts_lex_keywords(', start);
  if (start < 0 || end < start) throw new Error(`Missing lexer boundary: ${path}`);
  const lexer = source.slice(start, end);
  if (!lexer.includes('eof = lexer->eof(lexer);')) {
    throw new Error(`Missing EOF predicate: ${path}`);
  }
  const corrected = lexer.replace(/\blookahead != 0\b/g, '!eof');
  if (corrected === lexer) throw new Error(`Missing expected NUL guards: ${path}`);
  writeFileSync(path, source.slice(0, start) + corrected + source.slice(end));
}
