#!/usr/bin/env node
// Shell-independent recursive test discovery.
//
// Why this exists: `tsx --test tests/**/*.test.ts` silently under-selects
// files because `**` recursive globbing is a BASH-ONLY feature (requires
// `shopt -s globstar`), and npm actually invokes scripts via `/bin/sh`
// (dash on this system), which has no such feature at all -- `**` there
// behaves like a plain `*`, matching only one directory level. This was
// caught during M2.4.3: a nested test file (tests/harness/evidence/*)
// was silently excluded from every `npm test` run despite passing when
// invoked directly. Passing a bare directory to `tsx --test` also does not
// correctly recurse. This script removes the shell/tool ambiguity entirely
// by walking the filesystem itself and passing an explicit file list.

import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function findTestFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...findTestFiles(full));
    } else if (name.endsWith('.test.ts')) {
      out.push(full);
    }
  }
  return out;
}

const files = findTestFiles('tests').sort();
console.error(`[run-tests] discovered ${files.length} test file(s):`);
for (const f of files) console.error(`  - ${f}`);

const result = spawnSync('npx', ['tsx', '--test', ...files], { stdio: 'inherit' });
process.exit(result.status ?? 1);
