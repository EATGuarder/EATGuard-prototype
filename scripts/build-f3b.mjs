import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {ROOT} from '../lib/crypto.mjs';

fs.mkdirSync(path.join(ROOT, 'build'), {recursive: true});
const env = {...process.env,
  GOCACHE: process.env.GOCACHE ?? path.join(ROOT, 'build/go-cache'),
  GOMODCACHE: process.env.GOMODCACHE ?? path.join(ROOT, 'build/go-mod'),
};
for (const args of [['mod', 'download'], ['test', './...'],
  ['build', '-trimpath', '-o', '../build/f3b-crypto', '.']]) {
  const result = spawnSync(process.env.GO ?? 'go', args, {
    cwd: path.join(ROOT, 'f3b'), env, stdio: 'inherit',
  });
  if (result.error || result.status !== 0) throw result.error ?? new Error(`Go exited ${result.status}`);
}
