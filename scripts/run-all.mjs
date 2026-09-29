import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {ROOT} from '../lib/crypto.mjs';
import {argumentsFor, checkSetup, newRun, readJSON} from '../lib/runtime.mjs';

const options = argumentsFor('');
checkSetup();
const run = newRun('suite', options);
try {
  for (const stage of ['evm', 'f3b', 'depth', 'economics']) {
    console.log(`Running ${stage} (${options.profile})`);
    const out = path.join(options.out, stage);
    const result = spawnSync(process.execPath,
      [path.join(ROOT, `scripts/run-${stage}.mjs`), '--profile', options.profile, '--out', out],
      {cwd: ROOT, stdio: 'inherit'});
    if (result.error || result.status !== 0) throw result.error ?? new Error(`${stage} exited ${result.status}`);
    if (readJSON(path.join(out, 'manifest.json')).status !== 'complete') throw new Error(`${stage} did not complete`);
  }
  run.finish();
  console.log(`Results: ${options.out}`);
} catch (error) {
  run.fail(error); throw error;
}
