import {fixture, makeTicket} from '../lib/crypto.mjs';
import {chain} from '../lib/chain.mjs';
import {correctness} from '../lib/correctness.mjs';
import {normalGas, individualReports, aggregateFaults} from '../lib/experiments.mjs';
import {argumentsFor, checkSetup, newRun, saveRows, closeProver} from '../lib/runtime.mjs';

const options = argumentsFor('evm');
checkSetup();
const run = newRun('evm', options), cfg = options.config;
run.manifest.evm = {hardfork: 'shanghai', chainId: 31337};
let env;
try {
  const fx = await fixture(), pool = {};
  const total = Math.max(...cfg.batchSizes, cfg.aggregateBatchSize * cfg.aggregateBatches);
  const faults = Math.max(2, Math.round(total * Math.max(...cfg.faultRatios)));
  for (const [kind, count] of [['normal', total], ['signature', faults], ['encoding', 2], ['binding', 2]]) {
    pool[kind] = [];
    for (let i = 0; i < count; i++) {
      pool[kind].push(await makeTicket(fx, i, {kind}));
      if ((i + 1) % 32 === 0 || i + 1 === count) console.log(`${kind}: ${i + 1}/${count}`);
    }
  }
  env = await chain(fx);
  saveRows(options.out, 'setup_gas', env.setupGas);
  saveRows(options.out, 'normal_gas', await normalGas(env, pool, cfg));
  saveRows(options.out, 'correctness', await correctness(env, pool));
  saveRows(options.out, 'report_costs', await individualReports(env, pool, cfg));
  saveRows(options.out, 'aggregate_faults', await aggregateFaults(env, pool, cfg));
  run.finish();
} catch (error) {
  run.fail(error); throw error;
} finally {
  if (env) await env.close();
  await closeProver();
}
