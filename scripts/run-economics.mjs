import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fixture, makeTicket, mutated, wallets, json} from '../lib/crypto.mjs';
import {chain, commit, certifyBatch, report, STATE} from '../lib/chain.mjs';
import {argumentsFor, checkSetup, newRun, saveRows, closeProver} from '../lib/runtime.mjs';

const options = argumentsFor('economics');
checkSetup();
const run = newRun('economics', options), cfg = options.config;
const rows = [], staticPool = [], normalPool = [];
const sum = values => values.reduce((a, b) => a + BigInt(b), 0n);
const append = (name, data) => fs.appendFileSync(path.join(options.out, name), json(data, 0) + '\n');
const balances = async env => ({
  sender: await Promise.all(env.fx.senders.map(s => env.guard.bonds(s.bond).then(b => b.balance))),
  builder: await env.guard.builderBalance(wallets[4].address),
  rewards: await env.guard.totalRewards(), burned: await env.guard.totalBurned(),
});
let env;
try {
  const base = await fixture();
  for (let i = 0; i < cfg.staticFaults; i++) staticPool.push(await makeTicket(base, i, {kind: 'signature'}));
  for (let i = 0; i < cfg.admissionBatches * 4; i++) normalPool.push(await makeTicket(base, i + cfg.staticFaults));
  const coverage = [0.25, 0.5, 0.75, 1];
  for (const rewardBps of [1000, 2000, 5000]) {
    const fx = {...base, policy: {...base.policy, rewardBps: BigInt(rewardBps)}};
    env = await chain(fx);
    for (const fraction of coverage) {
      const count = cfg.staticFaults * fraction;
      assert.equal(count % 1, 0);
      const snapshot = await env.snapshot();
      try {
        const senderBatch = await commit(env, staticPool);
        await env.advance(11);
        const certificates = await certifyBatch(env, senderBatch);
        const batches = [];
        for (let j = 0; j < cfg.admissionBatches; j++) {
          const records = normalPool.slice(j * 4, j * 4 + 4);
          records[0] = mutated(records[0], ticket => ticket.a = ['0', '0']);
          batches.push(await commit(env, records));
        }
        const before = await balances(env);
        let observedRewards = 0n, fees = 0n;
        async function execute(batch, index, reason, reporter, certificate) {
          const result = await report(env, batch, index, reason, {reporter, certificate});
          const liable = reason < 5 ? wallets[4].address : wallets[staticPool[index].senderIndex].address;
          assert.equal(result.metrics.liable.toLowerCase(), liable.toLowerCase());
          observedRewards += result.metrics.reward; fees += result.metrics.fee;
          append('reports.jsonl', {rewardBps, staticReports: count, ...result.metrics,
            evidence: result.evidence, receipt: result.receipt.toJSON()});
        }
        for (const batch of batches) {
          await execute(batch, 0, 4, 4);
          assert.equal(await env.guard.status(batch.id), STATE.REJECTED);
        }
        for (let i = 0; i < count; i++) await execute(senderBatch, i, 7, staticPool[i].senderIndex, certificates[i]);
        const after = await balances(env);
        const senderDeduction = sum(before.sender) - sum(after.sender);
        const builderDeduction = before.builder - after.builder;
        const total = senderDeduction + builderDeduction;
        assert.equal(senderDeduction, BigInt(count) * fx.policy.deltaU);
        assert.equal(builderDeduction, BigInt(cfg.admissionBatches) * fx.policy.deltaB);
        assert.equal(observedRewards, total * BigInt(rewardBps) / 10000n);
        assert.equal(after.rewards - before.rewards, observedRewards);
        assert.equal(after.burned - before.burned, total - observedRewards);
        assert.equal(await env.guard.builderReserved(wallets[4].address), 0n);
        rows.push({rewardBps, staticFaultTransactions: cfg.staticFaults, staticBatchSize: cfg.staticFaults,
          admissionFaultBatches: cfg.admissionBatches, admissionBatchSize: 4,
          staticReports: count, staticReportingFraction: fraction, builderReports: batches.length,
          senderDeduction, builderDeduction, coalitionRewards: observedRewards,
          coalitionNetLoss: total - observedRewards, deltaU: fx.policy.deltaU,
          deltaB: fx.policy.deltaB, reportFees: fees});
        await env.advance(20);
        assert.equal(await env.guard.status(senderBatch.id), STATE.FINALIZED);
        if (count < cfg.staticFaults) {
          await assert.rejects(report(env, senderBatch, count, 7, {certificate: certificates[count]}),
            error => error.receipt?.status === 0);
          assert.deepEqual(await balances(env), after);
        }
        saveRows(options.out, 'losses', rows);
        console.log(`Reward ${rewardBps / 100}%, reporting ${fraction * 100}%: ${Number(total - observedRewards) / 1e18} ETH`);
      } finally {await env.restore(snapshot);}
    }
    await env.close(); env = null;
  }
  assert.equal(rows.length, 12);
  run.finish();
} catch (error) {
  run.fail(error); throw error;
} finally {
  if (env) await env.close();
  await closeProver();
}
