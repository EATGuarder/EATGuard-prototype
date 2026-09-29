import assert from 'node:assert/strict';
import {formatEther} from 'ethers';
import {fixture, makeTicket, mutated, wallets} from '../lib/crypto.mjs';
import {chain, commit, audit, certifyBatch, report, staticReason, STATE} from '../lib/chain.mjs';
import {checkSetup, closeProver} from '../lib/runtime.mjs';

checkSetup();
let env;
try {
  const fx = await fixture();
  const normal = await makeTicket(fx, 0);
  const faulty = await makeTicket(fx, 1, {kind: 'signature'});
  const invalid = mutated(await makeTicket(fx, 2), ticket => ticket.a = ['0', '0']);
  env = await chain(fx);
  console.log('EAT prototype: contracts deployed and bonds funded on a local chain.');

  const accepted = await commit(env, [normal, faulty]);
  assert.equal((await audit(env, accepted)).ok, true);
  console.log(`Batch ${accepted.id}: both EATs pass the admission audit.`);

  const rejected = await commit(env, [invalid]);
  const checked = await audit(env, rejected);
  assert.equal(checked.batchId, rejected.id);
  assert.equal(checked.reason, 4);
  const builderBefore = await env.guard.builderBalance(wallets[4].address);
  const admission = await report(env, rejected, 0, 4);
  assert.equal(admission.metrics.liable, wallets[4].address);
  assert.equal(await env.guard.status(rejected.id), STATE.REJECTED);
  assert.equal(await env.guard.builderBalance(wallets[4].address), builderBefore - fx.policy.deltaB);
  console.log(`Batch ${rejected.id}: invalid EAT reported, batch rejected, builder penalized ${formatEther(admission.metrics.penalty)} ETH.`);

  await env.advance(Number(env.config.admissionWindow) + 1);
  const certificates = await certifyBatch(env, accepted);
  assert.equal(staticReason(certificates[0].message, normal.ticket), null);
  assert.equal(staticReason(certificates[1].message, faulty.ticket), 7);
  console.log(`Batch ${accepted.id}: authenticated decryption after admission finality.`);

  const sender = fx.senders[faulty.senderIndex];
  const senderBefore = (await env.guard.bonds(sender.bond)).balance;
  const builderAfterAdmission = await env.guard.builderBalance(wallets[4].address);
  const result = await report(env, accepted, 1, 7, {certificate: certificates[1]});
  assert.equal(result.metrics.liable, sender.wallet.address);
  assert.equal((await env.guard.bonds(sender.bond)).balance, senderBefore - fx.policy.deltaU);
  assert.equal(await env.guard.builderBalance(wallets[4].address), builderAfterAdmission);
  assert.equal((await env.guard.bonds(fx.senders[0].bond)).balance, fx.senders[0].deposit);
  assert.equal((await env.guard.bonds(fx.senders[2].bond)).balance, fx.senders[2].deposit);
  assert.equal(await env.guard.status(accepted.id), STATE.ADMISSION_FINAL);
  console.log('Transaction 0: valid plaintext, no penalty.');
  console.log(`Transaction 1: invalid signature reported, sender penalized ${formatEther(result.metrics.penalty)} ETH.`);
  console.log('EAT prototype completed.');
} finally {
  if (env) await env.close();
  await closeProver();
}
