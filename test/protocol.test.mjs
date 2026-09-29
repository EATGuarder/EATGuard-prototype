import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,makeTicket,verifyRecord,mutated,clone,ROOT} from '../lib/crypto.mjs';
import {wtns} from 'snarkjs';
import path from 'node:path';
import {chain,commit,report,audit,certify,STATE} from '../lib/chain.mjs';
import {correctness} from '../lib/correctness.mjs';

test('EAT admission, authenticated plaintext and per-ticket penalty',{timeout:180000},async()=>{
  const fx=await fixture();const good=await makeTicket(fx,0),bad=await makeTicket(fx,1,{kind:'signature'});
  assert.equal(await verifyRecord(good),true);
  for(const edit of [
    x=>x.slot=fx.policy.quota.toString(),
    x=>x.bondSiblings[0]='123',
    x=>x.stateSiblings[0]='123',
    x=>x.secret='42',
    x=>x.tx[2]='1',
    x=>x.balance='0'
  ]) {
    const witness=clone(good.input);edit(witness);
    await assert.rejects(wtns.calculate(witness,path.join(ROOT,'build/eat_js/eat.wasm'),{type:'mem'}));
  }
  const env=await chain(fx);
  try {
    assert.equal(await env.guard.validTicket(good.raw),true);
    assert.equal(await env.guard.validTicket(mutated(good,t=>t.x[5]='123').raw),false);
    const b=await commit(env,[good,bad]);
    assert.equal((await audit(env,b)).ok,true);
    await assert.rejects(certify(env,b,1),/admission finality/);
    await env.advance(11);
    const cert=await certify(env,b,1);
    const before=(await env.guard.bonds(fx.senders[1].bond)).balance;
    const result=await report(env,b,1,7,{certificate:cert});
    assert.equal(result.metrics.penalty,fx.policy.deltaU);
    assert.equal((await env.guard.bonds(fx.senders[1].bond)).balance,before-fx.policy.deltaU);
    assert.equal(await env.guard.status(b.id),STATE.ADMISSION_FINAL);
    assert.equal(await env.guard.totalBurned(),fx.policy.deltaU*8000n/10000n);
    await assert.rejects(report(env,b,1,7,{certificate:cert}));
  } finally {await env.close();if(globalThis.curve_bn128)await globalThis.curve_bn128.terminate();}
});

test('Fault taxonomy, report replay, temporal and collateral invariants',{timeout:240000},async()=>{
  const fx=await fixture(),pool={};
  for(const kind of ['normal','encoding','binding','signature']) {
    pool[kind]=[];
    for(let i=0;i<2;i++)pool[kind].push(await makeTicket(fx,i,{kind}));
  }
  const env=await chain(fx);
  try {const rows=await correctness(env,pool);assert.equal(rows.length,26);}
  finally {await env.close();if(globalThis.curve_bn128)await globalThis.curve_bn128.terminate();}
});
