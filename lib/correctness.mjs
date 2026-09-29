import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {mutated,evidence,encodeEvidence,wallets,decodeTicket} from './crypto.mjs';
import {commit,report,audit,certify,staticReason,STATE} from './chain.mjs';

export async function correctness(env,pool) {
  const rows=[],p=env.fx.policy;
  async function run(name,expected,fn) {
    const snap=await env.snapshot(),start=performance.now();
    try {
      const observed=await fn();
      rows.push({case:name,expected,observed:observed??expected,passed:true,elapsedMs:performance.now()-start});
    } finally {await env.restore(snap);}
  }
  const direct=(b,i,r,extra={})=>env.guard.connect(env.signers[5]).reportFault(b.id,r<5?0:1,r,encodeEvidence(evidence(b,i,extra)),{gasLimit:10_000_000}).then(tx=>tx.wait());
  async function noPenalty(fn) {
    const burned=await env.guard.totalBurned(),reward=await env.guard.totalRewards();
    const sb=await Promise.all(env.fx.senders.map(s=>env.guard.bonds(s.bond).then(x=>x.balance)));
    const bb=await env.guard.builderBalance(wallets[4].address);
    await fn();
    assert.equal(await env.guard.totalBurned(),burned);assert.equal(await env.guard.totalRewards(),reward);
    assert.equal(await env.guard.builderBalance(wallets[4].address),bb);
    for(let i=0;i<sb.length;i++)assert.equal((await env.guard.bonds(env.fx.senders[i].bond)).balance,sb[i]);
  }
  await run('normal_transaction','admitted; no penalty',async()=>{
    const b=await commit(env,[pool.normal[0]]);assert.equal((await audit(env,b)).ok,true);
    await env.advance(11);const c=await certify(env,b,0);
    assert.equal(staticReason(c.message,decodeTicket(b.raws[0])),null);
    await noPenalty(()=>assert.rejects(report(env,b,0,7,{certificate:c})));
  });
  const admissions=[
    ['malformed_eat',0,'0x1234'],
    ['ticket_size_limit',0,'0x'+'ab'.repeat(8193)],
    ['invalid_epoch',1,mutated(pool.normal[0],t=>t.x[1]='2')],
    ['invalid_policy',1,mutated(pool.normal[0],t=>t.x[0]='2')],
    ['invalid_bond_root',1,mutated(pool.normal[0],t=>t.x[2]='3')],
    ['invalid_state_root',1,mutated(pool.normal[0],t=>t.x[3]='3')],
    ['bad_public_binding',2,mutated(pool.normal[0],t=>t.x[5]='123')],
    ['invalid_eat_proof',4,mutated(pool.normal[0],t=>t.a=['0','0'])]
  ];
  for(const [name,reason,record] of admissions)await run(name,'builder penalized once; batch rejected',async()=>{
    const b=await commit(env,[record]);assert.equal((await audit(env,b)).ok,false);
    const before=await env.guard.builderBalance(wallets[4].address);
    const r=await report(env,b,0,reason);
    assert.equal(r.metrics.penalty,p.deltaB);
    assert.equal(await env.guard.builderBalance(wallets[4].address),before-p.deltaB);
    assert.equal(await env.guard.status(b.id),STATE.REJECTED);
    await noPenalty(()=>assert.rejects(report(env,b,0,reason)));
  });
  for(const [kind,reason] of [['encoding',5],['binding',6],['signature',7]])await run(kind+'_sender_fault','sender loses deltaU; builder balance unchanged',async()=>{
    const r=pool[kind][0],b=await commit(env,[r]);
    assert.equal((await audit(env,b)).ok,true);await env.advance(11);
    const c=await certify(env,b,0);assert.equal(staticReason(c.message,r.ticket),reason);
    const before=(await env.guard.bonds(env.fx.senders[r.senderIndex].bond)).balance;
    const builder=await env.guard.builderBalance(wallets[4].address);
    await report(env,b,0,reason,{certificate:c});
    assert.equal((await env.guard.bonds(env.fx.senders[r.senderIndex].bond)).balance,before-p.deltaU);
    assert.equal(await env.guard.builderBalance(wallets[4].address),builder);
    await noPenalty(()=>assert.rejects(report(env,b,0,reason===7?6:7,{certificate:c})));
  });
  await run('state_change','dynamic failure; no sender penalty',async()=>{
    const r=pool.normal[0],b=await commit(env,[r]);await env.advance(11);
    const c=await certify(env,b,0);assert.equal(staticReason(c.message,r.ticket),null);
    const executionState={nonce:r.payload.fields[2]+1n,balance:0n};
    const executable=r.payload.fields[2]===executionState.nonce && executionState.balance>=r.payload.fields[3]+r.payload.fields[4]*r.payload.fields[5];
    assert.equal(executable,false);
    await noPenalty(()=>assert.rejects(report(env,b,0,7,{certificate:c})));
  });
  await run('cross_batch_duplicate','later builder penalty; original sender penalty exactly once',async()=>{
    const r=pool.signature[0],a=await commit(env,[r]),b=await commit(env,[r]);
    assert.equal((await audit(env,b)).reason,3);
    await report(env,b,0,3,{earlier:{batch:a,index:0}});
    assert.equal(await env.guard.status(b.id),STATE.REJECTED);
    await env.advance(11);const c=await certify(env,a,0);await report(env,a,0,7,{certificate:c});
    const initial=env.fx.senders[r.senderIndex].deposit;
    assert.equal((await env.guard.bonds(env.fx.senders[r.senderIndex].bond)).balance,initial-p.deltaU);
    await noPenalty(()=>assert.rejects(direct(b,0,7,c)));
  });
  await run('within_batch_duplicate','builder penalty; earlier index must precede target',async()=>{
    const b=await commit(env,[pool.normal[0],pool.normal[0]]);
    await noPenalty(()=>assert.rejects(report(env,b,0,3,{earlier:{batch:b,index:1}})));
    await report(env,b,1,3,{earlier:{batch:b,index:0}});
    assert.equal(await env.guard.status(b.id),STATE.REJECTED);
  });
  await run('rejected_predecessor','rejected history does not block a later authorized ticket',async()=>{
    const a=await commit(env,[pool.normal[0],'0x12']);await report(env,a,1,0);
    const b=await commit(env,[pool.normal[0]]);assert.equal((await audit(env,b)).ok,true);
    await noPenalty(()=>assert.rejects(report(env,b,0,3,{earlier:{batch:a,index:0}})));
  });
  await run('invalid_predecessor','unauthorized earlier proof cannot justify duplicate penalty',async()=>{
    const a=await commit(env,[mutated(pool.normal[0],t=>t.a=['0','0'])]);
    const b=await commit(env,[pool.normal[0]]);
    await noPenalty(()=>assert.rejects(report(env,b,0,3,{earlier:{batch:a,index:0}})));
  });
  await run('tampered_membership','forged membership and position rejected',async()=>{
    const b=await commit(env,[pool.signature[0],pool.normal[1]]);await env.advance(11);const c=await certify(env,b,0);
    await noPenalty(()=>assert.rejects(direct(b,0,7,{...c,path:['0x'+'00'.repeat(32)]})));
    await noPenalty(()=>assert.rejects(direct(b,0,7,{...c,index:1})));
  });
  await run('authenticated_decryption_binding','forged, altered and cross-position certificates rejected',async()=>{
    const b=await commit(env,[pool.signature[0],pool.signature[1]]);await env.advance(11);const c=await certify(env,b,0);
    const digest=await env.guard.certificateDigest(b.id,0,pool.signature[0].ticket.x[5],c.message);
    const forged=wallets[8].signingKey.sign(digest).serialized;
    await noPenalty(()=>assert.rejects(direct(b,0,7,{message:c.message,certificate:forged})));
    await noPenalty(()=>assert.rejects(direct(b,0,5,{...c,message:'0x12'})));
    await noPenalty(()=>assert.rejects(direct(b,1,7,c)));
  });
  await run('static_authorization_revalidation','invalid EAT cannot authorize sender slashing even with a TDN signature',async()=>{
    const r=mutated(pool.signature[0],t=>t.a=['0','0']);const b=await commit(env,[r]);await env.advance(11);
    await assert.rejects(certify(env,b,0),/audit failed/);
    const digest=await env.guard.certificateDigest(b.id,0,r.ticket.x[5],r.message);
    await noPenalty(()=>assert.rejects(direct(b,0,7,{message:r.message,certificate:wallets[6].signingKey.sign(digest).serialized})));
  });
  await run('predicate_order','PDEF report cannot bypass payload binding',async()=>{
    const b=await commit(env,[pool.binding[0]]);await env.advance(11);const c=await certify(env,b,0);
    await noPenalty(()=>assert.rejects(report(env,b,0,7,{certificate:c})));
    await report(env,b,0,6,{certificate:c});
  });
  await run('admission_deadline_inclusive','admission report accepted at tA',async()=>{
    const b=await commit(env,['0x12']);await env.advance(10);await report(env,b,0,0);
    assert.equal(await env.guard.status(b.id),STATE.REJECTED);
  });
  await run('expired_admission','late admission report rejected without explicit finalize',async()=>{
    const b=await commit(env,['0x12']);await env.advance(11);
    await noPenalty(()=>assert.rejects(report(env,b,0,0)));
    assert.equal(await env.guard.status(b.id),STATE.ADMISSION_FINAL);
  });
  await run('static_deadlines','static report rejects tA and tS+1; accepts tS',async()=>{
    const b=await commit(env,[pool.signature[0]]);await env.advance(10);
    await noPenalty(()=>assert.rejects(direct(b,0,7)));
    await env.advance(20);const c=await certify(env,b,0);const snap=await env.snapshot();
    await report(env,b,0,7,{certificate:c});await env.restore(snap);
    await env.advance(1);assert.equal(await env.guard.status(b.id),STATE.FINALIZED);
    await noPenalty(()=>assert.rejects(report(env,b,0,7,{certificate:c})));
  });
  await run('pending_builder_reservation','reserved collateral cannot fund another pending batch or withdrawal',async()=>{
    const b=await commit(env,[pool.normal[0]]);
    const balance=await env.guard.builderBalance(wallets[4].address);
    await(await env.guard.connect(env.signers[4]).withdrawBuilder(balance-p.deltaB)).wait();
    await assert.rejects(commit(env,[pool.normal[1]]));
    await assert.rejects(env.guard.connect(env.signers[4]).withdrawBuilder(1n).then(t=>t.wait()));
    await env.advance(11);await(await env.guard.settle(b.id)).wait();
    assert.equal(await env.guard.builderReserved(wallets[4].address),0n);
    await commit(env,[pool.normal[1]]);
  });
  await run('sender_reservation_horizon','sender collateral locked until epoch reporting horizon',async()=>{
    const s=env.fx.senders[0];
    await assert.rejects(env.guard.withdrawBond(s.bond).then(t=>t.wait()));
    await env.advance(Number(env.config.epochEnd)+31-await env.now());
    await(await env.guard.withdrawBond(s.bond,{gasLimit:300_000})).wait();assert.equal((await env.guard.bonds(s.bond)).balance,0n);
  });
  return rows;
}
