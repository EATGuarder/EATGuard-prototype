import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {groth16} from 'snarkjs';
import {ROOT,fixture,makeTicket,P,fold,json} from '../lib/crypto.mjs';
import {F3BCrypto} from '../lib/f3b.mjs';
import {argumentsFor,checkSetup,newRun,hashFile,readJSON,saveRows,closeProver} from '../lib/runtime.mjs';

const options=argumentsFor('depth'),cfg=options.config;
checkSetup();
const run=newRun('depth',options);

// Zero-padded trees are evaluated sparsely to avoid allocating 2**depth leaves.
function sparseTree(leaves,depth) {
  const levels=[new Map(leaves.map((leaf,i)=>[i,leaf]))],zeros=[0n];
  for(let d=0;d<depth;d++) {
    const current=levels[d],next=new Map();
    zeros.push(P(zeros[d],zeros[d]));
    for(const parent of new Set([...current.keys()].map(i=>Math.floor(i/2))))
      next.set(parent,P(current.get(parent*2)??zeros[d],current.get(parent*2+1)??zeros[d]));
    levels.push(next);
  }
  return {root:levels[depth].get(0)??zeros[depth],path(index) {
    const siblings=[],bits=[];
    for(let d=0;d<depth;d++) {
      bits.push(index%2);
      siblings.push(levels[d].get(index%2?index-1:index+1)??zeros[d]);
      index=Math.floor(index/2);
    }
    return {siblings,bits};
  }};
}

async function measure(repeat) {
  const setup=readJSON(path.join(ROOT,'build/depth/setup.json'));
  assert.equal(setup.status,'complete');
  assert.equal(setup.originalSourceSha256,hashFile(path.join(ROOT,'circuits/eat.circom')));
  const backend=new F3BCrypto(),rows=[],batches=[];
  const fd=fs.openSync(path.join(options.out,'artifacts.jsonl'),'w');
  try {
    const base=await fixture();
    await backend.setup(8,4);
    const orders=[cfg.depths,[...cfg.depths].reverse(),[...cfg.depths.slice(1),cfg.depths[0]]];
    for(const depth of orders[repeat%orders.length]) {
      const p={...base.policy};
      const bt=sparseTree(base.senders.map(s=>fold(20,[s.bond,p.version,p.epoch,s.deposit])),depth);
      const st=sparseTree(base.senders.map(s=>fold(30,[BigInt(s.wallet.address),s.balance,s.referenceNonce])),depth);
      if(depth===4) {
        assert.equal(bt.root,p.bondRoot);assert.equal(st.root,p.stateRoot);
        base.senders.forEach((s,i)=>{
          assert.deepEqual(bt.path(i),s.bondPath);assert.deepEqual(st.path(i),s.statePath);
        });
      }
      p.bondRoot=bt.root;p.stateRoot=st.root;
      const fx={policy:p,senders:base.senders.map((s,i)=>({...s,bondPath:bt.path(i),statePath:st.path(i)}))};
      const artifacts=path.join(ROOT,setup.circuits[depth].directory);
      assert.equal(hashFile(path.join(artifacts,'eat_final.zkey')),setup.circuits[depth].zkeySha256);
      assert.equal(hashFile(path.join(artifacts,'eat_js/eat.wasm')),setup.circuits[depth].wasmSha256);
      const vk=readJSON(path.join(artifacts,'verification_key.json'));
      const prove=index=>makeTicket(fx,index,{
        label:`depth/${depth}/${repeat}/${index}`,artifacts,
        encryptor:async message=>(await backend.encrypt(message,'chain=31337/epoch=1/TDH2-depth/v1')).cipher,
      });
      for(let i=0;i<2;i++) {
        const r=await prove(i);
        assert.equal(await groth16.verify(vk,r.publicSignals,r.proof),true);
        if(i===0) {
          const wrong=[...r.publicSignals];wrong[2]=(BigInt(wrong[2])+1n).toString();
          assert.equal(await groth16.verify(vk,wrong,r.proof),false);
        }
      }
      const records=[];
      for(let index=0;index<cfg.depthSamples;index++) {
        records.push(await prove(index));
        if((index+1)%32===0)console.log(`Depth ${depth}: ${index+1}/${cfg.depthSamples}`);
      }
      const seen=new Set();
      for(const r of records) {
        assert.equal(await groth16.verify(vk,r.publicSignals,r.proof),true);
        assert.ok(!seen.has(r.publicSignals[7]));seen.add(r.publicSignals[7]);
        rows.push({depth,n:cfg.depthSamples,repeat,index:r.index,proofMs:r.metrics.proofMs,threads:r.metrics.proverThreads});
        fs.writeSync(fd,json({depth,repeat,index:r.index,proof:r.proof,publicSignals:r.publicSignals,raw:r.raw},0)+'\n');
      }
      const total=records.reduce((s,r)=>s+r.metrics.proofMs,0);
      batches.push({depth,n:cfg.depthSamples,repeat,proofCount:records.length,proofTotalMs:total,proofMeanMs:total/records.length});
      console.log(`Depth ${depth}, repetition ${repeat+1}: ${(total/records.length).toFixed(2)} ms per proof`);
    }
    assert.equal(rows.length,cfg.depths.length*cfg.depthSamples);
    assert.equal(new Set(rows.map(r=>r.threads)).size,1);
    return {rows,batches};
  } finally {fs.closeSync(fd);await backend.close();await closeProver();}
}

try {
  let rows=[],batches=[];
  if(options.repeat!==undefined) {
    const repeat=Number(options.repeat);
    assert.ok(Number.isInteger(repeat)&&repeat>=0&&repeat<cfg.repeats);
    ({rows,batches}=await measure(repeat));
  } else {
    for(let repeat=0;repeat<cfg.repeats;repeat++) {
      const out=path.join(options.out,`repeat-${repeat}`);
      const result=spawnSync(process.execPath,[import.meta.filename,'--profile',options.profile,'--out',out,'--repeat',String(repeat)],{stdio:'inherit'});
      if(result.error||result.status!==0)throw result.error??new Error(`Depth repetition ${repeat} failed`);
      assert.equal(readJSON(path.join(out,'manifest.json')).status,'complete');
      rows.push(...readJSON(path.join(out,'transactions.json')));
      batches.push(...readJSON(path.join(out,'batches.json')));
    }
    assert.equal(rows.length,cfg.depths.length*cfg.depthSamples*cfg.repeats);
  }
  saveRows(options.out,'transactions',rows);saveRows(options.out,'batches',batches);
  run.manifest.proverThreads=[...new Set(rows.map(r=>r.threads))];run.finish();
} catch(error) {run.fail(error);throw error;}
