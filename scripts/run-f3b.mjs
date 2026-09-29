import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {fixture,preparePayload,makeTicket,sha,json,bytes,batchTree,mutated,cipherHash} from '../lib/crypto.mjs';
import {admissionCheck} from '../lib/chain.mjs';
import {F3BCrypto} from '../lib/f3b.mjs';
import {argumentsFor,checkSetup,newRun,saveRows,writeJSON,closeProver} from '../lib/runtime.mjs';

const options=argumentsFor('f3b'),cfg=options.config,out=options.out;
checkSetup();
const run=newRun('f3b',options),manifest=run.manifest;
manifest.setup=[];
const save=(name,data)=>writeJSON(path.join(out,name),data);
const hash=s=>sha(s).toString('hex');
const backend=new F3BCrypto(),txs=[],batches=[];
const artifacts=fs.openSync(path.join(out,'artifacts.jsonl'),'w');
try {
 const fx=await fixture();manifest.setup.push(await backend.setup(8,4));
 const context='chain=31337/epoch=1/TDH2-normal/v1';
 for(let i=0;i<20;i++){const p=preparePayload(fx,i);const e=await backend.encrypt(p.message,context);await backend.process(e.cipher,context,p.message);}
 let warm;
 for(let i=0;i<2;i++){warm=await makeTicket(fx,i,{encryptor:async m=>(await backend.encrypt(m,context)).cipher});assert.equal(await admissionCheck(warm.raw,fx,new Set()),null);await backend.process(warm.ticket.cipher,context,warm.message);}
 assert.equal(BigInt(warm.ticket.x[5]),cipherHash(warm.ticket.cipher));
 assert.equal(await admissionCheck(mutated(warm,t=>t.cipher=t.cipher.slice(0,-2)+'ff').raw,fx,new Set()),2);
 assert.equal(await admissionCheck(mutated(warm,t=>t.a=['0','0']).raw,fx,new Set()),4);
 await assert.rejects(backend.process(warm.ticket.cipher,'wrong-epoch',warm.message));
 manifest.integrationChecks=['TDH2 roundtrip matches EAT plaintext','EAT public hash binds actual TDH2 envelope','tampered TDH2 envelope rejected by admission','tampered Groth16 proof rejected','cross-epoch TDH2 label rejected'];
 console.log(`F3B comparison: ${options.profile}`);
 let pair=0;
 for(const n of cfg.batchSizes)for(let repeat=0;repeat<cfg.repeats;repeat++) {
  const order=pair%2?['EATGuard','F3B-TDH2']:['F3B-TDH2','EATGuard'];
  const messages=new Map();
  for(const scheme of order) {
   const records=[],sampleRows=[];
   for(let i=0;i<n;i++) {
    const label=`paired/${n}/${repeat}/${i}`;
    let payload,message,encrypted,record,payloadMs,proofMs=0,eatBuildMs=0;
    if(scheme==='EATGuard') {
     record=await makeTicket(fx,i,{label,encryptor:async m=>{encrypted=await backend.encrypt(m,context);return encrypted.cipher;}});
     ({payload,message}=record);({payloadMs,proofMs}=record.metrics);
     eatBuildMs=record.metrics.prepareMs-record.metrics.encryptionMs-payloadMs;
     assert.equal(BigInt(record.ticket.x[5]),cipherHash(encrypted.cipher));
    }else{
     const t=performance.now();({payload,message}=preparePayload(fx,i,{label}));payloadMs=performance.now()-t;
     encrypted=await backend.encrypt(message,context);
    }
    if(messages.has(i))assert.equal(message,messages.get(i));else messages.set(i,message);
    const row={scheme,n,repeat,index:i,committee:8,threshold:4,pair,order:order.indexOf(scheme),messageHash:hash(message),cipherHash:hash(encrypted.cipher),payloadMs,proofMs,eatBuildMs,...encrypted.metrics,clientMs:payloadMs+encrypted.metrics.encryptMs+eatBuildMs,cipherBytes:bytes(encrypted.cipher),ticketBytes:record?bytes(record.raw):bytes(encrypted.cipher),extraBytes:record?bytes(record.raw)-bytes(encrypted.cipher):0};
    sampleRows.push(row);records.push({...record,raw:record?.raw??encrypted.cipher,message,cipher:encrypted.cipher});
   }
   let t=performance.now();const root=batchTree(pair+1,records.map(r=>r.raw)).root;const builderMerkleMs=performance.now()-t;
   let builderAuditMs=0,validatorAuditMs=0;
   if(scheme==='EATGuard'){t=performance.now();const seen=new Set();for(const r of records)assert.equal(await admissionCheck(r.raw,fx,seen),null);builderAuditMs=performance.now()-t;}
   t=performance.now();assert.equal(batchTree(pair+1,records.map(r=>r.raw)).root,root);const validatorMerkleMs=performance.now()-t;
   if(scheme==='EATGuard'){t=performance.now();const seen=new Set();for(const r of records)assert.equal(await admissionCheck(r.raw,fx,seen),null);validatorAuditMs=performance.now()-t;}
   for(let i=0;i<n;i++) {
    const r=records[i],row=sampleRows[i];
    const recovered=await backend.process(r.cipher,context,r.message);assert.equal(recovered.message,r.message);
    Object.assign(row,recovered.metrics,{roundtrip:true});txs.push(row);
    fs.writeSync(artifacts,json({scheme,n,repeat,index:i,context,message:r.message,cipher:r.cipher,eatRaw:scheme==='EATGuard'?r.raw:undefined,hash:row.cipherHash},0)+'\n');
   }
   const sum=k=>sampleRows.reduce((s,r)=>s+r[k],0);
   batches.push({scheme,n,repeat,pair,order:order.indexOf(scheme),clientMs:sum('clientMs'),proofMs:sum('proofMs'),eatBuildMs:sum('eatBuildMs'),encryptMs:sum('encryptMs'),receiverCipherVerifyMs:sum('receiverCipherVerifyMs'),trusteeWorkPerMemberMs:sum('trusteeWorkPerMemberMs'),receiverRecoveryMs:sum('receiverRecoveryMs'),cryptoSerialWorkMs:sum('encryptMs')+sum('processSerialWorkMs'),builderAuditMs,validatorAuditMs,builderMerkleMs,validatorMerkleMs,extraBytes:sum('extraBytes')});
   console.log(`${scheme}: batch ${n}, repetition ${repeat+1}/${cfg.repeats} complete`);
   save('transactions.json',txs);save('batches.json',batches);
  };pair++;
 }
 assert.equal(txs.length,2*cfg.repeats*cfg.batchSizes.reduce((a,b)=>a+b,0));
 assert.equal(batches.length,2*cfg.repeats*cfg.batchSizes.length);
 for(const rows of [txs,batches])for(const r of rows)for(const [k,v]of Object.entries(r))
  if(typeof v==='number')assert.ok(Number.isFinite(v)&&v>=0,`${k} invalid`);
 saveRows(out,'transactions',txs);saveRows(out,'batches',batches);
 manifest.measuredEATProofs=txs.filter(r=>r.scheme==='EATGuard').length;
 manifest.proverThreads=globalThis.curve_bn128?.tm.concurrency;
 run.finish();
}catch(error){run.fail(error);throw error;}
finally{fs.closeSync(artifacts);await backend.close();await closeProver();}
