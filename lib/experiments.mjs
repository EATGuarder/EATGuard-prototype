import assert from 'node:assert/strict';
import {mutated} from './crypto.mjs';
import {commit,report,certify,certifyBatch} from './chain.mjs';

export async function normalGas(env,pool,cfg) {
  const rows=[];
  for(const n of cfg.batchSizes)for(let repeat=0;repeat<cfg.repeats;repeat++) {
    const snap=await env.snapshot();
    try {
      const records=pool.normal.slice(0,n),b=await commit(env,records);
      rows.push({scheme:'EATGuard',n,repeat,gas:b.commitGas,gasPerEntry:Number(b.commitGas)/n,transactions:1});
      const basic=await(await env.basic.commit(b.tree.root,n)).wait();
      rows.push({scheme:'Basic-EM',n,repeat,gas:basic.gasUsed,gasPerEntry:Number(basic.gasUsed)/n,transactions:1});
      let total=0n;
      for(const r of records)total+=(await(await env.onchain.submitTicket(r.raw,{gasLimit:2_000_000})).wait()).gasUsed;
      total+=(await(await env.onchain.commit(b.tree.root,n)).wait()).gasUsed;
      rows.push({scheme:'On-chain EAT',n,repeat,gas:total,gasPerEntry:Number(total)/n,transactions:n+1});
    } finally {await env.restore(snap);}
  }
  return rows;
}
export async function individualReports(env,pool,cfg) {
  const rows=[];
  for(const n of cfg.batchSizes)for(const reason of [0,1,2,3,4,5,6,7]) {
    const snap=await env.snapshot();
    try {
      const records=pool.normal.slice(0,n);let earlier;
      if(reason===0)records[0]='0x1234';
      if(reason===1)records[0]=mutated(records[0],t=>t.x[0]='2');
      if(reason===2)records[0]=mutated(records[0],t=>t.x[5]='123');
      if(reason===3)earlier={batch:await commit(env,[records[0]]),index:0};
      if(reason===4)records[0]=mutated(records[0],t=>t.a=['0','0']);
      if(reason>=5)records[0]=pool[['encoding','binding','signature'][reason-5]][0];
      const b=await commit(env,records);let certificate;
      if(reason>=5) {await env.advance(11);certificate=await certify(env,b,0);}
      const result=await report(env,b,0,reason,{earlier,certificate});
      rows.push({...result.metrics,certificateAcquisitionMs:certificate?.decryptionAndCertificationMs??0,admissionAuditMs:certificate?.auditMs??0});
    }finally {await env.restore(snap);}
  }
  return rows;
}
export async function aggregateFaults(env,pool,cfg) {
  const rows=[],n=cfg.aggregateBatchSize,B=cfg.aggregateBatches,total=n*B;
  for(const family of ['admission','static'])for(const ratio of cfg.faultRatios) {
    const snap=await env.snapshot();
    try {
      const count=Math.round((family==='admission'?B:total)*ratio),batches=[];
      let normalGas=0n,reportGas=0n,reports=0;
      for(let j=0;j<B;j++) {
        const records=pool.normal.slice(j*n,(j+1)*n);
        if(family==='admission' && j<count)records[0]=mutated(records[0],t=>t.a=['0','0']);
        if(family==='static')for(let i=0;i<n;i++)if(j*n+i<count)records[i]=pool.signature[j*n+i];
        const b=await commit(env,records);batches.push(b);normalGas+=b.commitGas;
        if(family==='admission' && j<count) {reportGas+=(await report(env,b,0,4)).metrics.gas;reports++;}
      }
      if(family==='static' && count>0) {
        await env.advance(11);
        for(let j=0;j<B;j++) {
          if(j*n>=count)break;
          const b=batches[j],certificates=await certifyBatch(env,b);
          for(let i=0;i<n && j*n+i<count;i++) {reportGas+=(await report(env,b,i,7,{certificate:certificates[i]})).metrics.gas;reports++;}
        }
      }
      assert.equal(reports,count);
      rows.push({family,n,batches:B,totalEntries:total,requestedRatio:ratio,actualRatio:count/(family==='admission'?B:total),faultUnits:family==='admission'?'batches':'entries',faultCount:count,reports,normalGas,reportGas,totalGas:normalGas+reportGas,gasPerSubmittedEntry:Number(normalGas+reportGas)/total});
    }finally {await env.restore(snap);}
  }
  return rows;
}
