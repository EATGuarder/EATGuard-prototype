import fs from 'node:fs';
import path from 'node:path';
import ganache from 'ganache';
import {BrowserProvider,ContractFactory,recoverAddress,keccak256} from 'ethers';
import {poseidonContract} from 'circomlibjs';
import {performance} from 'node:perf_hooks';
import assert from 'node:assert/strict';
import {ROOT,CHAIN,mnemonic,wallets,ABI,bytes,batchTree,decodeTicket,encodeTicket,cipherHash,verifyTicket,evidence,encodeEvidence,decrypt,payloadFault} from './crypto.mjs';

export const STATE={MISSING:0n,PENDING:1n,ADMISSION_FINAL:2n,FINALIZED:3n,REJECTED:4n};
const artifacts=()=>JSON.parse(fs.readFileSync(path.join(ROOT,'build/contracts.json')));
export async function chain(fx,{senderSlashing=true}={}) {
  const rpc=ganache.provider({logging:{quiet:true},wallet:{mnemonic,totalAccounts:10,defaultBalance:1000},chain:{chainId:Number(CHAIN),hardfork:'shanghai',time:new Date('2026-01-01T00:00:00Z')},miner:{blockGasLimit:30_000_000,instamine:'eager',timestampIncrement:0}});
  // Avoid cached receipts after evm_revert.
  const provider=new BrowserProvider(rpc,undefined,{cacheTimeout:-1});provider.pollingInterval=10;
  const signers=await Promise.all(wallets.map((_,i)=>provider.getSigner(i)));
  const contracts=artifacts(); const setupGas=[];
  async function deploy(file,name,args=[]) {
    const a=contracts[file][name];
    if(a.evm.deployedBytecode.object.length/2>24576)throw new Error(`${name} exceeds EIP-170`);
    const c=await new ContractFactory(a.abi,a.evm.bytecode.object,signers[0]).deploy(...args);
    const receipt=await c.deploymentTransaction().wait();setupGas.push({name,gas:receipt.gasUsed});return c;
  }
  const verifier=await deploy('Groth16Verifier.sol','Groth16Verifier');
  const hash=await new ContractFactory(poseidonContract.generateABI(2),poseidonContract.createCode(2),signers[0]).deploy();
  setupGas.push({name:'Poseidon2',gas:(await hash.deploymentTransaction().wait()).gasUsed});
  const now=async()=>Number((await rpc.request({method:'eth_getBlockByNumber',params:['latest',false]})).timestamp);
  const config={...fx.policy,epochEnd:BigInt(await now())+86400n,admissionWindow:10n,staticWindow:20n,maxBatch:128n,maxTicket:8192n,tdn:wallets[6].address};
  const guard=await deploy('EATGuard.sol','EATGuard',[config,await verifier.getAddress(),await hash.getAddress(),senderSlashing]);
  for(let i=0;i<fx.senders.length;i++) {
    const s=fx.senders[i];setupGas.push({name:`activateBond/${i}`,gas:(await(await guard.connect(signers[i]).activateBond(s.bond,{value:s.deposit})).wait()).gasUsed});
  }
  setupGas.push({name:'freezeEpochSnapshot',gas:(await(await guard.freeze()).wait()).gasUsed});
  setupGas.push({name:'fundBuilder',gas:(await(await guard.connect(signers[4]).fundBuilder({value:10n**18n})).wait()).gasUsed});
  const basic=await deploy('NormalBaselines.sol','BasicEM');
  const onchain=await deploy('NormalBaselines.sol','OnChainEAT',[await guard.getAddress()]);
  const env={rpc,provider,signers,guard,basic,onchain,fx,config,batches:[],setupGas,now};
  env.advance=async seconds=>{await rpc.request({method:'evm_increaseTime',params:[seconds]});await rpc.request({method:'evm_mine',params:[]});};
  env.snapshot=async()=>({id:await rpc.request({method:'evm_snapshot',params:[]}),length:env.batches.length});
  env.restore=async snap=>{if(!await rpc.request({method:'evm_revert',params:[snap.id]}))throw new Error('snapshot restore failed');env.batches.length=snap.length;};
  env.close=async()=>{provider.destroy();await rpc.disconnect();};
  return env;
}
export async function commit(env,records) {
  const id=Number(await env.guard.count())+1;
  const raws=records.map(r=>typeof r==='string'?r:r.raw);
  const tree=batchTree(id,raws);
  const tx=await env.guard.connect(env.signers[4]).commit(tree.root,raws.length,{gasLimit:1_000_000});
  const receipt=await tx.wait();
  const batch={id,raws,records,tree,receipt,commitGas:receipt.gasUsed};env.batches.push(batch);return batch;
}
export async function admissionCheck(raw,fx,seen=new Set()) {
  let t;
  try {if(bytes(raw)>8192)throw new Error('size');t=decodeTicket(raw);if(encodeTicket(t)!==raw)throw new Error('canonical');}catch{return 0;}
  const p=fx.policy,x=t.x;
  if(x[0]!==p.version||x[1]!==p.epoch||x[2]!==p.bondRoot||x[3]!==p.stateRoot||x[8]!==p.quota||x[9]!==p.quota*p.deltaU||x[10]===0n||x[10]>30_000_000n)return 1;
  if(x[5]!==cipherHash(t.cipher))return 2;
  if(seen.has(x[7].toString()))return 3;
  if(!await verifyTicket(t))return 4;
  seen.add(x[7].toString());return null;
}
export async function audit(env,target) {
  const seen=new Set(),start=performance.now();
  for(const b of env.batches) {
    if(b.id>target.id)break;
    if(await env.guard.status(b.id)===STATE.REJECTED)continue;
    for(let i=0;i<b.raws.length;i++) {
      const reason=await admissionCheck(b.raws[i],env.fx,seen);
      if(reason!==null)return {ok:false,batchId:b.id,index:i,reason,elapsedMs:performance.now()-start};
    }
  }
  return {ok:true,elapsedMs:performance.now()-start};
}
export async function certify(env,batch,index) {
  if(await env.guard.status(batch.id)!==STATE.ADMISSION_FINAL)throw new Error('TDN requires admission finality');
  const checked=await audit(env,batch);
  if(!checked.ok)throw new Error(`TDN audit failed: ${checked.batchId}/${checked.index}/${checked.reason}`);
  const ticket=decodeTicket(batch.raws[index]);
  const start=performance.now();
  const message=decrypt(ticket.cipher);
  const digest=await env.guard.certificateDigest(batch.id,index,ticket.x[5],message);
  const certificate=wallets[6].signingKey.sign(digest).serialized;
  return {message,certificate,decryptionAndCertificationMs:performance.now()-start,auditMs:checked.elapsedMs};
}
export async function certifyBatch(env,batch) {
  if(await env.guard.status(batch.id)!==STATE.ADMISSION_FINAL)throw new Error('TDN requires admission finality');
  const checked=await audit(env,batch);if(!checked.ok)throw new Error('TDN audit failed');
  const address=await env.guard.getAddress();
  return batch.raws.map((raw,index)=>{
    const start=performance.now(),ticket=decodeTicket(raw),message=decrypt(ticket.cipher);
    const digest=keccak256(ABI.encode(['string','uint256','address','uint256','uint256','uint256','bytes32'],['EATGuard/TDN/v1',CHAIN,address,batch.id,index,ticket.x[5],keccak256(message)]));
    return {message,certificate:wallets[6].signingKey.sign(digest).serialized,decryptionAndCertificationMs:performance.now()-start,auditMs:checked.elapsedMs};
  });
}
export function staticReason(message,ticket) {
  const result=payloadFault(message,ticket);
  if(typeof result==='number')return result;
  try {return recoverAddress(result.digest,result.signature).toLowerCase()===('0x'+result.payload.fields[0].toString(16).padStart(40,'0')).toLowerCase()?null:7;}
  catch{return 7;}
}
export async function report(env,batch,index,reason,{earlier,reporter=5,certificate,extra={}}={}) {
  const start=performance.now();
  let supplied={};
  if(earlier)supplied={earlierId:earlier.batch.id,earlierRaw:earlier.batch.raws[earlier.index],earlierIndex:earlier.index,earlierPath:earlier.batch.tree.path(earlier.index)};
  if(reason>=5) {
    const c=certificate??await certify(env,batch,index);supplied={...supplied,message:c.message,certificate:c.certificate};
  }
  const ev=evidence(batch,index,{...supplied,...extra}),encoded=encodeEvidence(ev);
  const fault=reason<5?0:1;
  const calldata=env.guard.interface.encodeFunctionData('reportFault',[batch.id,fault,reason,encoded]);
  const constructionMs=performance.now()-start;
  const accountBalance=async address=>BigInt(await env.rpc.request({method:'eth_getBalance',params:[address,'latest']}));
  const beforeReporter=await accountBalance(wallets[reporter].address);
  const tx=await env.guard.connect(env.signers[reporter]).reportFault(batch.id,fault,reason,encoded,{gasLimit:10_000_000});
  const receipt=await tx.wait();
  const event=receipt.logs.map(l=>{try{return env.guard.interface.parseLog(l);}catch{return null;}}).find(l=>l?.name==='Penalized');
  const fee=receipt.gasUsed*receipt.gasPrice;
  const observedReward=await accountBalance(wallets[reporter].address)-beforeReporter+fee;
  assert.equal(observedReward,event.args.reward,'reward must reach the real reporter account');
  return {receipt,evidence:ev,metrics:{batchId:batch.id,n:batch.raws.length,index,reason,fault,constructionMs,evidenceBytes:bytes(encoded),calldataBytes:bytes(calldata),gas:receipt.gasUsed,fee,penalty:event.args.penalty,reward:observedReward,liable:event.args.liable,reporter:wallets[reporter].address}};
}
