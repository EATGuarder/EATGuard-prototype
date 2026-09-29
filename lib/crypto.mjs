import {createHash,createECDH,createCipheriv,createDecipheriv} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {AbiCoder,HDNodeWallet,keccak256,concat,toBeHex,Signature} from 'ethers';
import {buildPoseidon} from 'circomlibjs';
import {groth16} from 'snarkjs';
import fs from 'node:fs';
import path from 'node:path';

export const ROOT=path.resolve(import.meta.dirname,'..');
export const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const CHAIN=31337n;
export const ABI=AbiCoder.defaultAbiCoder();
export const TICKET='tuple(bytes cipher,uint256[11] x,uint256[2] a,uint256[2][2] b,uint256[2] c)';
export const PAYLOAD='tuple(uint256[11] fields,uint256 opening)';
export const EVIDENCE='tuple(bytes raw,uint256 index,bytes32[] path,uint256 earlierId,bytes earlierRaw,uint256 earlierIndex,bytes32[] earlierPath,bytes message,bytes certificate)';
export const mnemonic='test test test test test test test test test test test junk';
export const wallets=Array.from({length:10},(_,i)=>HDNodeWallet.fromPhrase(mnemonic,undefined,`m/44'/60'/0'/0/${i}`));
export const sha=s=>createHash('sha256').update(s).digest();
export const hex=b=>'0x'+Buffer.from(b).toString('hex');
export const bytes=s=>(s.length-2)/2;
export const json=(x,space=2)=>JSON.stringify(x,(_,v)=>typeof v==='bigint'?v.toString():v,space);
export const clone=x=>JSON.parse(json(x));
export const encodeTicket=t=>ABI.encode([TICKET],[t]);
export function decodeTicket(raw) { const v=ABI.decode([TICKET],raw)[0]; return {cipher:v.cipher,x:Array.from(v.x),a:Array.from(v.a),b:v.b.map(x=>Array.from(x)),c:Array.from(v.c)}; }
export const encodePayload=p=>ABI.encode([PAYLOAD],[p]);
export function decodePayload(raw) {
  if(bytes(raw)!==384) throw new Error('payload length');
  const v=ABI.decode([PAYLOAD],raw)[0], p={fields:Array.from(v.fields),opening:v.opening};
  const widths=[160,160,32,64,32,64,128,128,128,128,8];
  if(p.opening>=FIELD || p.fields.some((x,i)=>x>=1n<<BigInt(widths[i]))) throw new Error('payload range');
  return p;
}
let hasher;
export async function initCrypto() { hasher??=await buildPoseidon(); }
export function P(a,b) { return hasher.F.toObject(hasher([BigInt(a),BigInt(b)])); }
export function fold(tag,values) {return values.reduce((h,x)=>P(h,x),BigInt(tag));}
export function poseidonTree(leaves,depth=4) {
  const rows=[Array.from({length:2**depth},(_,i)=>leaves[i]??0n)];
  for(let d=0;d<depth;d++) { const r=rows.at(-1); rows.push(Array.from({length:r.length/2},(_,i)=>P(r[2*i],r[2*i+1]))); }
  return {root:rows.at(-1)[0],path:index=>({siblings:rows.slice(0,-1).map((r,d)=>r[(index>>d)^1]),bits:Array.from({length:depth},(_,d)=>(index>>d)&1)})};
}
export function batchTree(id,raws) {
  let size=1;while(size<raws.length)size*=2;
  const zero=toBeHex(0,32);
  const rows=[Array.from({length:size},(_,i)=>i<raws.length?keccak256(ABI.encode(['string','uint256','uint256','bytes'],['EATGuard/leaf/v1',id,i,raws[i]])):zero)];
  while(rows.at(-1).length>1) { const r=rows.at(-1); rows.push(Array.from({length:r.length/2},(_,i)=>keccak256(concat([r[2*i],r[2*i+1]])))); }
  return {root:rows.at(-1)[0],path:index=>rows.slice(0,-1).map((r,d)=>r[(index>>d)^1])};
}
// Deterministic keys and nonces are test fixtures.
const tdnECDH=createECDH('secp256k1'); tdnECDH.setPrivateKey(sha('EATGuard/local-test/TDN'));
export function encrypt(message,label) {
  const eph=createECDH('secp256k1'); eph.setPrivateKey(sha('ephemeral/'+label));
  const key=sha(eph.computeSecret(tdnECDH.getPublicKey()));
  const iv=sha('iv/'+label).subarray(0,12);
  const aes=createCipheriv('aes-256-gcm',key,iv);
  const ciphertext=Buffer.concat([aes.update(Buffer.from(message.slice(2),'hex')),aes.final()]);
  return hex(Buffer.concat([eph.getPublicKey(undefined,'compressed'),iv,ciphertext,aes.getAuthTag()]));
}
export function decrypt(cipher) {
  const b=Buffer.from(cipher.slice(2),'hex');
  const key=sha(tdnECDH.computeSecret(b.subarray(0,33)));
  const aes=createDecipheriv('aes-256-gcm',key,b.subarray(33,45));
  aes.setAuthTag(b.subarray(-16));
  return hex(Buffer.concat([aes.update(b.subarray(45,-16)),aes.final()]));
}
export const cipherHash=c=>BigInt(keccak256(ABI.encode(['string','bytes'],['EATGuard/cipher/v1',c])))%FIELD;
export const commitment=(p,h)=>fold(60,[fold(50,p.fields),p.opening,h]);
export function txDigest(fields) {return keccak256(ABI.encode(['string',...Array(7).fill('uint256')],['EATGuard/transfer/v1',CHAIN,...fields.slice(0,6)]));}
export function payloadFault(raw,ticket) {
  let p;try {p=decodePayload(raw);}catch{return 5;}
  if(commitment(p,ticket.x[5])!==BigInt(ticket.x[6]))return 6;
  try {
    const f=p.fields;
    const sig=Signature.from({r:toBeHex(f[6]+(f[7]<<128n),32),s:toBeHex(f[8]+(f[9]<<128n),32),v:Number(f[10])});
    return {payload:p,signature:sig,digest:txDigest(f)};
  }catch{return 7;}
}
export async function fixture(config={}) {
  await initCrypto();
  const {senderCount=4,...overrides}=config;
  const p={version:1n,epoch:1n,quota:256n,deltaU:10_000_000_000_000_000n,deltaB:100_000_000_000_000_000n,rewardBps:2000n,...overrides};
  const senders=wallets.slice(0,senderCount).map((wallet,i)=>({wallet,secret:BigInt('0x'+sha('bond/'+i).toString('hex'))%FIELD,balance:10n**22n,referenceNonce:0n,deposit:p.quota*p.deltaU}));
  senders.forEach(s=>s.bond=fold(10,[s.secret]));
  const bt=poseidonTree(senders.map(s=>fold(20,[s.bond,p.version,p.epoch,s.deposit])));
  const st=poseidonTree(senders.map(s=>fold(30,[BigInt(s.wallet.address),s.balance,s.referenceNonce])));
  senders.forEach((s,i)=>{s.bondPath=bt.path(i);s.statePath=st.path(i);});
  return {policy:{...p,bondRoot:bt.root,stateRoot:st.root},senders};
}
export function preparePayload(fx,index,{kind='normal',senderIndex=index%4,label=`${kind}/${index}`}={}) {
  const s=fx.senders[senderIndex], p=fx.policy;
  let fields=[BigInt(s.wallet.address),BigInt(wallets[9].address),s.referenceNonce,1000n+BigInt(index),21000n,1_000_000_000n];
  const signer=kind==='signature'?wallets[8]:s.wallet;
  const sig=signer.signingKey.sign(txDigest(fields));
  const mask=(1n<<128n)-1n;
  fields.push(BigInt(sig.r)&mask,BigInt(sig.r)>>128n,BigInt(sig.s)&mask,BigInt(sig.s)>>128n,BigInt(sig.v));
  const payload={fields,opening:BigInt('0x'+sha('opening/'+label).toString('hex'))%FIELD};
  let message=encodePayload(payload);
  if(kind==='encoding')message='0x123456';
  if(kind==='binding') {const other={fields:[...fields],opening:payload.opening};other.fields[3]+=1n;message=encodePayload(other);}
  return {payload,message,fields};
}
export async function makeTicket(fx,index,{kind='normal',senderIndex=index%4,slot=Math.floor(index/4),label=`${kind}/${index}`,encryptor=encrypt,artifacts=path.join(ROOT,'build')}={}) {
  const s=fx.senders[senderIndex], p=fx.policy,start=performance.now();
  const {payload,message,fields}=preparePayload(fx,index,{kind,senderIndex,label});
  const payloadMs=performance.now()-start;
  const beforeEncryption=performance.now();
  const cipher=await encryptor(message,label);const encryptionMs=performance.now()-beforeEncryption;
  const h=cipherHash(cipher),cm=commitment(payload,h),nu=fold(40,[s.secret,p.version,p.epoch,slot]);
  const input={version:p.version,epoch:p.epoch,bondRoot:p.bondRoot,stateRoot:p.stateRoot,bond:s.bond,cipherHash:h,commitment:cm,nullifier:nu,quota:p.quota,minimum:p.quota*p.deltaU,resourceGas:fields[4],secret:s.secret,deposit:s.deposit,slot,bondSiblings:s.bondPath.siblings,bondBits:s.bondPath.bits,stateSiblings:s.statePath.siblings,stateBits:s.statePath.bits,balance:s.balance,referenceNonce:s.referenceNonce,tx:fields,opening:payload.opening};
  const beforeProof=performance.now();
  const {proof,publicSignals}=await groth16.fullProve(JSON.parse(json(input)),path.join(artifacts,'eat_js/eat.wasm'),path.join(artifacts,'eat_final.zkey'));
  const proofMs=performance.now()-beforeProof;
  const calldata=JSON.parse(`[${await groth16.exportSolidityCallData(proof,publicSignals)}]`);
  const ticket={cipher,x:calldata[3],a:calldata[0],b:calldata[1],c:calldata[2]},raw=encodeTicket(ticket);
  return {ticket,raw,proof,publicSignals,message,payload,input,kind,index,senderIndex,metrics:{prepareMs:performance.now()-start,payloadMs,encryptionMs,proofMs,preProofMs:beforeProof-start,rawBytes:bytes(raw),cipherBytes:bytes(cipher),proofBytes:256,proverThreads:globalThis.curve_bn128?.tm.concurrency??1}};
}
let vk;
export async function verifyTicket(t) {
  vk??=JSON.parse(fs.readFileSync(path.join(ROOT,'build/verification_key.json')));
  const proof={pi_a:[...t.a,'1'],pi_b:[[t.b[0][1],t.b[0][0]],[t.b[1][1],t.b[1][0]],['1','0']],pi_c:[...t.c,'1'],protocol:'groth16',curve:'bn128'};
  try{return await groth16.verify(vk,t.x,proof);}catch{return false;}
}
export const verifyRecord=r=>verifyTicket(r.ticket);
export function mutated(record,edit) {
  const t=clone(record.ticket);edit(t);return {...record,ticket:t,raw:encodeTicket(t)};
}
export function evidence(batch,index,extra={}) {
  return {raw:batch.raws[index],index,path:batch.tree.path(index),earlierId:0,earlierRaw:'0x',earlierIndex:0,earlierPath:[],message:'0x',certificate:'0x',...extra};
}
export const encodeEvidence=e=>ABI.encode([EVIDENCE],[e]);
