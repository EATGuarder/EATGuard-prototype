import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const root=path.resolve(import.meta.dirname,'..');
const dest=path.join(root,'build/depth');
const circom=process.env.CIRCOM ?? 'circom';
const snark=path.join(root,'node_modules/snarkjs/build/cli.cjs');
const sha=f=>createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const source=fs.readFileSync(path.join(root,'circuits/eat.circom'),'utf8');
const depths=[4,8,16,24];
const metadataFile=path.join(dest,'setup.json');
if(fs.existsSync(metadataFile)) {
 const cached=JSON.parse(fs.readFileSync(metadataFile));
 if(cached.status==='complete' && cached.originalSourceSha256===sha(path.join(root,'circuits/eat.circom')) &&
   depths.every(depth=>{
    const c=cached.circuits[depth],dir=path.join(root,c?.directory??'');
    return c && ['eat_final.zkey','eat_js/eat.wasm','verification_key.json'].every(f=>fs.existsSync(path.join(dir,f))) &&
      c.zkeySha256===sha(path.join(dir,'eat_final.zkey')) && c.wasmSha256===sha(path.join(dir,'eat_js/eat.wasm'));
   })) {console.log('Depth circuits are up to date.');process.exit(0);}
}
fs.mkdirSync(dest,{recursive:true});
function run(cmd,args){
 const r=spawnSync(cmd,args,{cwd:root,encoding:'utf8',timeout:900_000,maxBuffer:8*1024*1024});
 if(r.status!==0||r.error)throw new Error(`${r.error??r.status}\n${r.stdout}\n${r.stderr}`);
 return r.stdout;
}
const metadata={status:'compiling',depths,circuits:{},originalSourceSha256:sha(path.join(root,'circuits/eat.circom')),setupScope:'Local benchmark keys'};
for(const depth of depths){
 const dir=path.join(dest,`d${depth}`);fs.mkdirSync(dir,{recursive:true});
 const src=source.replaceAll('../node_modules/','../../../node_modules/').replace('= EAT(4);',`= EAT(${depth});`);
 if(src===source)throw new Error('Expected circuit source structure');
 fs.writeFileSync(path.join(dir,'eat.circom'),src);
 console.log(`Compiling both Merkle paths at depth ${depth}`);
 console.log(run(circom,[path.join(dir,'eat.circom'),'--O2','--r1cs','--wasm','-o',dir]));
 const info=run(process.execPath,[snark,'r1cs','info',path.join(dir,'eat.r1cs')]);
 console.log(info);
 metadata.circuits[depth]={directory:path.relative(root,dir),sourceSha256:sha(path.join(dir,'eat.circom')),r1csSha256:sha(path.join(dir,'eat.r1cs')),info};
}
fs.writeFileSync(path.join(dest,'setup.json'),JSON.stringify(metadata,null,2)+'\n');
let maxConstraints=0;
for(const c of Object.values(metadata.circuits)){
 const clean=c.info.replace(/\x1b\[[0-9;]*m/g,'');
 const match=clean.match(/# of Constraints:\s*(\d+)/);
 if(!match)throw new Error('Unable to read constraint count');
 c.constraints=Number(match[1]);maxConstraints=Math.max(maxConstraints,c.constraints);
}
const power=Math.max(14,Math.ceil(Math.log2(maxConstraints+32)));
let ptau=path.join(root,`build/pot${power}_final.ptau`);
if(!fs.existsSync(ptau)){
 ptau=path.join(dest,`pot${power}_final.ptau`);
 if(!fs.existsSync(ptau)){
  console.log(`Preparing local benchmark parameters (power ${power})`);
  const p0=path.join(dest,`pot${power}_0.ptau`),p1=path.join(dest,`pot${power}_1.ptau`);
  run(process.execPath,[snark,'powersoftau','new','bn128',String(power),p0]);
  run(process.execPath,[snark,'powersoftau','contribute',p0,p1,'--name=depth','-e=EATGuard-local-test-only']);
  run(process.execPath,[snark,'powersoftau','prepare','phase2',p1,ptau]);
 }
}
for(const depth of depths){
 const dir=path.join(dest,`d${depth}`);
 console.log(`Preparing depth ${depth} proving key`);
 run(process.execPath,[snark,'groth16','setup',path.join(dir,'eat.r1cs'),ptau,path.join(dir,'eat_0.zkey')]);
 run(process.execPath,[snark,'zkey','contribute',path.join(dir,'eat_0.zkey'),path.join(dir,'eat_final.zkey'),'--name=depth','-e=EATGuard-depth-local-only']);
 run(process.execPath,[snark,'zkey','export','verificationkey',path.join(dir,'eat_final.zkey'),path.join(dir,'verification_key.json')]);
 metadata.circuits[depth].zkeySha256=sha(path.join(dir,'eat_final.zkey'));
 metadata.circuits[depth].wasmSha256=sha(path.join(dir,'eat_js/eat.wasm'));
 console.log(`Depth ${depth} ready`);
}
metadata.status='complete';metadata.ptauSha256=sha(ptau);metadata.finishedAt=new Date().toISOString();
fs.writeFileSync(path.join(dest,'setup.json'),JSON.stringify(metadata,null,2)+'\n');
