import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import solc from 'solc';

const root=path.resolve(import.meta.dirname,'..'); process.chdir(root);
fs.mkdirSync('build',{recursive:true});
const circom=process.env.CIRCOM ?? 'circom';
const snark=path.resolve('node_modules/snarkjs/build/cli.cjs');
function run(cmd,args) {
  console.log(`Setup: ${path.basename(cmd)} ${args.slice(0,3).join(' ')}`);
  const r=spawnSync(cmd,args,{stdio:'inherit',timeout:900_000});
  if(r.error || r.status!==0) throw r.error ?? new Error(`Setup exited ${r.status}`);
}
const source=fs.readFileSync('circuits/eat.circom');
const hash=createHash('sha256').update(source).digest('hex');
const previous=fs.existsSync('build/setup.json') ? JSON.parse(fs.readFileSync('build/setup.json')) : {};
const outputs=['eat_final.zkey','eat_js/eat.wasm','verification_key.json','Groth16Verifier.sol'];
if(previous.circuitHash!==hash || outputs.some(file=>!fs.existsSync(path.join('build',file)))) {
  run(circom,['circuits/eat.circom','--O2','--r1cs','--wasm','--sym','-o','build']);
  if(!fs.existsSync('build/pot14_final.ptau')) {
    run(process.execPath,[snark,'powersoftau','new','bn128','14','build/pot14_0.ptau']);
    run(process.execPath,[snark,'powersoftau','contribute','build/pot14_0.ptau','build/pot14_1.ptau','--name=local-benchmark','-e=EATGuard-local-test-only-not-a-production-ceremony']);
    run(process.execPath,[snark,'powersoftau','prepare','phase2','build/pot14_1.ptau','build/pot14_final.ptau']);
  }
  run(process.execPath,[snark,'groth16','setup','build/eat.r1cs','build/pot14_final.ptau','build/eat_0.zkey']);
  run(process.execPath,[snark,'zkey','contribute','build/eat_0.zkey','build/eat_final.zkey','--name=local-benchmark','-e=EATGuard-local-test-only-phase2']);
  run(process.execPath,[snark,'zkey','export','verificationkey','build/eat_final.zkey','build/verification_key.json']);
  run(process.execPath,[snark,'zkey','export','solidityverifier','build/eat_final.zkey','build/Groth16Verifier.sol']);
}
const files=['build/Groth16Verifier.sol','contracts/EATGuard.sol','contracts/NormalBaselines.sol'];
const sources=Object.fromEntries(files.map(f=>[path.basename(f),{content:fs.readFileSync(f,'utf8')}]));
const input={language:'Solidity',sources,settings:{optimizer:{enabled:true,runs:200},viaIR:true,evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}};
const output=JSON.parse(solc.compile(JSON.stringify(input)));
for(const err of output.errors ?? []) console.log(err.formattedMessage);
if(output.errors?.some(e=>e.severity==='error')) throw new Error('Solidity compilation failed');
fs.writeFileSync('build/contracts.json',JSON.stringify(output.contracts,null,2));
const metadata={circuitHash:hash,contractHash:createHash('sha256').update(JSON.stringify(sources)).digest('hex'),node:process.version,solc:solc.version(),circom:spawnSync(circom,['--version'],{encoding:'utf8'}).stdout.trim(),trustedSetup:'LOCAL TEST ONLY; public deterministic entropy; never use these keys in production',createdAt:new Date().toISOString()};
fs.writeFileSync('build/setup.json',JSON.stringify(metadata,null,2));
console.log('Circuit and contracts built.');
