import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import path from 'node:path';
import {ROOT} from './crypto.mjs';

export class F3BCrypto {
 constructor() {
  this.pending=[];this.stderr='';
  this.child=spawn(path.join(ROOT,'build/f3b-crypto'),[],{stdio:['pipe','pipe','pipe']});
  this.child.stderr.on('data',d=>this.stderr+=d);
  createInterface({input:this.child.stdout}).on('line',line=>{
   const p=this.pending.shift();if(!p)return;
   try{const v=JSON.parse(line);v.error?p.reject(new Error(v.error)):p.resolve(v);}catch(e){p.reject(e);}
  });
  this.child.on('error',e=>{for(const p of this.pending.splice(0))p.reject(e);});
  this.closed=new Promise(resolve=>this.child.on('close',code=>{for(const p of this.pending.splice(0))p.reject(new Error(`TDH2 process closed ${code}: ${this.stderr}`));resolve(code);}));
 }
 call(req){return new Promise((resolve,reject)=>{this.pending.push({resolve,reject});this.child.stdin.write(JSON.stringify(req)+'\n');});}
 setup(n,k){return this.call({op:'setup',n,k});}
 encrypt(message,context){return this.call({op:'encrypt',message,context});}
 process(cipher,context,message){return this.call({op:'process',cipher,context,message});}
 async close(){this.child.stdin.end();return this.closed;}
}
