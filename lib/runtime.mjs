import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {parseArgs} from 'node:util';
import {ROOT, json} from './crypto.mjs';

export const hashFile = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export const readJSON = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export const writeJSON = (file, data) => fs.writeFileSync(file, json(data) + '\n');

export function argumentsFor(stage) {
  const {values} = parseArgs({options: {
    profile: {type: 'string', default: 'full'},
    out: {type: 'string'},
    repeat: {type: 'string'},
  }});
  const profiles = readJSON(path.join(ROOT, 'config/profiles.json'));
  if (!profiles[values.profile]) throw new Error(`Unknown profile: ${values.profile}`);
  const out = values.out ? path.resolve(values.out) : path.join(ROOT, 'results', values.profile, stage);
  return {...values, out, config: profiles[values.profile]};
}

export function checkSetup() {
  const setup = readJSON(path.join(ROOT, 'build/setup.json'));
  if (setup.circuitHash !== hashFile(path.join(ROOT, 'circuits/eat.circom'))) {
    throw new Error('Circuit changed. Run npm run setup.');
  }
  const sources = Object.fromEntries(['build/Groth16Verifier.sol', 'contracts/EATGuard.sol', 'contracts/NormalBaselines.sol']
    .map(file => [path.basename(file), {content: fs.readFileSync(path.join(ROOT, file), 'utf8')}]));
  const hash = createHash('sha256').update(JSON.stringify(sources)).digest('hex');
  if (setup.contractHash !== hash) throw new Error('Contracts changed. Run npm run setup.');
  return setup;
}

export function sourceHashes() {
  const files = ['package.json', 'package-lock.json', 'config/profiles.json', 'requirements.txt'];
  for (const dir of ['circuits', 'contracts', 'lib', 'scripts', 'f3b', 'plots']) {
    for (const name of fs.readdirSync(path.join(ROOT, dir))) {
      if (/\.(mjs|sol|circom|go|mod|sum|py)$/.test(name)) files.push(`${dir}/${name}`);
    }
  }
  return Object.fromEntries(files.map(file => [file, hashFile(path.join(ROOT, file))]));
}

export function newRun(stage, options) {
  if (fs.existsSync(options.out) && fs.readdirSync(options.out).length) {
    throw new Error(`Output directory is not empty: ${options.out}. Choose --out with a new path.`);
  }
  fs.mkdirSync(options.out, {recursive: true});
  const manifest = {
    status: 'running', stage, profile: options.profile, config: options.config,
    startedAt: new Date().toISOString(),
    environment: {node: process.version, platform: process.platform, arch: process.arch,
      cpu: os.cpus()[0]?.model, logicalCPUs: os.cpus().length, memoryBytes: os.totalmem()},
    sourceHashes: sourceHashes(),
  };
  const save = () => writeJSON(path.join(options.out, 'manifest.json'), manifest);
  save();
  return {
    manifest, save,
    finish() {
      manifest.resultHashes = Object.fromEntries(fs.readdirSync(options.out)
        .filter(name => name !== 'manifest.json' && fs.statSync(path.join(options.out, name)).isFile())
        .map(name => [name, hashFile(path.join(options.out, name))]));
      manifest.status = 'complete'; manifest.finishedAt = new Date().toISOString(); save();
    },
    fail(error) {manifest.status = 'failed'; manifest.error = error.stack; save();},
  };
}

export function saveRows(out, name, rows) {
  writeJSON(path.join(out, `${name}.json`), rows);
  const keys = [...new Set(rows.flatMap(Object.keys))];
  const cell = value => {
    const text = value === undefined ? '' : typeof value === 'object' ? json(value, 0) : String(value);
    return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  };
  fs.writeFileSync(path.join(out, `${name}.csv`),
    [keys.join(','), ...rows.map(row => keys.map(key => cell(row[key])).join(','))].join('\n') + '\n');
}

export async function closeProver() {
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}
