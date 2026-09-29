# EATGuard

Source code for the paper: A DoS-Resistant Encrypted Blockchain Mempool with Stage-Aware Accountability, including the admission circuit, accountability contracts, and evaluation scripts.

## Requirements

The EAT prototype requires Node.js 20.11 or later and Circom 2.2.3. Reproducing the experiments also requires Go 1.23 or later and Python 3.10 or later. Keep `circom` and `go` on your PATH.

## Run the EAT prototype

From the repository root:

```sh
npm ci
npm run setup
npm run prototype
```

The prototype starts a local Ganache chain, deploys the contracts, and funds the sender and builder bonds. It generates EATs, audits committed batches, and decrypts an admitted batch. The console shows a builder penalty for admitting an invalid EAT and a sender penalty for an invalid transaction signature. The valid transaction incurs no penalty. The local chain closes when the run finishes.

To run the protocol tests, including the 26 correctness cases:

```sh
npm test
```

## Reproduce the experimental results

After setting up the prototype, prepare the additional tree-depth circuits, TDH2 backend, and plotting dependencies:

```sh
npm run setup:experiments
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

The following commands reproduce Sections 7.2–7.4 separately. The `full` configuration uses the experimental settings in `config/profiles.json`. Timing measurements use three runs after warm-up, with error bars showing one sample standard deviation of the run means.

### 7.2 Computational overhead

Compare encryption and decryption with F3B, measure builder and validator EAT verification, and measure proving time at Merkle tree depths 4, 8, 16, and 24.

```sh
node scripts/run-f3b.mjs --profile full
node scripts/run-depth.mjs --profile full
python plots/plot.py results/full --section 7.2
```

Measurements are saved in `results/full/f3b/` and `results/full/depth/`. The F3B comparison uses the same local TDH2/AES-GCM backend for both schemes. See [f3b/PROVENANCE.md](f3b/PROVENANCE.md) for implementation details.

### 7.3 On-chain submission and reporting costs

Measure submission gas against Basic-EM and On-chain EAT, individual fault-report costs, and cumulative gas under faulty workloads. Submission experiments use batch sizes 8, 32, and 128. Faulty workloads use ten batches of 32 transactions at fault ratios of 0%, 10%, and 30%.

```sh
node scripts/run-evm.mjs --profile full
python plots/plot.py results/full --section 7.3
```

Results are saved in `results/full/evm/` as `normal_gas`, `report_costs`, and `aggregate_faults` CSV/JSON files.

### 7.4 Fault accountability and economic losses

The preceding EVM run also records the 26 fault-attribution and boundary cases in `results/full/evm/correctness.csv`. The economic experiment measures net slashing losses for 64 static-fault transactions and eight admission-fault batches, varying reporting coverage and the reporter reward fraction.

```sh
node scripts/run-economics.mjs --profile full
python plots/plot.py results/full --section 7.4
```

Results are saved in `results/full/economics/losses.csv`, with report evidence and receipts in `reports.jsonl`.

### Run all experiments together

As an alternative to the section commands, run the complete evaluation in a separate directory:

```sh
npm run evaluate -- --out results/evaluation
python plots/plot.py results/evaluation
```

For a shorter run with fewer samples, use `npm run evaluate:quick`. This uses the `quick` configuration and saves results in `results/quick/`. Each run records its settings and environment in `manifest.json`. Figures are saved as PDF and PNG under the result directory's `figures/` folder. To repeat an experiment, pass `--out` with a new directory.

The prototype and EVM experiments use a local signed decryption adapter. Generated setup keys and fixture accounts are for experiments only.
