import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "eatguard-matplotlib"))
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

COLORS = ["#416b96", "#c66b39", "#638b68"]
MARKERS = ["o", "s", "^"]
LINES = ["-", "--", ":"]


def read(path):
    return json.loads(path.read_text())


def load_stage(root, stage):
    directory = root / stage
    manifest = read(directory / "manifest.json")
    if manifest["status"] != "complete":
        raise ValueError(f"Incomplete experiment: {stage}")
    for name, expected in manifest["resultHashes"].items():
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Result changed: {stage}/{name}")
    return directory, manifest["config"]


def stats(values):
    values = np.asarray(values, dtype=float)
    if values.size == 0 or not np.all(np.isfinite(values)):
        raise ValueError("Missing or invalid samples")
    return values.mean(), values.std(ddof=1) if values.size > 1 else 0.0


def repeat_stats(rows, metric, repeats):
    means = []
    for repeat in range(repeats):
        samples = [metric(r) for r in rows if r["repeat"] == repeat]
        means.append(stats(samples)[0])
    return stats(means)


def axes(width=7.2, height=4.2):
    fig, ax = plt.subplots(figsize=(width, height))
    ax.grid(axis="y", alpha=0.16)
    ax.set_axisbelow(True)
    return fig, ax


def save(fig, directory, name):
    fig.tight_layout()
    fig.savefig(directory / f"{name}.pdf")
    fig.savefig(directory / f"{name}.png", dpi=300)
    plt.close(fig)


def plot_crypto(root, dest):
    directory, cfg = load_stage(root, "f3b")
    rows = read(directory / "transactions.json")
    batches = read(directory / "batches.json")
    expected = 2 * cfg["repeats"] * sum(cfg["batchSizes"])
    if len(rows) != expected or not all(r["roundtrip"] for r in rows):
        raise ValueError("Incomplete paired cryptographic measurements")
    n = 32 if 32 in cfg["batchSizes"] else cfg["batchSizes"][0]
    fig, ax = axes(5.3)
    x = np.arange(2)
    for j, (scheme, label, color, hatch) in enumerate([
        ("F3B-TDH2", "F3B", "#6a8daf", ""),
        ("EATGuard", "EATGuard", "#edc79f", "//"),
    ]):
        subset = [r for r in rows if r["n"] == n and r["scheme"] == scheme]
        values = [repeat_stats(subset, lambda r, k=k: r[k], cfg["repeats"])
                  for k in ["encryptMs", "processSerialWorkMs"]]
        ax.bar(x + (j - 0.5) * 0.34, [v[0] for v in values], 0.34,
               yerr=[v[1] for v in values], capsize=4, color=color,
               hatch=hatch, edgecolor="#3e4852", linewidth=0.6, label=label)
    ax.set_xticks(x, ["Encryption", "Decryption"])
    ax.set_ylabel("Computation per transaction (ms)")
    ax.legend(frameon=False)
    save(fig, dest, "figure1_encryption_decryption")

    fig, ax = axes(5.3)
    for j, (key, label) in enumerate([
        ("builderAuditMs", "Builder checks"), ("validatorAuditMs", "Validator audit")
    ]):
        values = [repeat_stats([r for r in batches if r["n"] == n and r["scheme"] == "EATGuard"],
                               lambda r: r[key] / r["n"], cfg["repeats"])
                  for n in cfg["batchSizes"]]
        ax.errorbar(cfg["batchSizes"], [v[0] for v in values], yerr=[v[1] for v in values],
                    color=COLORS[j], marker=MARKERS[j], linestyle=LINES[j],
                    linewidth=1.8, markersize=6, capsize=4, label=label)
    ax.set_xticks(cfg["batchSizes"])
    ax.set_xlabel("Batch size")
    ax.set_ylabel("Audit time per transaction (ms)")
    ax.legend(frameon=False)
    save(fig, dest, "figure1_eat_verification")


def plot_depth(root, dest):
    directory, cfg = load_stage(root, "depth")
    rows = read(directory / "transactions.json")
    batches = read(directory / "batches.json")
    expected = len(cfg["depths"]) * cfg["depthSamples"] * cfg["repeats"]
    if len(rows) != expected:
        raise ValueError("Incomplete depth measurements")
    for batch in batches:
        subset = [r for r in rows if r["depth"] == batch["depth"] and r["repeat"] == batch["repeat"]]
        if len(subset) != batch["proofCount"] or not np.isclose(sum(r["proofMs"] for r in subset), batch["proofTotalMs"]):
            raise ValueError("Depth totals disagree with samples")
    values = [repeat_stats([r for r in rows if r["depth"] == depth], lambda r: r["proofMs"], cfg["repeats"])
              for depth in cfg["depths"]]
    fig, ax = axes()
    ax.errorbar(cfg["depths"], [v[0] for v in values], yerr=[v[1] for v in values],
                color=COLORS[0], marker="o", linewidth=1.8, markersize=6, capsize=4)
    ax.set_xticks(cfg["depths"])
    ax.set_xlabel("Merkle tree depth")
    ax.set_ylabel("Proof generation time per ticket (ms)")
    save(fig, dest, "eat_depth_batch_per_ticket")


def plot_gas(root, dest):
    directory, cfg = load_stage(root, "evm")
    rows = read(directory / "normal_gas.json")
    fig, ax = axes()
    for j, scheme in enumerate(["EATGuard", "Basic-EM", "On-chain EAT"]):
        values = [stats([r["gasPerEntry"] for r in rows if r["scheme"] == scheme and r["n"] == n])[0]
                  for n in cfg["batchSizes"]]
        ax.plot(cfg["batchSizes"], values, color=COLORS[j], marker=MARKERS[j],
                linestyle=LINES[j], linewidth=1.8, markersize=6, label=scheme)
    ax.set_xticks(cfg["batchSizes"])
    ax.set_xlabel("Batch size")
    ax.set_ylabel("Submission gas per transaction")
    ax.set_yscale("log")
    ax.legend(frameon=False)
    save(fig, dest, "normal_gas")

    rows = read(directory / "report_costs.json")
    reasons = ["MALFORMED_EAT", "INVALID_CONTEXT", "BAD_PUBLIC_BINDING", "DUPLICATE_NULLIFIER",
               "INVALID_EAT_PROOF", "PAYLOAD_ENCODING", "PAYLOAD_BINDING"]
    labels = [r"$\mathtt{" + reason.replace("_", r"\_") + "}$" for reason in reasons]
    labels.append(r"$\mathtt{PDEF}_{j}$")
    styles = [("#c4d7e8", "///"), ("#dfa16b", "xx"), ("#638b68", "..")]
    fig, ax = axes(7.2, 4.4)
    x, width = np.arange(8), 0.78 / len(cfg["batchSizes"])
    for j, n in enumerate(cfg["batchSizes"]):
        values = []
        for reason in range(8):
            subset = [r for r in rows if r["n"] == n and r["reason"] == reason]
            if len(subset) != 1:
                raise ValueError(f"Missing report measurement: {n}/{reason}")
            values.append(int(subset[0]["gas"]) / 1000)
        color, hatch = styles[j % len(styles)]
        ax.bar(x + (j - (len(cfg["batchSizes"]) - 1) / 2) * width, values, width,
               color=color, hatch=hatch, edgecolor="#3e4852", linewidth=0.6, label=str(n))
    ax.set_xticks(x, labels, rotation=30, ha="right", rotation_mode="anchor", fontsize=10.5)
    ax.set_ylabel("Gas per successful report (k gas)")
    ax.legend(title="Batch size", frameon=False)
    save(fig, dest, "report_costs")

    rows = read(directory / "aggregate_faults.json")
    for family in ["admission", "static"]:
        subset = sorted([r for r in rows if r["family"] == family], key=lambda r: r["actualRatio"])
        if len(subset) != len(cfg["faultRatios"]):
            raise ValueError(f"Incomplete aggregate workloads: {family}")
        fig, ax = axes(5.3)
        x, bottom = np.arange(len(subset)), np.zeros(len(subset))
        for key, label, color, hatch in [
            ("normalGas", "Submission", "#6a8daf", ""),
            ("reportGas", "Fault reports", "#edc79f", "//"),
        ]:
            values = np.array([int(r[key]) / 1e6 for r in subset])
            ax.bar(x, values, 0.68, bottom=bottom, color=color, hatch=hatch,
                   edgecolor="#3e4852", linewidth=0.6, label=label)
            bottom += values
        ax.set_xticks(x, [f'{100 * r["actualRatio"]:.0f}%' for r in subset])
        ax.set_xlabel("Actual fault ratio")
        ax.set_ylabel("Total gas (M gas)")
        ax.set_ylim(0, max(bottom) * 1.35)
        ax.legend(frameon=False)
        save(fig, dest, f"aggregate_faults_{family}")


def plot_losses(root, dest):
    directory, _ = load_stage(root, "economics")
    rows = read(directory / "losses.json")
    if len(rows) != 12:
        raise ValueError("Expected twelve economic configurations")
    fig, ax = axes()
    for j, gamma in enumerate([1000, 2000, 5000]):
        subset = sorted([r for r in rows if r["rewardBps"] == gamma], key=lambda r: r["staticReportingFraction"])
        ax.plot([100 * r["staticReportingFraction"] for r in subset],
                [int(r["coalitionNetLoss"]) / 1e18 for r in subset],
                color=COLORS[j], marker=MARKERS[j], linestyle=LINES[j],
                linewidth=1.8, markersize=6, label=rf'$\gamma = {gamma // 100}\%$')
    ax.set_xlabel("Static faults reported (%)")
    ax.set_ylabel("Coalition net loss (ETH)")
    ax.set_xticks([25, 50, 75, 100])
    ax.set_xlim(20, 105)
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False)
    save(fig, dest, "net_loss_reporting")


def main():
    parser = argparse.ArgumentParser(description="Plot EATGuard experiment results.")
    parser.add_argument("run", type=Path)
    parser.add_argument("--section", choices=["7.2", "7.3", "7.4", "all"], default="all")
    args = parser.parse_args()
    dest = args.run / "figures"
    dest.mkdir(exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12,
                         "axes.labelsize": 14, "xtick.labelsize": 12, "ytick.labelsize": 12,
                         "legend.fontsize": 12, "legend.title_fontsize": 12,
                         "pdf.fonttype": 42, "mathtext.fontset": "cm",
                         "axes.spines.top": False, "axes.spines.right": False,
                         "hatch.linewidth": 0.65})
    if args.section in ["7.2", "all"]:
        plot_crypto(args.run, dest)
        plot_depth(args.run, dest)
    if args.section in ["7.3", "all"]:
        plot_gas(args.run, dest)
    if args.section in ["7.4", "all"]:
        plot_losses(args.run, dest)
    print(f"Saved figures as PDF and PNG in {dest}")


if __name__ == "__main__":
    main()
