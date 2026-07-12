#!/usr/bin/env python3
"""Genera gráficos PNG a partir de scripts/results/*.csv"""
from __future__ import annotations

import csv
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    raise SystemExit("matplotlib no instalado: pip install matplotlib")


def load_csv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def plot_concurrent(rows: list[dict], out: Path) -> None:
    req = [int(r["requested"]) for r in rows]
    ok = [int(r["ok"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(req, ok, marker="o", label="conexiones OK")
    ax.plot(req, req, linestyle="--", color="gray", label="ideal")
    ax.set_xlabel("Conexiones solicitadas")
    ax.set_ylabel("Conexiones establecidas")
    ax.set_title("Estrés: conexiones concurrentes vía SOCKS5")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_throughput(rows: list[dict], out: Path) -> None:
    clients = [int(r["clients"]) for r in rows]
    mib = [float(r["mib_s"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(clients, mib, marker="o")
    ax.set_xlabel("Clientes concurrentes")
    ax.set_ylabel("Throughput agregado (MiB/s)")
    ax.set_title("Estrés: throughput a través del proxy")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def main() -> None:
    root = Path("scripts/results")
    conc = load_csv(root / "concurrent.csv")
    thr = load_csv(root / "throughput.csv")
    plot_concurrent(conc, root / "concurrent.png")
    plot_throughput(thr, root / "throughput.png")
    print(f"Gráficos: {root / 'concurrent.png'}, {root / 'throughput.png'}")


if __name__ == "__main__":
    main()
