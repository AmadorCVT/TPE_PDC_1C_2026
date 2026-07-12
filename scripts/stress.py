#!/usr/bin/env python3
"""
Pruebas de estrés del proxy SOCKS5.
Mide conexiones concurrentes sostenidas y throughput agregado.

Uso:
  python3 scripts/stress.py [--socks-port 1080] [--out scripts/results]
"""
from __future__ import annotations

import argparse
import csv
import os
import select
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def socks5_connect(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int,
                   timeout: float = 10.0) -> socket.socket:
    """Handshake SOCKS5 sin auth + CONNECT a dest_host:dest_port (IPv4)."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    # HELLO: VER=5, NMETHODS=1, METHOD=0
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
        s.close()
        raise OSError(f"HELLO rejected: {resp!r}")

    # REQUEST CONNECT IPv4
    dest_ip = socket.inet_aton(dest_host)
    req = b"\x05\x01\x00\x01" + dest_ip + struct.pack("!H", dest_port)
    s.sendall(req)
    # VER REP RSV ATYP + addr + port (mínimo 10 para IPv4)
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            s.close()
            raise OSError("short REQUEST response")
        hdr += chunk
    if hdr[1] != 0:
        s.close()
        raise OSError(f"CONNECT failed REP={hdr[1]}")
    atyp = hdr[3]
    if atyp == 1:
        rest_len = 4 + 2
    elif atyp == 4:
        rest_len = 16 + 2
    elif atyp == 3:
        ln = s.recv(1)
        rest_len = ln[0] + 2
    else:
        s.close()
        raise OSError(f"bad ATYP {atyp}")
    rest = b""
    while len(rest) < rest_len:
        chunk = s.recv(rest_len - len(rest))
        if not chunk:
            s.close()
            raise OSError("short BND")
        rest += chunk
    return s


class OriginServer:
    """Servidor origen: acepta TCP y responde payload fijo (o echo)."""

    def __init__(self, payload_size: int = 65536):
        self.payload = os.urandom(payload_size) if payload_size else b""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1024)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
        except OSError:
            pass
        self._sock.close()

    def _run(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(30.0)
            # Leer un request mínimo (si llega) y responder payload
            try:
                conn.recv(4096)
            except OSError:
                pass
            if self.payload:
                conn.sendall(self.payload)
            else:
                # hold-open mode: keep connection until peer closes
                while True:
                    r, _, _ = select.select([conn], [], [], 1.0)
                    if r:
                        data = conn.recv(4096)
                        if not data:
                            break
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def test_concurrent(proxy_host: str, proxy_port: int, origin_port: int,
                    targets: list[int], hold_s: float = 2.0) -> list[dict]:
    results = []
    for n in targets:
        ok = 0
        fail = 0
        socks: list[socket.socket] = []
        lock = threading.Lock()

        def one(_: int) -> None:
            nonlocal ok, fail
            try:
                s = socks5_connect(proxy_host, proxy_port, "127.0.0.1", origin_port)
                with lock:
                    socks.append(s)
                    ok += 1
            except OSError:
                with lock:
                    fail += 1

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=min(n, 256)) as ex:
            list(ex.map(one, range(n)))
        elapsed = time.perf_counter() - t0
        time.sleep(hold_s)
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        results.append({
            "requested": n,
            "ok": ok,
            "fail": fail,
            "setup_s": round(elapsed, 4),
        })
        print(f"concurrent requested={n} ok={ok} fail={fail} setup_s={elapsed:.3f}")
    return results


def test_throughput(proxy_host: str, proxy_port: int, origin_port: int,
                    clients_list: list[int], payload_size: int) -> list[dict]:
    results = []
    for n in clients_list:
        bytes_ok = 0
        fail = 0
        lock = threading.Lock()

        def one(_: int) -> None:
            nonlocal bytes_ok, fail
            try:
                s = socks5_connect(proxy_host, proxy_port, "127.0.0.1", origin_port)
                s.sendall(b"GET\n")
                got = 0
                while got < payload_size:
                    chunk = s.recv(min(65536, payload_size - got))
                    if not chunk:
                        break
                    got += len(chunk)
                s.close()
                with lock:
                    if got == payload_size:
                        bytes_ok += got
                    else:
                        fail += 1
            except OSError:
                with lock:
                    fail += 1

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=min(n, 128)) as ex:
            list(ex.map(one, range(n)))
        elapsed = time.perf_counter() - t0
        mbps = (bytes_ok * 8) / elapsed / 1e6 if elapsed > 0 else 0
        mib_s = bytes_ok / elapsed / (1024 * 1024) if elapsed > 0 else 0
        results.append({
            "clients": n,
            "bytes": bytes_ok,
            "fail": fail,
            "elapsed_s": round(elapsed, 4),
            "mib_s": round(mib_s, 4),
            "mbps": round(mbps, 4),
        })
        print(f"throughput clients={n} MiB/s={mib_s:.2f} fail={fail} elapsed={elapsed:.3f}s")
    return results


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-host", default="127.0.0.1")
    ap.add_argument("--socks-port", type=int, default=1080)
    ap.add_argument("--out", default="scripts/results")
    ap.add_argument("--payload", type=int, default=256 * 1024)
    ap.add_argument("--quick", action="store_true",
                    help="Corrida corta para humo (menos clientes)")
    args = ap.parse_args()
    out = Path(args.out)

    # --- concurrent (hold-open origin) ---
    hold_origin = OriginServer(payload_size=0)
    hold_origin.start()
    conc_targets = [50, 100, 250, 500, 750] if not args.quick else [10, 50, 100]
    try:
        conc = test_concurrent(args.proxy_host, args.socks_port, hold_origin.port, conc_targets)
    finally:
        hold_origin.stop()
    write_csv(out / "concurrent.csv", conc)

    # --- throughput ---
    thr_origin = OriginServer(payload_size=args.payload)
    thr_origin.start()
    thr_clients = [1, 4, 8, 16, 32, 64] if not args.quick else [1, 4, 8]
    try:
        thr = test_throughput(args.proxy_host, args.socks_port, thr_origin.port,
                              thr_clients, args.payload)
    finally:
        thr_origin.stop()
    write_csv(out / "throughput.csv", thr)

    print(f"Resultados en {out}/")


if __name__ == "__main__":
    main()
