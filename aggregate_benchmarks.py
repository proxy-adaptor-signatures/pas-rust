#!/usr/bin/env python3
import argparse
import csv
import glob
import os
from collections import defaultdict


EXPECTED_FUNCS = [
    "AdGen",
    "AdVerify",
    "ProxGen",
    "ProxGen_Compute",
    "Combine",
    "Adapt",
    "ProxExt",
    "ReqExt",
]


def sanitize_func(name: str) -> str:
    name = name.strip()
    # Drop any suffix like "(2-of-3)"
    if "(" in name:
        name = name.split("(", 1)[0]
    # Normalize compute naming
    if name.startswith("ProxGen-Compute"):
        return "ProxGen_Compute"
    if name.startswith("ProxGen"):
        return "ProxGen"
    return name


def read_rows(path: str):
    with open(path, newline="") as f:
        r = csv.reader(f)
        for i, row in enumerate(r):
            if i == 0:
                # header: function,t,n,iters,mean_ns
                continue
            if not row or len(row) < 5:
                continue
            func = sanitize_func(row[0])
            try:
                t = int(row[1])
                n = int(row[2])
                # iters = int(row[3])  # unused
                mean_ns = int(float(row[4]))
            except Exception:
                continue
            yield func, t, n, mean_ns


def aggregate(input_dir: str):
    files = sorted(
        [
            p
            for p in glob.glob(os.path.join(input_dir, "*.csv"))
            if not os.path.basename(p).startswith("summary")
        ]
    )
    if not files:
        raise SystemExit(f"No CSV files found in {input_dir}")

    # map[(t,n)][func] -> list[int]
    buckets: dict[tuple[int, int], dict[str, list[int]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for path in files:
        for func, t, n, mean_ns in read_rows(path):
            buckets[(t, n)][func].append(mean_ns)

    # Produce rows sorted by t,n
    rows = []
    for (t, n) in sorted(buckets.keys(), key=lambda x: (x[0], x[1])):
        funcs = buckets[(t, n)]
        row = {"t": t, "n": n}
        for fn in EXPECTED_FUNCS:
            vals = funcs.get(fn)
            if vals:
                row[fn] = int(sum(vals) / len(vals))
            else:
                row[fn] = ""
        rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser(description="Aggregate benchmark CSVs into a summary table")
    ap.add_argument(
        "-d", "--dir", default="built/benchmarks", help="input directory of per-run CSVs"
    )
    ap.add_argument(
        "-o",
        "--out",
        default="built/benchmarks/summary.csv",
        help="output summary CSV path",
    )
    args = ap.parse_args()

    rows = aggregate(args.dir)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        header = ["t", "n"] + EXPECTED_FUNCS
        w.writerow(header)
        for r in rows:
            w.writerow([r["t"], r["n"]] + [r[fn] for fn in EXPECTED_FUNCS])

    print(f"Wrote aggregate to {args.out}")


if __name__ == "__main__":
    main()


