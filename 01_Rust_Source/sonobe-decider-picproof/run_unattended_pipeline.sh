#!/bin/bash
set -e

export RUSTUP_HOME=/root/autodl-tmp/rustup
export CARGO_HOME=/root/autodl-tmp/cargo
export PATH=/root/autodl-tmp/cargo/bin:/root/miniconda3/bin:/usr/bin:/bin:$PATH
export RUSTUP_TOOLCHAIN=stable
export RAYON_NUM_THREADS=16
export RUST_BACKTRACE=1

cd /root/autodl-tmp/sonobe-decider
mkdir -p results/jisa_final_server

echo "=========================================================="
echo " [$(date)] Starting JISA Unattended E2E Pipeline (1 MiB + 4 MiB)"
echo "=========================================================="

# 1. 1 MiB Unified E2E
echo "[1/3] [$(date)] Launching 1 MiB Unified E2E..."
/usr/bin/time -v   ./target/release/jisa_unified_e2e   --image data/jisa/1mib.bin   --merkle-depth 128   --output results/jisa_final_server/e2e_1mib_full.json   --proof-out results/jisa_final_server/e2e_1mib_full.proof   > results/jisa_final_server/e2e_1mib_full.log 2> results/jisa_final_server/e2e_1mib_full.time.txt
echo "[1/3] [$(date)] 1 MiB Unified E2E FINISHED!"

# Recompile report after 1 MiB
/root/miniconda3/bin/python results/jisa_final_server/compile_final_summary.py

# 2. 4 MiB Unified E2E
echo "[2/3] [$(date)] Launching 4 MiB Unified E2E..."
/usr/bin/time -v   ./target/release/jisa_unified_e2e   --image data/jisa/4mib.bin   --merkle-depth 128   --output results/jisa_final_server/e2e_4mib_full.json   --proof-out results/jisa_final_server/e2e_4mib_full.proof   > results/jisa_final_server/e2e_4mib_full.log 2> results/jisa_final_server/e2e_4mib_full.time.txt
echo "[2/3] [$(date)] 4 MiB Unified E2E FINISHED!"

# 3. Final Master Compilation
echo "[3/3] [$(date)] Compiling Final Master Summary..."
/root/miniconda3/bin/python results/jisa_final_server/compile_final_summary.py

echo "ALL_EXPERIMENTS_COMPLETE" > results/jisa_final_server/ALL_EXPERIMENTS_COMPLETE.flag
echo "=========================================================="
echo " [$(date)] All tasks finished! Grace period 1800s before poweroff..."
echo "=========================================================="

sleep 1800
/usr/sbin/poweroff
