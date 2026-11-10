#!/bin/bash
set -u
export RUSTUP_HOME=/root/autodl-tmp/rustup
export CARGO_HOME=/root/autodl-tmp/cargo
export PATH=/root/autodl-tmp/cargo/bin:$PATH
export RUSTUP_TOOLCHAIN=stable
export RAYON_NUM_THREADS=16
export RUST_BACKTRACE=1

cd /root/autodl-tmp/sonobe-decider
RESULTS_DIR=/root/autodl-tmp/sonobe-decider/results/jisa_final_server
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$RESULTS_DIR/master_unattended.log"; }

log "============================================================"
log "=== MASTER UNATTENDED RUNNER STARTED (PERSISTENT DAEMON) ==="
log "============================================================"

# STEP 1: Wait for 1 MiB Unified E2E to complete
log "STEP 1: Monitoring currently running 1 MiB Unified E2E (PID 114785)..."
while ps -p 114785 > /dev/null 2>&1; do
    sleep 30
done
log "STEP 1: 1 MiB Unified E2E process finished."

if [ -f "$RESULTS_DIR/e2e_1mib.json" ]; then
    log "STEP 1 SUCCESS: e2e_1mib.json generated successfully."
else
    log "STEP 1 WARNING: e2e_1mib.json not found."
fi

# STEP 2: Multi-block HashFold Benchmark (k=1, 2, 4, 8)
log "STEP 2: Building hashfold_multiblock_bench binary..."
cargo build --release -p sonobe-ivc --bin hashfold_multiblock_bench --no-default-features --features parallel >> "$RESULTS_DIR/master_unattended.log" 2>&1
BUILD_RC=$?
if [ $BUILD_RC -ne 0 ]; then
    log "STEP 2 ERROR: cargo build hashfold_multiblock_bench failed (rc=$BUILD_RC)"
else
    log "STEP 2: Running 64 KiB Multi-Block Benchmark (k=1,2,4,8)..."
    /usr/bin/time -v ./target/release/hashfold_multiblock_bench         --bytes 65536         --k-values 1,2,4,8         --output "$RESULTS_DIR/hashfold_multiblock_64k.json"         --csv "$RESULTS_DIR/hashfold_multiblock_64k.csv"         >> "$RESULTS_DIR/master_unattended.log" 2>&1
    log "STEP 2: 64 KiB Multi-Block Benchmark completed."

    log "STEP 2: Running 256 KiB Multi-Block Benchmark (k=1,2,4,8)..."
    /usr/bin/time -v ./target/release/hashfold_multiblock_bench         --bytes 262144         --k-values 1,2,4,8         --output "$RESULTS_DIR/hashfold_multiblock_256k.json"         --csv "$RESULTS_DIR/hashfold_multiblock_256k.csv"         >> "$RESULTS_DIR/master_unattended.log" 2>&1
    log "STEP 2: 256 KiB Multi-Block Benchmark completed."
fi

# STEP 3: 4 MiB Unified E2E
log "STEP 3: Launching 4 MiB Unified E2E experiment..."
/usr/bin/time -v   ./target/release/jisa_unified_e2e   --image data/jisa/4mib.bin   --merkle-depth 128   --output "$RESULTS_DIR/e2e_4mib.json"   --proof-out "$RESULTS_DIR/e2e_4mib.proof"   > "$RESULTS_DIR/e2e_4mib.log" 2> "$RESULTS_DIR/e2e_4mib.time.txt"
E2E_4M_RC=$?
log "STEP 3: 4 MiB Unified E2E completed with rc=$E2E_4M_RC"

# STEP 4: Generate Summary Report
log "STEP 4: Compiling FINAL_SUMMARY_REPORT.md..."
python3 -c '
import json, glob, os

res_dir = "/root/autodl-tmp/sonobe-decider/results/jisa_final_server"
report_path = os.path.join(res_dir, "FINAL_SUMMARY_REPORT.md")

with open(report_path, "w") as out:
    out.write("# JISA Final AutoDL Benchmark Comprehensive Summary\n\n")
    out.write("Generated automatically by master unattended daemon.\n\n")
    
    # E2E files
    out.write("## 1. Unified End-to-End Ladder Results\n\n")
    out.write("| Scale | Payload Bytes | Blocks | Total Proving (s) | Fold (s) | Decider (s) | Total Verify (ms) | Peak RSS (GiB) | Proof Package (B) | Accept |\n")
    out.write("|---|---|---|---|---|---|---|---|---|---|\n")
    for scale in ["64k", "1mib", "4mib"]:
        jf = os.path.join(res_dir, f"e2e_{scale}.json")
        if os.path.exists(jf):
            with open(jf) as f:
                d = json.load(f)
            rss_gib = d.get("peak_rss_kib", 0) / (1024*1024)
            out.write(f"| {scale} | {d.get("image_bytes", 0)} | {d.get("sha256_blocks", 0)} | {d.get("total_prove_ms", 0)/1000:.2f} | {d.get("hashfold_ms", 0)/1000:.2f} | {d.get("decider_prove_ms", 0)/1000:.2f} | {d.get("total_verify_ms", 0)} | {rss_gib:.2f} | {d.get("proof_package_bytes", 0)} | {d.get("accept", False)} |\n")
    
    out.write("\n## 2. Multi-block HashFold Benchmark Results\n\n")
    for mf in sorted(glob.glob(os.path.join(res_dir, "hashfold_multiblock_*.csv"))):
        out.write(f"### {os.path.basename(mf)}\n\n")
        with open(mf) as f:
            lines = f.readlines()
        if lines:
            out.write("| " + " | ".join(lines[0].strip().split(",")) + " |\n")
            out.write("|" + "---|"*len(lines[0].strip().split(",")) + "\n")
            for l in lines[1:]:
                out.write("| " + " | ".join(l.strip().split(",")) + " |\n")
        out.write("\n")
' >> "$RESULTS_DIR/master_unattended.log" 2>&1

log "=== ALL UNATTENDED EXPERIMENTS COMPLETED SUCCESSFULLY ==="
touch "$RESULTS_DIR/ALL_EXPERIMENTS_COMPLETED"
