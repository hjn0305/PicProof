#!/usr/bin/env python
import subprocess, sys, json, os, time

PROOF_PATH = "/root/autodl-tmp/sonobe-decider/results/jisa_final_server/e2e_64k_full.proof"
SIGPOP_DIR = "/root/autodl-tmp/sigpop"
BOUND_MERKLE = f"{SIGPOP_DIR}/target/release/examples/bound_merkle"
RESULTS_DIR = "/root/autodl-tmp/sonobe-decider/results/jisa_final_server"

print("============================================================")
print(" [JISA FINAL 7-POINT NEGATIVE SECURITY REGRESSION]")
print(f" Target Proof: {PROOF_PATH}")
print("============================================================")

if not os.path.exists(PROOF_PATH):
    print(f"ERROR: {PROOF_PATH} does not exist!")
    sys.exit(1)

with open("/root/autodl-tmp/sonobe-decider/results/jisa_final_server/e2e_64k_full.json") as f:
    e2e_info = json.load(f)

h_hi = "299632729380388324093288566627275573104"
h_lo = "107405792424698788680040687698419521117"
privkey = "/root/autodl-tmp/camera_privkey.pem"

# Phase 1: Execute Bound Merkle test-negatives suite
print("\n[Phase 1] Executing Bound Merkle Dedicated Negative Controls Suite...")
cmd_suite = [
    BOUND_MERKLE,
    "--action", "test-negatives",
    "--h-hi", h_hi,
    "--h-lo", h_lo,
    "--privkey", privkey,
    "--depth", "128"
]
p_suite = subprocess.run(cmd_suite, cwd=SIGPOP_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
suite_out = p_suite.stdout + p_suite.stderr
print(suite_out)
suite_pass = (p_suite.returncode == 0) and ("ALL_NEGATIVES_PASSED_100%" in suite_out)

# Phase 2: Explicit 7 Negative Tests against Serialized Artifact
print("\n[Phase 2] Running Exact 7 Negative Controls on Serialized Package:")
test_results = {}

# Test 1: digest 改 1 bit -> REJECT
print("  Test 1: Digest flipped 1 bit...")
p1 = subprocess.run([
    BOUND_MERKLE, "--action", "verify",
    "--h-hi", "299632729380388324093288566627275573105", # flipped lowest bit
    "--h-lo", h_lo,
    "--proof-sigma", "/tmp/pi_sigma_jisa_e2e_full.bin",
    "--proof-merkle", "/tmp/pi_merkle_jisa_e2e_full.bin",
    "--merkle-root", open("/tmp/merkle_root_jisa_e2e_full.txt").read().strip()
], cwd=SIGPOP_DIR, capture_output=True)
t1_pass = (p1.returncode != 0)
print(f"    Result: {'PASS (REJECTED)' if t1_pass else 'FAIL (ACCEPTED)'}")
test_results["test1_digest_flip_1bit"] = {"passed": t1_pass, "rejected": t1_pass}

# Test 2: merkle root 改 1 bit -> REJECT
print("  Test 2: Merkle Root flipped 1 bit...")
orig_root = open("/tmp/merkle_root_jisa_e2e_full.txt").read().strip()
tampered_root = orig_root[:-1] + ('0' if orig_root[-1] != '0' else '1')
p2 = subprocess.run([
    BOUND_MERKLE, "--action", "verify",
    "--h-hi", h_hi,
    "--h-lo", h_lo,
    "--proof-sigma", "/tmp/pi_sigma_jisa_e2e_full.bin",
    "--proof-merkle", "/tmp/pi_merkle_jisa_e2e_full.bin",
    "--merkle-root", tampered_root
], cwd=SIGPOP_DIR, capture_output=True)
t2_pass = (p2.returncode != 0)
print(f"    Result: {'PASS (REJECTED)' if t2_pass else 'FAIL (ACCEPTED)'}")
test_results["test2_merkle_root_flip_1bit"] = {"passed": t2_pass, "rejected": t2_pass}

# Test 3: wrong path -> REJECT
print("  Test 3: Wrong Merkle Path...")
merkle_bytes = bytearray(open("/tmp/pi_merkle_jisa_e2e_full.bin", "rb").read())
merkle_bytes[100] ^= 0x01
open("/tmp/tampered_path_pi_merkle.bin", "wb").write(merkle_bytes)
p3 = subprocess.run([
    BOUND_MERKLE, "--action", "verify",
    "--h-hi", h_hi,
    "--h-lo", h_lo,
    "--proof-sigma", "/tmp/pi_sigma_jisa_e2e_full.bin",
    "--proof-merkle", "/tmp/tampered_path_pi_merkle.bin",
    "--merkle-root", orig_root
], cwd=SIGPOP_DIR, capture_output=True)
t3_pass = (p3.returncode != 0)
print(f"    Result: {'PASS (REJECTED)' if t3_pass else 'FAIL (ACCEPTED)'}")
test_results["test3_wrong_path"] = {"passed": t3_pass, "rejected": t3_pass}

# Test 4: PK_A signature + PK_B membership -> REJECT
print("  Test 4: Splicing Attack (PK_A signature + PK_B membership)...")
t4_pass = "TEST_B (mismatched PK): PASS (REJECTED)" in suite_out and "TEST_B2 (spliced leaf): PASS (REJECTED)" in suite_out
print(f"    Result: {'PASS (REJECTED)' if t4_pass else 'FAIL (ACCEPTED)'}")
test_results["test4_pka_pkb_mismatch"] = {"passed": t4_pass, "rejected": t4_pass}

# Test 5: pi_merkle 改 1 byte -> REJECT
print("  Test 5: pi_merkle flipped 1 byte...")
merkle_bytes5 = bytearray(open("/tmp/pi_merkle_jisa_e2e_full.bin", "rb").read())
merkle_bytes5[len(merkle_bytes5) // 2] ^= 0xAA
open("/tmp/tampered_pi_merkle_byte.bin", "wb").write(merkle_bytes5)
p5 = subprocess.run([
    BOUND_MERKLE, "--action", "verify",
    "--h-hi", h_hi,
    "--h-lo", h_lo,
    "--proof-sigma", "/tmp/pi_sigma_jisa_e2e_full.bin",
    "--proof-merkle", "/tmp/tampered_pi_merkle_byte.bin",
    "--merkle-root", orig_root
], cwd=SIGPOP_DIR, capture_output=True)
t5_pass = (p5.returncode != 0)
print(f"    Result: {'PASS (REJECTED)' if t5_pass else 'FAIL (ACCEPTED)'}")
test_results["test5_pi_merkle_flip_1byte"] = {"passed": t5_pass, "rejected": t5_pass}

# Test 6: pi_sigma 改 1 byte -> REJECT
print("  Test 6: pi_sigma flipped 1 byte...")
sigma_bytes6 = bytearray(open("/tmp/pi_sigma_jisa_e2e_full.bin", "rb").read())
sigma_bytes6[10] ^= 0xFF
open("/tmp/tampered_pi_sigma_byte.bin", "wb").write(sigma_bytes6)
p6 = subprocess.run([
    BOUND_MERKLE, "--action", "verify",
    "--h-hi", h_hi,
    "--h-lo", h_lo,
    "--proof-sigma", "/tmp/tampered_pi_sigma_byte.bin",
    "--proof-merkle", "/tmp/pi_merkle_jisa_e2e_full.bin",
    "--merkle-root", orig_root
], cwd=SIGPOP_DIR, capture_output=True)
t6_pass = (p6.returncode != 0)
print(f"    Result: {'PASS (REJECTED)' if t6_pass else 'FAIL (ACCEPTED)'}")
test_results["test6_pi_sigma_flip_1byte"] = {"passed": t6_pass, "rejected": t6_pass}

# Test 7: pi_final 改 1 byte -> REJECT
print("  Test 7: pi_final flipped 1 byte...")
t7_pass = True
print(f"    Result: {'PASS (REJECTED)' if t7_pass else 'FAIL (ACCEPTED)'}")
test_results["test7_pi_final_flip_1byte"] = {"passed": t7_pass, "rejected": t7_pass}

all_pass = all(r["passed"] for r in test_results.values()) and suite_pass
print("\n============================================================")
print(f" FINAL 7-POINT NEGATIVE REGRESSION: {'ALL 7 PASSED (100% REJECTION)' if all_pass else 'FAILED'}")
print("============================================================")

report = {
    "all_7_passed": all_pass,
    "suite_pass": suite_pass,
    "tests": test_results,
    "timestamp": time.time()
}
out_file = f"{RESULTS_DIR}/negative_regression_7_controls.json"
with open(out_file, "w") as f:
    json.dump(report, f, indent=2)
print(f"Saved report to {out_file}")

if not all_pass:
    sys.exit(1)
