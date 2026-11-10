import sys

method = '''
    /// Temporary E2E-03 D13 test hook.
    pub fn perturb_claimed_rx_first_for_testing(
        &mut self,
    ) -> Result<(), &'static str> {
        let first = self.r.0.first_mut()
            .ok_or("claimed rx vector is empty")?;
        *first = *first + Scalar::from(1u64);
        Ok(())
    }
'''

for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    needle = "impl NIZK {\n"
    if "perturb_claimed_rx_first_for_testing" in source:
        print(f"Skipping {path}, hook already present")
        continue

    if source.count(needle) != 1:
        raise SystemExit(f"Cannot uniquely locate impl NIZK in {path}")

    source = source.replace(needle, needle + method, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(source)
    print(f"Patched: {path}")
