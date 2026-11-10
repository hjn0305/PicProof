from pathlib import Path

p = Path("examples/picproof_authenticated_registry.rs")
s = p.read_text()

if "use bincode::Options;" not in s:
    s = "use bincode::Options;\n" + s

old_code = '''    let package: AuthenticatedPicProofPackage = catch_unwind(AssertUnwindSafe(|| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_AUTHENTICATED_PACKAGE_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize::<AuthenticatedPicProofPackage>(&bytes)
    }))
    .map_err(|_| "Authenticated package deserialization panicked; malformed EC point encoding rejected".to_string())?
    .map_err(|e| format!("Cannot deserialize authenticated PicProof package: {e}"))?;'''

if old_code not in s:
    old_code = '''    let package: AuthenticatedPicProofPackage = catch_unwind(AssertUnwindSafe(|| bincode::deserialize(&bytes)))
        .map_err(|_| "Authenticated package deserialization panicked; malformed EC point encoding rejected".to_string())?
        .map_err(|e| format!("Cannot deserialize authenticated PicProof package: {e}"))?;'''

new_code = '''    let package: AuthenticatedPicProofPackage = catch_unwind(AssertUnwindSafe(|| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_AUTHENTICATED_PACKAGE_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize::<AuthenticatedPicProofPackage>(&bytes)
    }))
    .map_err(|_| "Authenticated package deserialization panicked; malformed EC point encoding rejected".to_string())?
    .map_err(|e| format!("Cannot deserialize authenticated PicProof package: {e}"))?;'''

assert s.count(old_code) == 1, f"old_code count: {s.count(old_code)}"
s = s.replace(old_code, new_code, 1)
p.write_text(s)
print("F23_PATCH=PASS")
