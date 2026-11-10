from pathlib import Path

p = Path("src/ecdsa/group.rs")
s = p.read_text()

old_ec = '''        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let generic_bytes: &<ProjectivePoint as GroupEncoding>::Repr = GenericArray::from_slice(&bytes);

        let point = ProjectivePoint::from_bytes(generic_bytes);
        Ok(ECPoint(point.unwrap()))'''

new_ec = '''        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 33 {
            return Err(serde::de::Error::custom(format!("Expected 33 bytes for SEC1 point, got {}", bytes.len())));
        }
        let generic_bytes: &<ProjectivePoint as GroupEncoding>::Repr = GenericArray::from_slice(&bytes);

        let point = ProjectivePoint::from_bytes(generic_bytes);
        let affine = Option::<ProjectivePoint>::from(point).ok_or_else(|| {
            serde::de::Error::custom("Invalid SEC1 P-256 curve point encoding")
        })?;
        Ok(ECPoint(affine))'''

if old_ec in s:
    s = s.replace(old_ec, new_ec, 1)
    p.write_text(s)
    print("F24_PATCH=PASS")
else:
    if "Invalid SEC1 P-256 curve point encoding" in s:
        print("F24_PATCH=ALREADY_APPLIED")
    else:
        raise RuntimeError("F24 patch target not found")
