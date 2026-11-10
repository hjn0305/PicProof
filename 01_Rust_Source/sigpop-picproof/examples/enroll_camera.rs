//! Standalone CLI to generate camera enrollment commitment and register leaf*.
//!
//! USAGE:
//!   enroll_camera --pubkey <path/to/camera_pubkey.pem> --out-dir <path/to/out_dir>
//!
//! Outputs:
//!   camera_enrollment_public.json  -- public registration material (0644)
//!   camera_enrollment_private.json -- opening and public key (0600)
//!   opening_v.txt                  -- opening scalar only (0600, legacy tooling)

use circ::commitment::PointCommit;
use circ::ecdsa::convert::scalar_to_integer;
use circ::ecdsa::pk_link::h_reg;
use circ::ecdsa::picproof_k::{
    CURVE, K_PARAMETER_SHA256, K_SEC1_COMPRESSED, MESSAGE, PROFILE, SUITE,
};
use circ::ecdsa::pure_sigma::ECDSASigmaSetupParamsPrior;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, ProjectivePoint};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct CameraEnrollmentPublic {
    pub profile: String,
    pub k_profile: String,
    pub k_fingerprint: String,
    pub k_sec1_compressed: String,
    pub c0_sec1: String,
    pub c1_sec1: String,
    pub leaf_decimal: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CameraEnrollmentPrivate {
    pub opening_v: String,
    pub pk_sec1: String,
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn load_pubkey(path: &str) -> Result<ProjectivePoint, Box<dyn std::error::Error>> {
    let raw = fs::read(path)?;
    let content = String::from_utf8_lossy(&raw);
    let sec1_bytes = if content.contains("-----BEGIN") {
        let pkey = openssl::pkey::PKey::public_key_from_pem(&raw)?;
        let ec_key = pkey.ec_key()?;
        let group = ec_key.group();
        let mut ctx = openssl::bn::BigNumContext::new()?;
        ec_key.public_key().to_bytes(
            group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?
    } else {
        raw
    };
    let enc = EncodedPoint::from_bytes(&sec1_bytes)
        .map_err(|e| format!("Invalid SEC1 public key: {:?}", e))?;
    let pt = ProjectivePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or("Failed to convert EncodedPoint to ProjectivePoint")?;
    Ok(pt)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let pubkey_path = get_arg(&args, "--pubkey")
        .expect("Missing required argument: --pubkey");
    let out_dir = get_arg(&args, "--out-dir")
        .expect("Missing required argument: --out-dir");

    let out_path = Path::new(&out_dir);
    fs::create_dir_all(out_path)?;

    let pk_projective = load_pubkey(&pubkey_path)?;
    let params = ECDSASigmaSetupParamsPrior::new();

    // Generate fresh random opening with OsRng (once at enrollment time)
    let mut rng = rand::rngs::OsRng;
    let comm_pk = PointCommit::new(
        &pk_projective,
        &[params.hash_hash_g, params.hash_g],
        &mut rng,
    );

    let opening_int = scalar_to_integer(&comm_pk.opening);
    let opening_str = opening_int.to_string();

    let pt_c0 = comm_pk.comm[0];
    let pt_c1 = comm_pk.comm[1];

    let c0_sec1_bytes = pt_c0.to_encoded_point(true).as_bytes().to_vec();
    let c1_sec1_bytes = pt_c1.to_encoded_point(true).as_bytes().to_vec();
    let pk_sec1_bytes = pk_projective.to_encoded_point(true).as_bytes().to_vec();

    let c0_sec1 = hex::encode(&c0_sec1_bytes);
    let c1_sec1 = hex::encode(&c1_sec1_bytes);
    let pk_sec1 = hex::encode(&pk_sec1_bytes);

    let (leaf_int, _, _, _) = h_reg(&c0_sec1_bytes, &c1_sec1_bytes)
        .map_err(|e| format!("h_reg evaluation failed: {}", e))?;
    let leaf_decimal = leaf_int.to_string();

    // 1. Write opening_v.txt (private from creation, mode 0600).
    let opening_file = out_path.join("opening_v.txt");
    write_private_file(&opening_file, format!("{}\n", opening_str).as_bytes())?;

    // 2. Write camera_enrollment_private.json (prover-side secret, chmod 600).
    let private_enrollment = CameraEnrollmentPrivate {
        opening_v: opening_str,
        pk_sec1,
    };
    let private_json_file = out_path.join("camera_enrollment_private.json");
    write_private_file(
        &private_json_file,
        serde_json::to_string_pretty(&private_enrollment)?.as_bytes(),
    )?;

    // 3. Write camera_enrollment_public.json (public registration material).
    let public_enrollment = CameraEnrollmentPublic {
        profile: "PicProof-camera-enrollment-v1".to_string(),
        k_profile: format!(
            "{}|{}|{}|{}",
            PROFILE,
            CURVE,
            SUITE,
            core::str::from_utf8(MESSAGE).expect("MESSAGE is an ASCII constant")
        ),
        k_fingerprint: K_PARAMETER_SHA256.to_string(),
        k_sec1_compressed: K_SEC1_COMPRESSED.to_string(),
        c0_sec1: c0_sec1.clone(),
        c1_sec1: c1_sec1.clone(),
        leaf_decimal: leaf_decimal.clone(),
    };
    let public_json_file = out_path.join("camera_enrollment_public.json");
    fs::write(
        &public_json_file,
        serde_json::to_string_pretty(&public_enrollment)?,
    )?;
    let mut perms = fs::metadata(&public_json_file)?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&public_json_file, perms)?;

    println!("CAMERA_ENROLLMENT_OK out_dir={}", out_dir);
    println!("  profile      = {}", public_enrollment.profile);
    println!("  k_profile    = {}", public_enrollment.k_profile);
    println!("  k_fingerprint= {}", public_enrollment.k_fingerprint);
    println!("  leaf_decimal = {}", leaf_decimal);
    println!("  cmPK.C0      = {}", public_enrollment.c0_sec1);
    println!("  cmPK.C1      = {}", public_enrollment.c1_sec1);
    println!("  opening_file = {} (chmod 600)", opening_file.display());
    println!("  public_json  = {}", public_json_file.display());
    println!(
        "  private_json = {} (chmod 600)",
        private_json_file.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "picproof-enroll-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn public_enrollment_does_not_contain_private_material() {
        let public = CameraEnrollmentPublic {
            profile: "PicProof-camera-enrollment-v1".to_string(),
            k_profile: "profile".to_string(),
            k_fingerprint: K_PARAMETER_SHA256.to_string(),
            k_sec1_compressed: K_SEC1_COMPRESSED.to_string(),
            c0_sec1: "02aa".to_string(),
            c1_sec1: "02bb".to_string(),
            leaf_decimal: "123".to_string(),
        };
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains("opening_v"));
        assert!(!json.contains("pk_sec1"));
    }

    #[test]
    fn private_enrollment_contains_required_witness_material() {
        let private = CameraEnrollmentPrivate {
            opening_v: "7".to_string(),
            pk_sec1: "02cc".to_string(),
        };
        let json = serde_json::to_string(&private).unwrap();
        assert!(json.contains("opening_v"));
        assert!(json.contains("pk_sec1"));
    }

    #[test]
    fn private_files_are_created_with_restricted_modes_and_never_overwritten() {
        let dir = temp_dir("modes");
        let opening = dir.join("opening_v.txt");
        let private = dir.join("camera_enrollment_private.json");
        let public = dir.join("camera_enrollment_public.json");

        write_private_file(&opening, b"7\n").unwrap();
        write_private_file(&private, b"{\"opening_v\":\"7\"}\n").unwrap();
        fs::write(&public, b"{}\n").unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            fs::metadata(&opening).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&public).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(write_private_file(&private, b"replacement").is_err());

        fs::remove_dir_all(dir).unwrap();
    }
}
