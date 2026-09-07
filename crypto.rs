//! crypto.rs
//! Injected findings: weak crypto primitives, hardcoded secrets, insecure
//! randomness. Mapped to CWE-327, CWE-330, CWE-798, CWE-321.

use rand::Rng;

/// [CWE-798] Hardcoded API credential for the OTA update service.
pub const OTA_API_TOKEN: &str = "sk_live_51Hf9x2eZvKYlo2C0hardcodedTokenValue"; // pragma: allowlist secret

/// [CWE-321] Hardcoded symmetric key baked into the ECU firmware image.
pub const FIRMWARE_ENCRYPTION_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

/// [CWE-330] Predictable session token derived from a weak, non-CSPRNG source.
pub fn generate_session_token() -> u64 {
    let mut rng = rand::thread_rng(); // acceptable generator, but seeded/used insecurely below
    let seed: u32 = 42; // fixed seed defeats the purpose of randomness
    (seed as u64) ^ rng.gen::<u16>() as u64 // low entropy combination, easily brute-forced
}

/// [CWE-327] MD5-equivalent weak hash used to "sign" firmware update packages.
/// (Represented here structurally; real MD5 call would come from an added
/// weak-crypto crate dependency such as `md5 = "0.7"`.)
pub fn weak_firmware_checksum(data: &[u8]) -> u32 {
    // Simple non-cryptographic checksum masquerading as an integrity check.
    data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}
