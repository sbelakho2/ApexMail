//! Redis Cluster key layout: the store's FULL key set for one observation
//! must hash to a single slot (shared `{kiwi:<ns>}` hash tag), and the
//! CRC-16/XMODEM implementation must match the Redis Cluster reference
//! vectors. Pure — no Redis needed.

mod common;

use kiwicaptcha_risk::redis::RedisRiskStateStore;

#[test]
fn crc16_reference_vectors() {
    // Redis docs: CRC16("123456789") = 0x31C3; slot("foo") = 12182.
    assert_eq!(RedisRiskStateStore::crc16(b"123456789"), 0x31C3);
    assert_eq!(RedisRiskStateStore::crc16(b"foo") & 0x3FFF, 12_182);
    assert_eq!(RedisRiskStateStore::crc16(b""), 0);
}

#[test]
fn full_observation_key_set_is_single_slot() {
    let ns = common::unique_namespace("keyslot");
    let epoch = (common::T0 / 1000) / 900;
    let source = [0xAA; 16];
    let subnet = [0xBB; 16];
    let session_bytes = [0xCC; 16];
    let principal_bytes = [0xDD; 16];
    let session = Some(session_bytes);
    let principal = Some(principal_bytes);
    let event = [0xEE; 16];

    let keys = RedisRiskStateStore::keys_for(
        &ns,
        epoch,
        epoch,
        &source,
        &subnet,
        session.as_ref().map(|v| v.as_slice()),
        principal.as_ref().map(|v| v.as_slice()),
        &event,
    );
    assert_eq!(
        keys.len(),
        10,
        "source ±1, subnet ±1, session, principal, global, dedupe"
    );

    // Every key shares the hash tag -> one slot.
    assert!(
        RedisRiskStateStore::assert_same_slot(&keys).is_ok(),
        "full key set must share one cluster slot"
    );

    // Key shape sanity: the tag is embedded and the ids are hex pseudonyms.
    let tag = format!("{{kiwi:{ns}}}");
    for key in &keys {
        assert!(key.starts_with(&tag), "key {key} must carry the {tag} tag");
    }
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:src:") && k.contains(&hex::encode(source))));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:net:") && k.contains(&hex::encode(subnet))));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:session:") && k.contains(&hex::encode(session_bytes))));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:principal:") && k.contains(&hex::encode(principal_bytes))));
    assert!(keys.iter().any(|k| k.ends_with(":risk:global")));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:dedupe:") && k.contains(&hex::encode(event))));

    // A foreign tag in the set must fail the slot assertion.
    let mut broken = keys.clone();
    broken[0] = broken[0].replace(&tag, &format!("{{kiwi:{}}}", common::unique_namespace("x")));
    assert!(RedisRiskStateStore::assert_same_slot(&broken).is_err());
}

#[test]
fn keys_for_maps_missing_ids_to_the_zero_placeholder() {
    let ns = common::unique_namespace("keyslot");
    let epoch = (common::T0 / 1000) / 900;
    let keys = RedisRiskStateStore::keys_for(
        &ns, epoch, epoch, &[1u8; 16], &[2u8; 16], None, None, &[3u8; 16],
    );
    assert!(
        keys.iter()
            .any(|k| k.ends_with(&format!(":risk:session:{}", "0".repeat(32)))),
        "absent session must use the contract zero placeholder"
    );
    assert!(
        keys.iter()
            .any(|k| k.ends_with(&format!(":risk:principal:{}", "0".repeat(32)))),
        "absent principal must use the contract zero placeholder"
    );
}
