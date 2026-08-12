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
    let (src_epoch, src_prev, src_cur, src_next) = common::epoch_ids(0xAA, common::T0);
    let (net_epoch, net_prev, net_cur, net_next) = common::epoch_ids(0xBB, common::T0);
    let session_bytes = [0xCC; 16];
    let principal_bytes = [0xDD; 16];
    let session = Some(session_bytes);
    let principal = Some(principal_bytes);
    let event = common::event_id(0xEE);

    let keys = RedisRiskStateStore::keys_for(
        &ns,
        src_epoch,
        &src_prev,
        &src_cur,
        &src_next,
        net_epoch,
        &net_prev,
        &net_cur,
        &net_next,
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
    // The current-epoch key carries the CURRENT pseudonym; the ±1 keys
    // carry the epoch-scoped prev/next pseudonyms (never the current one).
    assert!(keys
        .iter()
        .any(|k| k == &format!("{tag}:risk:src:{src_epoch}:{src_cur}")));
    assert!(keys
        .iter()
        .any(|k| k == &format!("{tag}:risk:src:{}:{src_prev}", src_epoch - 1)));
    assert!(keys
        .iter()
        .any(|k| k == &format!("{tag}:risk:src:{}:{src_next}", src_epoch + 1)));
    assert!(keys
        .iter()
        .any(|k| k == &format!("{tag}:risk:net:{net_epoch}:{net_cur}")));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:session:") && k.contains(&hex::encode(session_bytes))));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:principal:") && k.contains(&hex::encode(principal_bytes))));
    assert!(keys.iter().any(|k| k.ends_with(":risk:global")));
    assert!(keys
        .iter()
        .any(|k| k.contains(":risk:dedupe:") && k.contains(&event)));

    // A foreign tag in the set must fail the slot assertion.
    let mut broken = keys.clone();
    broken[0] = broken[0].replace(&tag, &format!("{{kiwi:{}}}", common::unique_namespace("x")));
    assert!(RedisRiskStateStore::assert_same_slot(&broken).is_err());
}

#[test]
fn keys_for_maps_missing_ids_to_the_zero_placeholder() {
    let ns = common::unique_namespace("keyslot");
    let (src_epoch, src_prev, src_cur, src_next) = common::epoch_ids(0xAA, common::T0);
    let (net_epoch, net_prev, net_cur, net_next) = common::epoch_ids(0xBB, common::T0);
    let keys = RedisRiskStateStore::keys_for(
        &ns,
        src_epoch,
        &src_prev,
        &src_cur,
        &src_next,
        net_epoch,
        &net_prev,
        &net_cur,
        &net_next,
        None,
        None,
        &common::event_id(3),
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
