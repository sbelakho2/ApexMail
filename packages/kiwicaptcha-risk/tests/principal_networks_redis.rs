use kiwicaptcha_risk::redis::RedisPrincipalNetworks;
use kiwicaptcha_risk::store::PrincipalNetworkTagStore;

#[test]
fn redis_principal_networks_full_surface_on_real_redis() {
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        return;
    };
    let Ok(client) = redis::Client::open(url) else {
        return;
    };
    // Reachability gate: the real-Redis suite skips silently without.
    let Ok(mut conn) = client.get_connection() else {
        return;
    };
    let _: redis::RedisResult<()> = redis::cmd("FLUSHDB").query(&mut conn);

    let store = RedisPrincipalNetworks::new(client, "f16rust");
    let principal = "ab".repeat(16);

    // record + seen + trust
    assert!(store
        .record_principal_network_tag(&principal, "net:00ff", true)
        .unwrap());
    assert_eq!(
        store
            .principal_network_seen(&principal, "net:00ff")
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        store.tag_is_trusted(&principal, "net:00ff").unwrap(),
        Some(true)
    );
    assert_eq!(
        store.principal_has_trusted_network(&principal).unwrap(),
        Some(true)
    );

    // unseen answer
    assert_eq!(
        store
            .principal_network_seen(&principal, "net:dead")
            .unwrap(),
        Some(false)
    );

    // the just-written tag survives a same-ms cap eviction
    for i in 0..32u32 {
        let tag = format!("session:{:032x}", i);
        store
            .record_principal_network_tag(&principal, &tag, false)
            .unwrap();
    }
    let fresh = "session:ffffffff";
    store
        .record_principal_network_tag(&principal, fresh, false)
        .unwrap();
    assert_eq!(
        store.principal_network_seen(&principal, fresh).unwrap(),
        Some(true)
    );

    // forget_devices clears the session and device classes
    assert!(store
        .record_principal_network_tag(&principal, "device:abcd", true)
        .unwrap());
    // a trusted network minted under the old credentials re-arms at
    // the revocation: the trust mirrors go, the bare seen-ness stays
    assert!(store
        .record_principal_network_tag(&principal, "net:00ff", true)
        .unwrap());
    assert_eq!(
        store.principal_has_trusted_network(&principal).unwrap(),
        Some(true)
    );
    store.forget_devices(&principal).unwrap();
    assert_eq!(
        store.principal_network_seen(&principal, fresh).unwrap(),
        Some(false)
    );
    assert_eq!(
        store.tag_is_trusted(&principal, "device:abcd").unwrap(),
        Some(false)
    );
    // the net class survives the revocation, untrusted: the next
    // login re-runs the first-attempt gate on its own evidence
    assert_eq!(
        store
            .principal_network_seen(&principal, "net:00ff")
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        store.tag_is_trusted(&principal, "net:00ff").unwrap(),
        Some(false)
    );
    assert_eq!(
        store.principal_has_trusted_network(&principal).unwrap(),
        Some(false)
    );

    // invalid tags are refused, never answered as "not seen"
    assert!(store.principal_network_seen(&principal, "nope").is_err());
}
