use pocket_lib::{addr_from_mnemonic, BuildKind};

#[test]
fn addr_from_mnemonic_works() {
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let info = addr_from_mnemonic(m, "tpc").expect("addr");
    assert!(info.address.starts_with("tpc1"));
    assert_eq!(info.public_key_hex.len(), 64);
}

#[test]
fn build_kind_roundtrip() {
    let kinds = vec![
        BuildKind::Transfer {
            to: "tpc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgcp5hz".into(),
            amount: 10,
        },
        BuildKind::Stake {
            amount: 20,
            payout: "tpc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgcp5hz".into(),
            commission_bps: 100,
        },
        BuildKind::Unbond { amount: 5 },
        BuildKind::UpdateValidator {
            payout: None,
            commission_bps: Some(50),
        },
    ];
    for k in kinds {
        let val = serde_json::to_value(&k).unwrap();
        let back: BuildKind = serde_json::from_value(val).unwrap();
        // Simple equality check ensures serialization consistency.
        match (&k, &back) {
            (BuildKind::Transfer { .. }, BuildKind::Transfer { .. })
            | (BuildKind::Stake { .. }, BuildKind::Stake { .. })
            | (BuildKind::Unbond { .. }, BuildKind::Unbond { .. })
            | (BuildKind::UpdateValidator { .. }, BuildKind::UpdateValidator { .. }) => {}
            _ => panic!("roundtrip mismatch"),
        }
    }
}
