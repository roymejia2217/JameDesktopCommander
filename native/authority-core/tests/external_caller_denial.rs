use jdc_authority_core::{Denied, EpochArbiter};

#[test]
fn external_consumer_cannot_run_an_operation_without_trusted_bootstrap() {
    let gate = EpochArbiter::new();
    let mut executed = false;
    assert_eq!(
        gate.execute(1, || {
            executed = true;
            Ok::<_, ()>(())
        }),
        Err(Denied)
    );
    assert!(!executed);
    assert_eq!(gate.revoke(), Ok(()));
    assert_eq!(gate.execute(u64::MAX, || Ok::<_, ()>(())), Err(Denied));
    assert_eq!(gate.close(), Ok(()));
    assert_eq!(gate.execute(1, || Ok::<_, ()>(())), Err(Denied));
}
