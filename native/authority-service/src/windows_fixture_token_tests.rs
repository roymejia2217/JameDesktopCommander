//! Disposable Windows token acceptance only. Never compiled into the SCM observer.
use super::*;

// Disposable fixture-only, read-only launch capability observation. No
// privilege is enabled, assigned or added; this is not launcher authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureLaunchPrivilege {
    Absent,
    PresentDisabled,
    Enabled,
}

fn classify_fixture_launch_privileges(
    records: &[PrivilegeRecord],
    assign: (u32, i32),
    quota: (u32, i32),
) -> Result<[FixtureLaunchPrivilege; 2], TokenUnverifiable> {
    if assign == quota {
        return Err(TokenUnverifiable);
    }
    validated_enabled_privilege_indices(records).ok_or(TokenUnverifiable)?;
    let status = |id: (u32, i32)| match records.iter().find(|r| (r.luid_low, r.luid_high) == id) {
        None => FixtureLaunchPrivilege::Absent,
        Some(r) if r.attributes & 2 != 0 => FixtureLaunchPrivilege::Enabled,
        Some(_) => FixtureLaunchPrivilege::PresentDisabled,
    };
    Ok([status(assign), status(quota)])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixtureIssuerLaunch {
    is_primary: bool,
    session_id: u32,
    assign_primary_token: FixtureLaunchPrivilege,
    increase_quota: FixtureLaunchPrivilege,
}

impl FixtureIssuerLaunch {
    fn permits_distinct_primary_launch(self) -> bool {
        // CreateProcessAsUserW can enable an already-held privilege for
        // the duration of its call; absence is not an enablement problem.
        // Presence is necessary for this conservative fixture contract,
        // not proof that creation or cross-principal custody will succeed.
        self.is_primary
            && self.assign_primary_token != FixtureLaunchPrivilege::Absent
            && self.increase_quota != FixtureLaunchPrivilege::Absent
    }
}

fn lookup_fixture_privilege(name: &str) -> Result<(u32, i32), TokenUnverifiable> {
    use windows_sys::Win32::{Foundation::LUID, Security::LookupPrivilegeValueW};
    let name: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
    let mut luid: LUID = unsafe { mem::zeroed() };
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(TokenUnverifiable);
    }
    Ok((luid.LowPart, luid.HighPart))
}

fn observe_fixture_issuer_launch() -> Result<FixtureIssuerLaunch, TokenUnverifiable> {
    use windows_sys::Win32::Security::TokenSessionId;
    let token = open_current_process_token()?;
    let kind: TOKEN_TYPE = query(token.0, TokenType)?.fixed()?;
    let session_id: u32 = query(token.0, TokenSessionId)?.fixed()?;
    let (_, records) = native_privilege_records(&query(token.0, TokenPrivileges)?)?;
    let [assign_primary_token, increase_quota] = classify_fixture_launch_privileges(
        &records,
        lookup_fixture_privilege("SeAssignPrimaryTokenPrivilege")?,
        lookup_fixture_privilege("SeIncreaseQuotaPrivilege")?,
    )?;
    Ok(FixtureIssuerLaunch {
        is_primary: kind == TokenPrimary,
        session_id,
        assign_primary_token,
        increase_quota,
    })
}

// Native observations used only by the disposable storage acceptance
// fixture. The expected SIDs are provisioned by its trusted parent; these
// types never confer access or accept client-supplied claims as evidence.
#[derive(Clone, PartialEq, Eq)]
struct FixturePrincipalEvidence {
    user: Vec<u8>,
    owner: Vec<u8>,
    primary: bool,
    session: u32,
    integrity: u32,
    elevated_group: bool,
    forbidden_privilege: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixturePrincipalRole {
    Service,
    Client,
    Attacker,
}

struct FixturePrincipalSet {
    session: u32,
    issuer: Vec<u8>,
    service: Vec<u8>,
    client: Vec<u8>,
    attacker: Vec<u8>,
}

impl FixturePrincipalSet {
    fn new(
        session: u32,
        issuer: Vec<u8>,
        service: Vec<u8>,
        client: Vec<u8>,
        attacker: Vec<u8>,
    ) -> Result<Self, TokenUnverifiable> {
        let mut unique = HashSet::new();
        for sid in [&issuer, &service, &client, &attacker] {
            if bounded_sid_bytes(sid) != Some(sid.len()) || !unique.insert(sid.as_slice()) {
                return Err(TokenUnverifiable);
            }
        }
        Ok(Self {
            session,
            issuer,
            service,
            client,
            attacker,
        })
    }

    fn classify(
        &self,
        evidence: &FixturePrincipalEvidence,
    ) -> Result<FixturePrincipalRole, TokenUnverifiable> {
        if !evidence.primary
            || evidence.session != self.session
            || evidence.user != evidence.owner
            || evidence.user == self.issuer
            || !(0x2000..0x3000).contains(&evidence.integrity)
            || evidence.elevated_group
            || evidence.forbidden_privilege
        {
            return Err(TokenUnverifiable);
        }
        if evidence.user == self.service {
            Ok(FixturePrincipalRole::Service)
        } else if evidence.user == self.client {
            Ok(FixturePrincipalRole::Client)
        } else if evidence.user == self.attacker {
            Ok(FixturePrincipalRole::Attacker)
        } else {
            Err(TokenUnverifiable)
        }
    }
}

fn observe_fixture_principal() -> Result<FixturePrincipalEvidence, TokenUnverifiable> {
    use windows_sys::Win32::Security::{TokenOwner, TokenSessionId, TOKEN_OWNER};
    let token = open_current_process_token()?;
    let user_info = query(token.0, TokenUser)?;
    let user: TOKEN_USER = user_info.fixed()?;
    let user = user_info.sid(user.User.Sid)?.to_vec();
    let owner_info = query(token.0, TokenOwner)?;
    let owner: TOKEN_OWNER = owner_info.fixed()?;
    let owner = owner_info.sid(owner.Owner)?.to_vec();
    let kind: TOKEN_TYPE = query(token.0, TokenType)?.fixed()?;
    let session: u32 = query(token.0, TokenSessionId)?.fixed()?;
    let integrity = integrity_rid(&query(token.0, TokenIntegrityLevel)?)?;
    let groups = query(token.0, TokenGroups)?;
    let mut elevated_group = false;
    for group in groups.sid_groups()? {
        let checked = groups.copied_sid_group(group)?;
        if !checked.is_consistent() {
            return Err(TokenUnverifiable);
        }
        // Reject even disabled or deny-only membership: this fixture
        // requires dedicated, non-administrator accounts.
        elevated_group |= unsafe { IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid) } != 0
            || unsafe { IsWellKnownSid(group.Sid, WinLocalSystemSid) } != 0;
    }
    let (_, records) = native_privilege_records(&query(token.0, TokenPrivileges)?)?;
    let mut forbidden_privilege = false;
    // These privileges must be absent, not merely disabled, for the
    // dedicated test principals. No system policy is changed here.
    for name in [
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeCreateTokenPrivilege",
        "SeImpersonatePrivilege",
        "SeLoadDriverPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
    ] {
        let luid = lookup_fixture_privilege(name)?;
        forbidden_privilege |= records.iter().any(|r| (r.luid_low, r.luid_high) == luid);
    }
    Ok(FixturePrincipalEvidence {
        user,
        owner,
        primary: kind == TokenPrimary,
        session,
        integrity,
        elevated_group,
        forbidden_privilege,
    })
}

fn read_fixture_principal_set() -> Result<FixturePrincipalSet, TokenUnverifiable> {
    use std::io::Read;
    let file = std::fs::File::open("fixture-principal-input.txt").map_err(|_| TokenUnverifiable)?;
    let mut input = String::new();
    file.take(2049)
        .read_to_string(&mut input)
        .map_err(|_| TokenUnverifiable)?;
    if input.len() > 2048 {
        return Err(TokenUnverifiable);
    }
    let fields: Vec<_> = input.lines().collect();
    let [session, issuer, service, client, attacker] = fields.as_slice() else {
        return Err(TokenUnverifiable);
    };
    let sid =
        |text: &str| crate::windows_managed_volume::sid_bytes(text).map_err(|_| TokenUnverifiable);
    FixturePrincipalSet::new(
        session.parse().map_err(|_| TokenUnverifiable)?,
        sid(issuer)?,
        sid(service)?,
        sid(client)?,
        sid(attacker)?,
    )
}

#[test]
fn distinct_primary_launch_requires_both_native_privileges_present() {
    let record = |id, attributes| PrivilegeRecord {
        luid_low: id,
        luid_high: 0,
        attributes,
    };
    let assign = (11, 0);
    let quota = (12, 0);
    assert_eq!(
        classify_fixture_launch_privileges(&[record(11, 0), record(12, 2)], assign, quota),
        Ok([
            FixtureLaunchPrivilege::PresentDisabled,
            FixtureLaunchPrivilege::Enabled
        ])
    );
    assert_eq!(
        classify_fixture_launch_privileges(&[record(12, 0)], assign, quota),
        Ok([
            FixtureLaunchPrivilege::Absent,
            FixtureLaunchPrivilege::PresentDisabled
        ])
    );
    assert_eq!(
        classify_fixture_launch_privileges(&[record(11, 2), record(11, 0)], assign, quota),
        Err(TokenUnverifiable)
    );
    assert_eq!(
        classify_fixture_launch_privileges(&[record(11, 4)], assign, quota),
        Err(TokenUnverifiable)
    );
    assert_eq!(
        classify_fixture_launch_privileges(&[], assign, assign),
        Err(TokenUnverifiable)
    );
}

#[test]
fn distinct_fixture_principal_rejects_wrong_owner_session_and_authority() {
    let sid = |rid| vec![1, 1, 0, 0, 0, 0, 0, 5, rid, 0, 0, 0];
    let issuer = sid(1);
    let service = sid(2);
    let client = sid(3);
    let attacker = sid(4);
    let roles = FixturePrincipalSet::new(
        7,
        issuer.clone(),
        service.clone(),
        client.clone(),
        attacker.clone(),
    )
    .unwrap();
    let evidence = FixturePrincipalEvidence {
        user: service.clone(),
        owner: service.clone(),
        primary: true,
        session: 7,
        integrity: 0x2000,
        elevated_group: false,
        forbidden_privilege: false,
    };
    assert_eq!(roles.classify(&evidence), Ok(FixturePrincipalRole::Service));
    let mut bad = evidence.clone();
    bad.owner = client.clone();
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.session = 8;
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.primary = false;
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.integrity = 0x3000;
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.elevated_group = true;
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.forbidden_privilege = true;
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.user = issuer.clone();
    bad.owner = issuer.clone();
    assert!(roles.classify(&bad).is_err());
    bad = evidence.clone();
    bad.user = client.clone();
    bad.owner = client.clone();
    assert_eq!(roles.classify(&bad), Ok(FixturePrincipalRole::Client));
    bad.user = attacker.clone();
    bad.owner = attacker.clone();
    assert_eq!(roles.classify(&bad), Ok(FixturePrincipalRole::Attacker));
    assert!(
        FixturePrincipalSet::new(7, issuer.clone(), service.clone(), service, attacker).is_err()
    );
    assert!(FixturePrincipalSet::new(7, issuer, client, vec![0], sid(5)).is_err());
}

#[test]
fn actual_process_cannot_claim_independent_fixture_role() {
    let observed = observe_fixture_principal().unwrap();
    let alternate = |rid| vec![1, 1, 0, 0, 0, 0, 0, 5, rid, 0, 0, 0];
    let roles = FixturePrincipalSet::new(
        observed.session,
        observed.user.clone(),
        alternate(2),
        alternate(3),
        alternate(4),
    )
    .unwrap();
    assert!(roles.classify(&observed).is_err());
    assert!(observed == observe_fixture_principal().unwrap());
}

#[test]
#[ignore = "requires administrator-provisioned fixture principal input and actual dedicated process token"]
fn hosted_fixture_principal_matches_expected_role() {
    let roles = read_fixture_principal_set().expect("trusted fixture principal input");
    let observed = observe_fixture_principal().expect("bounded kernel token observation");
    let role = roles
        .classify(&observed)
        .expect("dedicated primary token, same session and no forbidden authority");
    let marker = match role {
        FixturePrincipalRole::Service => "T011_WINDOWS_FIXTURE_SERVICE_TOKEN_PASS_NONRELEASE",
        FixturePrincipalRole::Client => "T011_WINDOWS_FIXTURE_CLIENT_TOKEN_PASS_NONRELEASE",
        FixturePrincipalRole::Attacker => "T011_WINDOWS_FIXTURE_ATTACKER_TOKEN_PASS_NONRELEASE",
    };
    println!("{marker}");
}

#[test]
#[ignore = "requires the protected hosted fixture issuer and administrator-provisioned principal input"]
fn hosted_fixture_issuer_launch_prerequisites() {
    let roles = read_fixture_principal_set().expect("trusted fixture principal input");
    let observed = observe_fixture_principal().expect("bounded kernel token observation");
    let launch = observe_fixture_issuer_launch().expect("actual issuer launch capability");
    assert!(
        observed.user == roles.issuer
            && observed.primary
            && observed.session == roles.session
            && launch.session_id == roles.session,
        "issuer token or session mismatch"
    );
    assert!(
        launch.permits_distinct_primary_launch(),
        "E_STORAGE_ISSUER_REQUIRED_PRIVILEGE_ABSENT"
    );
    println!("T011_WINDOWS_DISTINCT_ISSUER_PREREQUISITES_PASS_NONRELEASE");
}

#[test]
fn actual_current_token_launch_prerequisite_is_read_only() {
    let before = observe_fixture_issuer_launch().unwrap();
    let after = observe_fixture_issuer_launch().unwrap();
    assert_eq!(before, after);
    assert!(before.is_primary);
    assert_eq!(
        before.permits_distinct_primary_launch(),
        before.is_primary
            && before.assign_primary_token != FixtureLaunchPrivilege::Absent
            && before.increase_quota != FixtureLaunchPrivilege::Absent
    );
}
