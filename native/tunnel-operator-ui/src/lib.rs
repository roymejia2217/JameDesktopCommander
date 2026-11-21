pub mod backend;

use serde::Deserialize;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024;
pub const BACKEND_TIMEOUT_SECONDS: u64 = 10;

/// Windows uses the D3D12 backend rather than the Vulkan ICD. The test host's
/// Intel 30.0.100.9805 Vulkan driver crashed at startup in igvk64.dll.
/// This is an explicit official wgpu backend choice, not a driver patch.
pub fn native_wgpu_backends() -> eframe::wgpu::Backends {
    #[cfg(windows)]
    {
        eframe::wgpu::Backends::DX12
    }
    #[cfg(target_os = "linux")]
    {
        eframe::wgpu::Backends::VULKAN | eframe::wgpu::Backends::GL
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        eframe::wgpu::Backends::PRIMARY
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupMode {
    Graphical,
    CheckInstallation,
}

/// Unrecognized launch options are rejected; users cannot select a different backend.
pub fn startup_mode(args: &[std::ffi::OsString]) -> Result<StartupMode, &'static str> {
    match args {
        [] => Ok(StartupMode::Graphical),
        [only] if only == std::ffi::OsStr::new("--check-installation") => {
            Ok(StartupMode::CheckInstallation)
        }
        _ => Err("Unsupported operator launch options"),
    }
}

/// A non-authorizing presentation object. Never include source paths or raw errors.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Overview {
    pub kind: String,
    pub platform: String,
    pub capabilities: String,
    pub observed_at: String,
    #[serde(alias = "serviceRegistration")]
    pub task_registration: String,
    pub local_health: String,
    pub mcp_initialize: String,
    pub tool_discovery: String,
    pub control_plane: String,
    pub remote_delivery: String,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Verdict {
    pub state: String,
    pub reason_code: String,
}

impl Overview {
    pub fn reason(&self) -> &str {
        &self.verdict.reason_code
    }

    pub fn registration_label(&self) -> &'static str {
        if self.platform == "linux" {
            "Tunnel service"
        } else {
            "Tunnel task"
        }
    }
}

fn one_of(value: &str, accepted: &[&str]) -> bool {
    accepted.contains(&value)
}

/// Local service failures must never be paired with an observation that
/// claims a working tunnel, active MCP state or a current control-plane error.
fn linux_service_verdict_consistent(snapshot: &Overview) -> bool {
    let observational_fields_unverified = snapshot.mcp_initialize == "unverified"
        && snapshot.tool_discovery == "unverified"
        && snapshot.control_plane == "unverified";
    match snapshot.verdict.reason_code.as_str() {
        "SERVICE_INACTIVE" => {
            observational_fields_unverified
                && snapshot.task_registration == "observed"
                && snapshot.local_health == "not_ready"
                && snapshot.verdict.state == "degraded"
        }
        "SERVICE_NOT_ENABLED" => {
            observational_fields_unverified
                && snapshot.task_registration == "observed"
                && snapshot.local_health == "unverified"
                && snapshot.verdict.state == "unverified"
        }
        "SERVICE_STATUS_UNAVAILABLE" => {
            observational_fields_unverified
                && snapshot.task_registration == "unverified"
                && snapshot.local_health == "unverified"
                && snapshot.verdict.state == "unverified"
        }
        _ => true,
    }
}

/// Require local reason codes to agree with the same evidence precedence
/// used by the shared TypeScript operator assessor on Windows and Linux.
/// This is only input validation, never an authority or remote success grant.
fn local_verdict_consistent(snapshot: &Overview) -> bool {
    let state = snapshot.verdict.state.as_str();
    let health = snapshot.local_health.as_str();
    let initialize = snapshot.mcp_initialize.as_str();
    let discovery = snapshot.tool_discovery.as_str();
    let plane = snapshot.control_plane.as_str();
    let registered = snapshot.task_registration == "observed";
    match snapshot.verdict.reason_code.as_str() {
        "LOCAL_NOT_READY" => {
            registered
                && state == "degraded"
                && health == "not_ready"
                && matches!(plane, "none" | "unverified")
        }
        "LOCAL_READINESS_UNVERIFIED" => {
            registered && state == "unverified" && health == "unverified" && plane == "none"
        }
        "MCP_HANDSHAKE_UNOBSERVED" => {
            registered
                && state == "unverified"
                && health == "ready"
                && plane == "none"
                && initialize != "observed"
                && discovery != "observed_complete"
        }
        "MCP_TOOLS_LIST_UNVERIFIED" => {
            registered
                && state == "unverified"
                && health == "ready"
                && plane == "none"
                && initialize == "observed"
                && discovery != "observed_complete"
        }
        "CONTROL_PLANE_UNVERIFIED" => {
            registered && state == "unverified" && plane == "unverified" && health != "not_ready"
        }
        _ => true,
    }
}

/// Unavailable/conflict reasons must preserve the producer's loss-of-evidence
/// contract. Neither a missing diagnostic nor contradictory local observations
/// can be displayed beside a successful handshake or a verified control plane.
fn unavailable_verdict_consistent(snapshot: &Overview, linux: bool) -> bool {
    let unknown_evidence = snapshot.verdict.state == "unverified"
        && snapshot.mcp_initialize == "unverified"
        && snapshot.tool_discovery == "unverified"
        && snapshot.control_plane == "unverified";
    match snapshot.verdict.reason_code.as_str() {
        "TASK_STATUS_UNAVAILABLE" => {
            !linux
                && unknown_evidence
                && snapshot.task_registration == "unverified"
                && snapshot.local_health == "unverified"
        }
        "LOCAL_DIAGNOSTICS_UNAVAILABLE" => {
            unknown_evidence
                && snapshot.task_registration == "observed"
                && (if linux {
                    snapshot.local_health == "unverified"
                } else {
                    one_of(&snapshot.local_health, &["ready", "not_ready"])
                })
        }
        "LOCAL_EVIDENCE_CONFLICT" => {
            unknown_evidence
                && snapshot.local_health == "unverified"
                && (linux || snapshot.task_registration == "observed")
        }
        _ => true,
    }
}

pub fn parse_overview(raw: &[u8]) -> Result<Overview, &'static str> {
    if raw.is_empty() || raw.len() > MAX_SNAPSHOT_BYTES {
        return Err("Operator response size out of bounds");
    }
    // Deserialize directly first: Serde's struct visitor rejects duplicate
    // known fields; a Value round-trip would silently keep the last duplicate.
    let snapshot: Overview =
        serde_json::from_slice(raw).map_err(|_| "Invalid operator response schema")?;
    let raw_object: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| "Invalid operator response schema")?;
    let fields = raw_object
        .as_object()
        .ok_or("Invalid operator response schema")?;
    // Do not let aliasing blur the Windows task and Linux service contracts.
    let linux = match (
        fields.get("kind").and_then(serde_json::Value::as_str),
        fields.get("platform").and_then(serde_json::Value::as_str),
    ) {
        (Some("tunnel_operator_overview_v1"), Some("win32"))
            if fields.contains_key("taskRegistration")
                && !fields.contains_key("serviceRegistration") =>
        {
            false
        }
        (Some("tunnel_operator_linux_overview_v1"), Some("linux"))
            if fields.contains_key("serviceRegistration")
                && !fields.contains_key("taskRegistration") =>
        {
            true
        }
        _ => return Err("Unsupported operator platform or registration schema"),
    };
    if snapshot.capabilities != "read_only"
        || !one_of(&snapshot.task_registration, &["observed", "unverified"])
        || !one_of(
            &snapshot.local_health,
            &["ready", "not_ready", "unverified"],
        )
        || !one_of(
            &snapshot.mcp_initialize,
            &["observed", "not_observed", "unverified"],
        )
        || !one_of(
            &snapshot.tool_discovery,
            &["observed_complete", "observed_incomplete", "unverified"],
        )
        || !one_of(
            &snapshot.control_plane,
            &[
                "none",
                "credential_rejected",
                "permission_denied",
                "rate_limited",
                "server_error",
                "other_http_error",
                "unverified",
            ],
        )
        || snapshot.remote_delivery != "not_observed"
        || !one_of(&snapshot.verdict.state, &["degraded", "unverified"])
        || !one_of(
            &snapshot.verdict.reason_code,
            &[
                "CONTROL_PLANE_CREDENTIAL_REJECTED",
                "CONTROL_PLANE_FORBIDDEN",
                "CONTROL_PLANE_RATE_LIMITED",
                "CONTROL_PLANE_SERVER_ERROR",
                "CONTROL_PLANE_HTTP_ERROR",
                "CONTROL_PLANE_UNVERIFIED",
                "LOCAL_NOT_READY",
                "LOCAL_READINESS_UNVERIFIED",
                "MCP_HANDSHAKE_UNOBSERVED",
                "MCP_TOOLS_LIST_UNVERIFIED",
                "REMOTE_ROUND_TRIP_UNVERIFIED",
                "TASK_STATUS_UNAVAILABLE",
                "CLIENT_PROVENANCE_UNVERIFIED",
                "SERVICE_STATUS_UNAVAILABLE",
                "SERVICE_INACTIVE",
                "SERVICE_NOT_ENABLED",
                "LOCAL_DIAGNOSTICS_UNAVAILABLE",
                "LOCAL_EVIDENCE_CONFLICT",
            ],
        )
        || snapshot.observed_at.len() > 64
        || OffsetDateTime::parse(&snapshot.observed_at, &Rfc3339).is_err()
    {
        return Err("Unsupported or contradictory operator evidence");
    }
    // The backend's cause must be supported by the observed control-plane
    // category. Otherwise an unverified probe could be displayed as HTTP 401.
    let observed_failure = match snapshot.control_plane.as_str() {
        "credential_rejected" => Some("CONTROL_PLANE_CREDENTIAL_REJECTED"),
        "permission_denied" => Some("CONTROL_PLANE_FORBIDDEN"),
        "rate_limited" => Some("CONTROL_PLANE_RATE_LIMITED"),
        "server_error" => Some("CONTROL_PLANE_SERVER_ERROR"),
        "other_http_error" => Some("CONTROL_PLANE_HTTP_ERROR"),
        _ => None,
    };
    if let Some(expected) = observed_failure {
        if snapshot.verdict.reason_code != expected || snapshot.verdict.state != "degraded" {
            return Err("Control-plane fault contradicts diagnostic reason");
        }
    } else if matches!(
        snapshot.verdict.reason_code.as_str(),
        "CONTROL_PLANE_CREDENTIAL_REJECTED"
            | "CONTROL_PLANE_FORBIDDEN"
            | "CONTROL_PLANE_RATE_LIMITED"
            | "CONTROL_PLANE_SERVER_ERROR"
            | "CONTROL_PLANE_HTTP_ERROR"
    ) {
        return Err("Control-plane fault has no matching observation");
    }
    if !local_verdict_consistent(&snapshot) {
        return Err("Local diagnostic reason contradicts observed evidence");
    }
    if !unavailable_verdict_consistent(&snapshot, linux) {
        return Err("Unavailable diagnostic contradicts observed evidence");
    }
    // Remote delivery can be the only remaining unknown only after every
    // local readiness, handshake, tool-discovery and control-plane gate passed.
    if snapshot.verdict.reason_code == "REMOTE_ROUND_TRIP_UNVERIFIED"
        && (snapshot.verdict.state != "unverified"
            || snapshot.task_registration != "observed"
            || snapshot.local_health != "ready"
            || snapshot.mcp_initialize != "observed"
            || snapshot.tool_discovery != "observed_complete"
            || snapshot.control_plane != "none")
    {
        return Err("Remote-only uncertainty contradicts incomplete local evidence");
    }
    if (linux && snapshot.verdict.reason_code == "TASK_STATUS_UNAVAILABLE")
        || (!linux
            && one_of(
                &snapshot.verdict.reason_code,
                &[
                    "SERVICE_STATUS_UNAVAILABLE",
                    "SERVICE_INACTIVE",
                    "SERVICE_NOT_ENABLED",
                ],
            ))
    {
        return Err("Operator reason does not belong to its platform");
    }
    // A registered Windows task without a verified client is not a missing
    // task; no local, MCP, or control-plane readiness follows from its XML.
    if snapshot.verdict.reason_code == "CLIENT_PROVENANCE_UNVERIFIED"
        && (linux
            || snapshot.task_registration != "observed"
            || snapshot.local_health != "unverified"
            || snapshot.mcp_initialize != "unverified"
            || snapshot.tool_discovery != "unverified"
            || snapshot.control_plane != "unverified"
            || snapshot.remote_delivery != "not_observed"
            || snapshot.verdict.state != "unverified")
    {
        return Err("Unverified client cannot claim operational evidence");
    }
    if linux && !linux_service_verdict_consistent(&snapshot) {
        return Err("Linux service status contradicts local evidence");
    }
    // If task/service registration is unavailable, no trusted installed
    // instance can be linked to a current local or control-plane observation.
    if snapshot.task_registration == "unverified"
        && (snapshot.local_health != "unverified"
            || snapshot.mcp_initialize != "unverified"
            || snapshot.tool_discovery != "unverified"
            || snapshot.control_plane != "unverified")
    {
        return Err("Unverified registration cannot assert operational evidence");
    }
    if snapshot.mcp_initialize != "observed" && snapshot.tool_discovery == "observed_complete" {
        return Err("MCP tools cannot be complete without initialization evidence");
    }
    Ok(snapshot)
}

/// A local backend timestamp that is old or implausibly future-dated is not fresh.
/// Neither case is evidence of a remote MCP request.
pub fn observation_is_stale(observed_at: &str, now: OffsetDateTime) -> bool {
    let Ok(observed) = OffsetDateTime::parse(observed_at, &Rfc3339) else {
        return true;
    };
    let elapsed = now - observed;
    elapsed > time::Duration::seconds(30) || elapsed < time::Duration::seconds(-5)
}

/// UI location is fixed by the installed package layout; no PATH lookup or user-selected binary.
#[derive(Clone, Debug)]
pub struct InstalledLayout {
    pub root: PathBuf,
    pub node: PathBuf,
    pub entrypoint: PathBuf,
}

impl InstalledLayout {
    pub fn arguments(&self) -> [&'static str; 2] {
        ["tunnel", "overview"]
    }
}

pub fn installed_layout(ui_executable: &Path) -> Result<InstalledLayout, &'static str> {
    #[cfg(windows)]
    let expected = "jdc-tunnel-operator-ui.exe";
    #[cfg(not(windows))]
    let expected = "jdc-tunnel-operator-ui";

    if !ui_executable.is_absolute()
        || ui_executable
            .file_name()
            .is_none_or(|name| name != expected)
    {
        return Err("Unknown operator executable location");
    }
    let root = ui_executable
        .parent()
        .ok_or("Missing installed UI directory")?
        .to_owned();
    #[cfg(windows)]
    let node = root.join("runtime").join("node.exe");
    #[cfg(not(windows))]
    let node = root.join("runtime").join("node");
    Ok(InstalledLayout {
        entrypoint: root.join("dist").join("index.js"),
        root,
        node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
      "kind":"tunnel_operator_overview_v1",
      "platform":"win32",
      "capabilities":"read_only",
      "observedAt":"2026-11-06T14:53:31.698Z",
      "taskRegistration":"observed",
      "localHealth":"ready",
      "mcpInitialize":"observed",
      "toolDiscovery":"observed_incomplete",
      "controlPlane":"credential_rejected",
      "remoteDelivery":"not_observed",
      "verdict":{"state":"degraded", "reasonCode":"CONTROL_PLANE_CREDENTIAL_REJECTED"}
    }"#;

    fn linux_sample() -> String {
        GOOD.replace(
            "tunnel_operator_overview_v1",
            "tunnel_operator_linux_overview_v1",
        )
        .replace("\"platform\":\"win32\"", "\"platform\":\"linux\"")
        .replace("\"taskRegistration\"", "\"serviceRegistration\"")
    }

    const UNVERIFIED_CLIENT: &str = r#"{
      "kind":"tunnel_operator_overview_v1",
      "platform":"win32",
      "capabilities":"read_only",
      "observedAt":"2026-11-10T12:00:00Z",
      "taskRegistration":"observed",
      "localHealth":"unverified",
      "mcpInitialize":"unverified",
      "toolDiscovery":"unverified",
      "controlPlane":"unverified",
      "remoteDelivery":"not_observed",
      "verdict":{"state":"unverified","reasonCode":"CLIENT_PROVENANCE_UNVERIFIED"}
    }"#;

    #[test]
    fn unverified_registration_cannot_claim_a_control_plane_http_observation() {
        // A missing task/service identity cannot authenticate a 401/403/429
        // or server-side HTTP diagnosis, even if the remote JSON says it did.
        for baseline in [GOOD.to_string(), linux_sample()] {
            let mut snapshot: serde_json::Value = serde_json::from_str(&baseline).unwrap();
            let linux = snapshot["platform"] == "linux";
            let field = if linux {
                "serviceRegistration"
            } else {
                "taskRegistration"
            };
            snapshot[field] = "unverified".into();
            snapshot["localHealth"] = "unverified".into();
            snapshot["mcpInitialize"] = "unverified".into();
            snapshot["toolDiscovery"] = "unverified".into();
            for (category, reason) in [
                ("credential_rejected", "CONTROL_PLANE_CREDENTIAL_REJECTED"),
                ("permission_denied", "CONTROL_PLANE_FORBIDDEN"),
                ("rate_limited", "CONTROL_PLANE_RATE_LIMITED"),
                ("server_error", "CONTROL_PLANE_SERVER_ERROR"),
                ("other_http_error", "CONTROL_PLANE_HTTP_ERROR"),
                ("none", "CONTROL_PLANE_UNVERIFIED"),
            ] {
                snapshot["controlPlane"] = category.into();
                snapshot["verdict"]["reasonCode"] = reason.into();
                snapshot["verdict"]["state"] = if category == "none" {
                    "unverified"
                } else {
                    "degraded"
                }
                .into();
                assert!(
                    parse_overview(&serde_json::to_vec(&snapshot).unwrap()).is_err(),
                    "{field} unverified must not claim {category} as observed"
                );
            }
            // Normal missing-registration reports remain representable.
            snapshot["controlPlane"] = "unverified".into();
            snapshot["verdict"]["state"] = "unverified".into();
            snapshot["verdict"]["reasonCode"] = if linux {
                "SERVICE_STATUS_UNAVAILABLE"
            } else {
                "TASK_STATUS_UNAVAILABLE"
            }
            .into();
            assert!(parse_overview(&serde_json::to_vec(&snapshot).unwrap()).is_ok());
            // Real registration with original evidence remains usable.
            assert!(parse_overview(baseline.as_bytes()).is_ok());
        }
    }

    #[test]
    fn windows_client_provenance_reason_requires_observed_task_and_unknown_health() {
        let observed = parse_overview(UNVERIFIED_CLIENT.as_bytes())
            .expect("registered task with unverified client is valid evidence");
        assert_eq!(observed.reason(), "CLIENT_PROVENANCE_UNVERIFIED");
        assert_eq!(observed.task_registration, "observed");

        for (field, value) in [
            ("taskRegistration", "unverified"),
            ("localHealth", "ready"),
            ("mcpInitialize", "observed"),
            ("controlPlane", "none"),
        ] {
            let mut contradictory: serde_json::Value =
                serde_json::from_str(UNVERIFIED_CLIENT).unwrap();
            contradictory[field] = serde_json::Value::String(value.into());
            let bytes = serde_json::to_vec(&contradictory).unwrap();
            assert!(parse_overview(&bytes).is_err(), "{field}={value}");
        }

        let linux = UNVERIFIED_CLIENT
            .replace(
                "tunnel_operator_overview_v1",
                "tunnel_operator_linux_overview_v1",
            )
            .replace("\"platform\":\"win32\"", "\"platform\":\"linux\"")
            .replace("\"taskRegistration\"", "\"serviceRegistration\"");
        assert!(
            parse_overview(linux.as_bytes()).is_err(),
            "Windows-only client reason must not be accepted on Linux"
        );
    }

    #[test]
    fn linux_read_only_contract_accepts_registered_service_without_claiming_remote_success() {
        let overview = parse_overview(linux_sample().as_bytes()).expect("supported Linux evidence");
        assert_eq!(overview.platform, "linux");
        assert_eq!(overview.task_registration, "observed");
        assert_eq!(overview.remote_delivery, "not_observed");
        assert_eq!(overview.reason(), "CONTROL_PLANE_CREDENTIAL_REJECTED");
    }

    fn inactive_linux_sample() -> String {
        linux_sample()
            .replace("\"localHealth\":\"ready\"", "\"localHealth\":\"not_ready\"")
            .replace("\"mcpInitialize\":\"observed\"", "\"mcpInitialize\":\"unverified\"")
            .replace("\"toolDiscovery\":\"observed_incomplete\"", "\"toolDiscovery\":\"unverified\"")
            .replace("\"controlPlane\":\"credential_rejected\"", "\"controlPlane\":\"unverified\"")
            .replace("\"verdict\":{\"state\":\"degraded\", \"reasonCode\":\"CONTROL_PLANE_CREDENTIAL_REJECTED\"}",
                     "\"verdict\":{\"state\":\"degraded\", \"reasonCode\":\"SERVICE_INACTIVE\"}")
    }

    #[test]
    fn linux_service_state_reasons_are_supported_without_healthy_promotion() {
        let inactive = inactive_linux_sample();
        let view = parse_overview(inactive.as_bytes()).expect("inactive service is supported");
        assert_eq!(view.reason(), "SERVICE_INACTIVE");
        assert_eq!(view.control_plane, "unverified");
        assert_eq!(view.remote_delivery, "not_observed");
    }

    #[test]
    fn linux_service_inactive_cannot_claim_a_current_credential_error() {
        let bad = inactive_linux_sample().replace(
            "\"controlPlane\":\"unverified\"",
            "\"controlPlane\":\"credential_rejected\"",
        );
        assert!(parse_overview(bad.as_bytes()).is_err());
    }

    #[test]
    fn linux_not_enabled_cannot_claim_active_service_evidence() {
        let not_enabled = inactive_linux_sample()
            .replace(
                "\"localHealth\":\"not_ready\"",
                "\"localHealth\":\"unverified\"",
            )
            .replace(
                "\"verdict\":{\"state\":\"degraded\", \"reasonCode\":\"SERVICE_INACTIVE\"}",
                "\"verdict\":{\"state\":\"unverified\", \"reasonCode\":\"SERVICE_NOT_ENABLED\"}",
            );
        assert_eq!(
            parse_overview(not_enabled.as_bytes()).unwrap().reason(),
            "SERVICE_NOT_ENABLED"
        );
        let credential_claim = not_enabled.replace(
            "\"controlPlane\":\"unverified\"",
            "\"controlPlane\":\"credential_rejected\"",
        );
        assert!(parse_overview(credential_claim.as_bytes()).is_err());
    }

    #[test]
    fn linux_service_status_unavailable_cannot_claim_ready_local_health() {
        let unavailable = inactive_linux_sample()
            .replace("\"serviceRegistration\":\"observed\"",
                     "\"serviceRegistration\":\"unverified\"")
            .replace("\"verdict\":{\"state\":\"degraded\", \"reasonCode\":\"SERVICE_INACTIVE\"}",
                     "\"verdict\":{\"state\":\"unverified\", \"reasonCode\":\"SERVICE_STATUS_UNAVAILABLE\"}");
        let unavailable = unavailable.replace(
            "\"localHealth\":\"not_ready\"",
            "\"localHealth\":\"unverified\"",
        );
        assert_eq!(
            parse_overview(unavailable.as_bytes()).unwrap().reason(),
            "SERVICE_STATUS_UNAVAILABLE"
        );
        let contradictory = unavailable.replace(
            "\"serviceRegistration\":\"unverified\"",
            "\"serviceRegistration\":\"observed\"",
        );
        assert!(parse_overview(contradictory.as_bytes()).is_err());
    }

    #[test]
    fn reject_cross_platform_schema_confusion_and_untrusted_linux_source_fields() {
        let linux = linux_sample();
        assert!(
            parse_overview(
                linux
                    .replace("\"serviceRegistration\"", "\"taskRegistration\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_overview(
                linux
                    .replace("\"platform\":\"linux\"", "\"platform\":\"win32\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_overview(
                GOOD.replace("\"platform\":\"win32\"", "\"platform\":\"linux\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_overview(
                linux
                    .replace("\"kind\"", "\"profilePath\":\"secret\",\"kind\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_overview(
                linux
                    .replace(
                        "\"serviceRegistration\"",
                        "\"taskRegistration\":\"observed\",\"serviceRegistration\""
                    )
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn duplicated_linux_schema_fields_cannot_override_prior_untrusted_values() {
        let linux = linux_sample();
        let duplicated_kind = linux.replacen("\"kind\"", "\"kind\":\"untrusted\",\"kind\"", 1);
        let duplicated_platform =
            linux.replacen("\"platform\"", "\"platform\":\"win32\",\"platform\"", 1);
        let duplicated_registration = linux.replacen(
            "\"serviceRegistration\"",
            "\"serviceRegistration\":\"unverified\",\"serviceRegistration\"",
            1,
        );
        assert!(parse_overview(duplicated_kind.as_bytes()).is_err());
        assert!(parse_overview(duplicated_platform.as_bytes()).is_err());
        assert!(parse_overview(duplicated_registration.as_bytes()).is_err());
    }

    #[test]
    fn valid_live_observation_does_not_promote_remote_health() {
        let value = parse_overview(GOOD.as_bytes()).unwrap();
        assert_eq!(value.remote_delivery, "not_observed");
        assert_eq!(value.reason(), "CONTROL_PLANE_CREDENTIAL_REJECTED");
        assert_eq!(value.control_plane, "credential_rejected");
    }

    #[test]
    fn rejects_control_plane_errors_without_corresponding_evidence() {
        for baseline in [GOOD.to_string(), linux_sample()] {
            for wrong in [
                "unverified",
                "none",
                "permission_denied",
                "rate_limited",
                "server_error",
                "other_http_error",
            ] {
                let inconsistent = baseline.replace(
                    "\"controlPlane\":\"credential_rejected\"",
                    &format!("\"controlPlane\":\"{wrong}\""),
                );
                assert!(
                    parse_overview(inconsistent.as_bytes()).is_err(),
                    "a reported credential rejection cannot be based on {wrong}"
                );
            }
            let wrong_state =
                baseline.replace("\"state\":\"degraded\"", "\"state\":\"unverified\"");
            assert!(parse_overview(wrong_state.as_bytes()).is_err());
        }
    }

    #[test]
    fn accepts_matching_control_plane_failure_codes_on_both_platforms() {
        for baseline in [GOOD.to_string(), linux_sample()] {
            for (evidence, reason) in [
                ("credential_rejected", "CONTROL_PLANE_CREDENTIAL_REJECTED"),
                ("permission_denied", "CONTROL_PLANE_FORBIDDEN"),
                ("rate_limited", "CONTROL_PLANE_RATE_LIMITED"),
                ("server_error", "CONTROL_PLANE_SERVER_ERROR"),
                ("other_http_error", "CONTROL_PLANE_HTTP_ERROR"),
            ] {
                let valid = baseline
                    .replace(
                        "\"controlPlane\":\"credential_rejected\"",
                        &format!("\"controlPlane\":\"{evidence}\""),
                    )
                    .replace("CONTROL_PLANE_CREDENTIAL_REJECTED", reason);
                assert!(
                    parse_overview(valid.as_bytes()).is_ok(),
                    "{evidence}: {reason}"
                );
            }
        }
    }

    #[test]
    fn an_unverified_control_plane_reason_requires_unknown_evidence() {
        for baseline in [GOOD.to_string(), linux_sample()] {
            let unknown = baseline
                .replace(
                    "\"controlPlane\":\"credential_rejected\"",
                    "\"controlPlane\":\"unverified\"",
                )
                .replace("\"state\":\"degraded\"", "\"state\":\"unverified\"")
                .replace(
                    "CONTROL_PLANE_CREDENTIAL_REJECTED",
                    "CONTROL_PLANE_UNVERIFIED",
                );
            assert!(parse_overview(unknown.as_bytes()).is_ok());
            let falsely_unverified = unknown.replace(
                "\"controlPlane\":\"unverified\"",
                "\"controlPlane\":\"none\"",
            );
            assert!(parse_overview(falsely_unverified.as_bytes()).is_err());
        }
    }

    #[test]
    fn local_operator_reasons_require_their_observed_evidence_on_both_platforms() {
        for (platform, baseline) in [("win32", GOOD.to_string()), ("linux", linux_sample())] {
            for (reason, state, health, initialize, tools, plane, mismatched_field, mismatched) in [
                (
                    "LOCAL_NOT_READY",
                    "degraded",
                    "not_ready",
                    "observed",
                    "observed_incomplete",
                    "none",
                    "localHealth",
                    "ready",
                ),
                (
                    "LOCAL_READINESS_UNVERIFIED",
                    "unverified",
                    "unverified",
                    "observed",
                    "observed_incomplete",
                    "none",
                    "localHealth",
                    "ready",
                ),
                (
                    "MCP_HANDSHAKE_UNOBSERVED",
                    "unverified",
                    "ready",
                    "not_observed",
                    "observed_incomplete",
                    "none",
                    "mcpInitialize",
                    "observed",
                ),
                (
                    "MCP_TOOLS_LIST_UNVERIFIED",
                    "unverified",
                    "ready",
                    "observed",
                    "observed_incomplete",
                    "none",
                    "toolDiscovery",
                    "observed_complete",
                ),
                (
                    "CONTROL_PLANE_UNVERIFIED",
                    "unverified",
                    "ready",
                    "observed",
                    "observed_incomplete",
                    "unverified",
                    "localHealth",
                    "not_ready",
                ),
            ] {
                let mut payload: serde_json::Value = serde_json::from_str(&baseline).unwrap();
                payload["localHealth"] = serde_json::Value::String(health.into());
                payload["mcpInitialize"] = serde_json::Value::String(initialize.into());
                payload["toolDiscovery"] = serde_json::Value::String(tools.into());
                payload["controlPlane"] = serde_json::Value::String(plane.into());
                payload["verdict"]["state"] = serde_json::Value::String(state.into());
                payload["verdict"]["reasonCode"] = serde_json::Value::String(reason.into());
                assert!(
                    parse_overview(&serde_json::to_vec(&payload).unwrap()).is_ok(),
                    "{platform} {reason}: consistent evidence must remain valid"
                );
                payload[mismatched_field] = serde_json::Value::String(mismatched.into());
                assert!(
                    parse_overview(&serde_json::to_vec(&payload).unwrap()).is_err(),
                    "{platform} {reason}: {mismatched_field}={mismatched} cannot retain the old reason"
                );
            }
        }
    }

    #[test]
    fn unavailable_reasons_require_consistent_local_observations() {
        for (platform, baseline) in [("win32", GOOD.to_string()), ("linux", linux_sample())] {
            let linux = platform == "linux";
            let registration = if linux {
                "serviceRegistration"
            } else {
                "taskRegistration"
            };
            let cases = [
                (
                    if linux {
                        "SERVICE_STATUS_UNAVAILABLE"
                    } else {
                        "TASK_STATUS_UNAVAILABLE"
                    },
                    "unverified",
                    "unverified",
                ),
                (
                    "LOCAL_DIAGNOSTICS_UNAVAILABLE",
                    "observed",
                    if linux { "unverified" } else { "ready" },
                ),
                ("LOCAL_EVIDENCE_CONFLICT", "observed", "unverified"),
            ];
            for (reason, reg, health) in cases {
                let mut observed: serde_json::Value = serde_json::from_str(&baseline).unwrap();
                for (field, value) in [
                    (registration, reg),
                    ("localHealth", health),
                    ("mcpInitialize", "unverified"),
                    ("toolDiscovery", "unverified"),
                    ("controlPlane", "unverified"),
                ] {
                    observed[field] = serde_json::Value::String(value.into());
                }
                observed["verdict"]["state"] = serde_json::Value::String("unverified".into());
                observed["verdict"]["reasonCode"] = serde_json::Value::String(reason.into());
                assert!(
                    parse_overview(&serde_json::to_vec(&observed).unwrap()).is_ok(),
                    "{platform} {reason}: matching producer evidence must remain valid"
                );
                if !linux && reason == "LOCAL_DIAGNOSTICS_UNAVAILABLE" {
                    let mut failed_health = observed.clone();
                    failed_health["localHealth"] = serde_json::Value::String("not_ready".into());
                    assert!(
                        parse_overview(&serde_json::to_vec(&failed_health).unwrap()).is_ok(),
                        "Windows diagnostics can be unavailable even when local health fails"
                    );
                }
                if linux && reason == "LOCAL_EVIDENCE_CONFLICT" {
                    let mut bad_service_status = observed.clone();
                    bad_service_status[registration] =
                        serde_json::Value::String("unverified".into());
                    assert!(
                        parse_overview(&serde_json::to_vec(&bad_service_status).unwrap()).is_ok(),
                        "Linux service-status evidence can conflict before registration is verified"
                    );
                }
                for (field, wrong) in [
                    ("mcpInitialize", "observed"),
                    ("toolDiscovery", "observed_incomplete"),
                    ("controlPlane", "none"),
                    ("verdict.state", "degraded"),
                ] {
                    let mut contradictory = observed.clone();
                    if field == "verdict.state" {
                        contradictory["verdict"]["state"] = serde_json::Value::String(wrong.into());
                    } else {
                        contradictory[field] = serde_json::Value::String(wrong.into());
                    }
                    assert!(
                        parse_overview(&serde_json::to_vec(&contradictory).unwrap()).is_err(),
                        "{platform} {reason}: {field}={wrong} must not be displayed"
                    );
                }
                if reason != "LOCAL_DIAGNOSTICS_UNAVAILABLE" || linux {
                    let mut contradictory = observed.clone();
                    contradictory["localHealth"] = serde_json::Value::String("not_ready".into());
                    assert!(
                        parse_overview(&serde_json::to_vec(&contradictory).unwrap()).is_err(),
                        "{platform} {reason}: failed local health contradicts unavailable evidence"
                    );
                }
                if !linux || reason != "LOCAL_EVIDENCE_CONFLICT" {
                    let mut contradictory = observed.clone();
                    contradictory[registration] = serde_json::Value::String(
                        if reg == "observed" {
                            "unverified"
                        } else {
                            "observed"
                        }
                        .into(),
                    );
                    assert!(
                        parse_overview(&serde_json::to_vec(&contradictory).unwrap()).is_err(),
                        "{platform} {reason}: unsupported registration state must be rejected"
                    );
                }
            }
        }
    }

    #[test]
    fn remote_unverified_reason_requires_actual_local_readiness_on_both_platforms() {
        for baseline in [GOOD.to_string(), linux_sample()] {
            let locally_ready = baseline
                .replace(
                    "\"toolDiscovery\":\"observed_incomplete\"",
                    "\"toolDiscovery\":\"observed_complete\"",
                )
                .replace(
                    "\"controlPlane\":\"credential_rejected\"",
                    "\"controlPlane\":\"none\"",
                )
                .replace("\"state\":\"degraded\"", "\"state\":\"unverified\"")
                .replace(
                    "CONTROL_PLANE_CREDENTIAL_REJECTED",
                    "REMOTE_ROUND_TRIP_UNVERIFIED",
                );
            assert!(
                parse_overview(locally_ready.as_bytes()).is_ok(),
                "verified local state with unknown remote delivery is allowed"
            );
            let registration_field = if baseline.contains("\"platform\":\"linux\"") {
                "serviceRegistration"
            } else {
                "taskRegistration"
            };
            for (field, contradictory) in [
                (registration_field, "unverified"),
                ("localHealth", "not_ready"),
                ("localHealth", "unverified"),
                ("mcpInitialize", "not_observed"),
                ("mcpInitialize", "unverified"),
                ("toolDiscovery", "observed_incomplete"),
                ("toolDiscovery", "unverified"),
                ("controlPlane", "unverified"),
            ] {
                let mut payload: serde_json::Value = serde_json::from_str(&locally_ready).unwrap();
                payload[field] = serde_json::Value::String(contradictory.into());
                let bytes = serde_json::to_vec(&payload).unwrap();
                assert!(
                    parse_overview(&bytes).is_err(),
                    "{field}={contradictory}: remote-only uncertainty cannot conceal a local fault"
                );
            }
            let mut false_severity: serde_json::Value =
                serde_json::from_str(&locally_ready).unwrap();
            false_severity["verdict"]["state"] = serde_json::Value::String("degraded".into());
            assert!(
                parse_overview(&serde_json::to_vec(&false_severity).unwrap()).is_err(),
                "a remote-only unverified reason cannot claim a degraded verdict"
            );
        }
    }

    #[test]
    fn unsupported_contract_version_fails_closed() {
        let stale = GOOD.replace("tunnel_operator_overview_v1", "tunnel_operator_overview_v9");
        assert!(parse_overview(stale.as_bytes()).is_err());
    }

    #[test]
    fn never_admit_a_fake_healthy_or_remote_success() {
        let fake = GOOD.replace("\"degraded\"", "\"healthy\"");
        assert!(parse_overview(fake.as_bytes()).is_err());
        let fake = GOOD.replace("\"not_observed\"", "\"observed_complete\"");
        assert!(parse_overview(fake.as_bytes()).is_err());
    }

    #[test]
    fn reject_secret_fields_and_unbounded_stdout() {
        let with_token = GOOD.replace("\"kind\"", "\"api_key\":\"PRIVATE\",\"kind\"");
        assert!(parse_overview(with_token.as_bytes()).is_err());
        assert!(parse_overview(&vec![b'x'; 16_385]).is_err());
    }

    #[test]
    fn malformed_schema_and_misleading_codes_fail_closed() {
        let invalid = GOOD.replace("CONTROL_PLANE_CREDENTIAL_REJECTED", "CREDENTIAL_EXPIRED");
        assert!(parse_overview(invalid.as_bytes()).is_err());
        let invalid = GOOD.replace("\"mcpInitialize\":\"observed\"", "\"mcpInitialize\":true");
        assert!(parse_overview(invalid.as_bytes()).is_err());
    }

    #[test]
    fn installation_smoke_is_explicit_and_never_accepts_backend_overrides() {
        use std::ffi::OsString;
        assert_eq!(startup_mode(&[]).unwrap(), StartupMode::Graphical);
        assert_eq!(
            startup_mode(&[OsString::from("--check-installation")]).unwrap(),
            StartupMode::CheckInstallation,
        );
        assert!(
            startup_mode(&[OsString::from("--backend-exe"), OsString::from("evil.exe")]).is_err()
        );
        assert!(
            startup_mode(&[
                OsString::from("--check-installation"),
                OsString::from("--force")
            ])
            .is_err()
        );
    }

    #[test]
    fn operator_interface_copy_uses_plain_punctuation() {
        for source in [include_str!("main.rs"), include_str!("../README.md")] {
            for unsupported in ['\u{2013}', '\u{2014}', '\u{00b7}'] {
                assert!(
                    !source.contains(unsupported),
                    "UI copy contains decorative punctuation: U+{:04X}",
                    unsupported as u32
                );
            }
        }
    }

    #[test]
    fn renderer_never_enumerates_known_crashing_windows_vulkan_driver() {
        let actual = native_wgpu_backends();
        #[cfg(windows)]
        {
            assert_eq!(actual, eframe::wgpu::Backends::DX12);
            assert!(!actual.contains(eframe::wgpu::Backends::VULKAN));
        }
        #[cfg(target_os = "linux")]
        {
            assert!(actual.contains(eframe::wgpu::Backends::VULKAN));
        }
    }

    #[test]
    fn stale_and_future_observations_are_not_fresh() {
        let now = OffsetDateTime::parse("2026-11-06T15:00:00Z", &Rfc3339).unwrap();
        assert!(observation_is_stale("2026-11-06T14:59:29Z", now));
        assert!(observation_is_stale("2026-11-06T15:00:06Z", now));
        assert!(observation_is_stale("not-a-date", now));
        assert!(!observation_is_stale("2026-11-06T14:59:50Z", now));
    }

    #[test]
    #[cfg(windows)]
    fn backend_is_only_the_sibling_pinned_runtime_not_a_path_search() {
        let root = std::path::Path::new("C:/Program Files/JDC/jdc-tunnel-operator-ui.exe");
        let layout = installed_layout(root).unwrap();
        assert_eq!(
            layout.node,
            std::path::PathBuf::from("C:/Program Files/JDC/runtime/node.exe")
        );
        assert_eq!(
            layout.entrypoint,
            std::path::PathBuf::from("C:/Program Files/JDC/dist/index.js")
        );
        assert_eq!(layout.arguments(), ["tunnel", "overview"]);
    }
}
