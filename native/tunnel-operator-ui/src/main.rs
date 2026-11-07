// A Windows GUI product must not show a companion console window.
// Interactive desktop acceptance uses the real registered user session.
#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;
use jdc_tunnel_operator_ui::backend::{BackendError, read_installed_overview};
use jdc_tunnel_operator_ui::{
    InstalledLayout, Overview, StartupMode, installed_layout, native_wgpu_backends,
    observation_is_stale, startup_mode,
};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Screen {
    Overview,
    Diagnose,
}

enum Presentation {
    Loading,
    Snapshot {
        value: Box<Overview>,
        received: Instant,
    },
    Failed(BackendError),
    NoInstallation,
}

// Status always reflects the current freshness of a read-only observation.
// A stale last-known result cannot be presented as a live tunnel verdict.
fn snapshot_stale(value: &Overview, received_age: Duration, now: OffsetDateTime) -> bool {
    received_age > Duration::from_secs(30) || observation_is_stale(&value.observed_at, now)
}

fn snapshot_status_label(
    value: &Overview,
    received_age: Duration,
    now: OffsetDateTime,
) -> &'static str {
    if snapshot_stale(value, received_age, now) {
        "STALE DATA"
    } else if value.verdict.state == "degraded" {
        "DEGRADED"
    } else {
        "UNVERIFIED"
    }
}

struct OperatorApp {
    layout: Option<InstalledLayout>,
    screen: Screen,
    presentation: Presentation,
    receiver: Option<Receiver<Result<Overview, BackendError>>>,
}

impl OperatorApp {
    fn new(ctx: &egui::Context) -> Self {
        ctx.set_visuals(egui::Visuals::dark());
        let layout = std::env::current_exe()
            .ok()
            .and_then(|path| installed_layout(&path).ok());
        let mut app = Self {
            layout,
            screen: Screen::Overview,
            presentation: Presentation::NoInstallation,
            receiver: None,
        };
        app.refresh(ctx);
        app
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        let Some(layout) = self.layout.clone() else {
            self.presentation = Presentation::NoInstallation;
            return;
        };
        if self.receiver.is_some() {
            return;
        }
        self.presentation = Presentation::Loading;
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = ctx.clone();
        std::thread::spawn(move || {
            let result = read_installed_overview(&layout);
            let _ = sender.send(result);
            context.request_repaint();
        });
        self.receiver = Some(receiver);
    }

    fn collect(&mut self) {
        let Some(receiver) = self.receiver.as_ref() else {
            return;
        };
        match receiver.try_recv() {
            Ok(Ok(value)) => {
                self.presentation = Presentation::Snapshot {
                    value: Box::new(value),
                    received: Instant::now(),
                };
                self.receiver = None;
            }
            Ok(Err(reason)) => {
                self.presentation = Presentation::Failed(reason);
                self.receiver = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.presentation = Presentation::Failed(BackendError::Failed);
                self.receiver = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
    fn show_navigation(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.heading("Tunnel Operator");
            ui.separator();
            ui.weak("Local - Read-only");
        });
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            if ui
                .selectable_label(self.screen == Screen::Overview, "Overview")
                .clicked()
            {
                self.screen = Screen::Overview;
            }
            if ui
                .selectable_label(self.screen == Screen::Diagnose, "Diagnostics")
                .clicked()
            {
                self.screen = Screen::Diagnose;
            }
            ui.separator();
            ui.add_enabled(false, egui::Button::new("Credentials"));
            ui.add_enabled(false, egui::Button::new("Service"));
            ui.separator();
            let pending = self.receiver.is_some();
            if ui
                .add_enabled(!pending, egui::Button::new("Refresh"))
                .clicked()
            {
                self.refresh(ctx);
            }
        });
        ui.add_space(12.0);
        ui.weak("Status is checked only when you select Refresh.");
        ui.separator();
    }

    fn show_snapshot(&self, ui: &mut egui::Ui, value: &Overview, received: Instant) {
        // Repaint only the local age/staleness presentation, never the child
        // backend. A network/diagnostic refresh still requires user action.
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        let age = received.elapsed();
        let status_label = snapshot_status_label(value, age, OffsetDateTime::now_utc());
        let stale = status_label == "STALE DATA";
        let verdict_color = if stale || value.verdict.state == "degraded" {
            egui::Color32::from_rgb(250, 180, 90)
        } else {
            egui::Color32::from_rgb(175, 195, 215)
        };
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Status").strong());
            ui.colored_label(verdict_color, status_label);
        });
        if stale {
            ui.label(format!("Last observed: {}", guidance(value.reason())));
        } else {
            ui.label(guidance(value.reason()));
        }
        ui.add_space(8.0);
        ui.small(format!("Checked: {}", value.observed_at));
        ui.small(format!("Age: {}s", age.as_secs()));
        if stale {
            ui.label(
                egui::RichText::new("Last observation is outdated. Refresh to verify.")
                    .color(egui::Color32::YELLOW),
            );
        }
        ui.add_space(15.0);

        egui::Grid::new("evidence_grid")
            .num_columns(2)
            .spacing([26.0, 13.0])
            .striped(true)
            .show(ui, |ui| {
                evidence_row(ui, value.registration_label(), &value.task_registration);
                evidence_row(ui, "Local health", &value.local_health);
                evidence_row(ui, "MCP handshake", &value.mcp_initialize);
                evidence_row(ui, "MCP tools", &value.tool_discovery);
                evidence_row(ui, "Control plane issue", &value.control_plane);
                evidence_row(ui, "Remote MCP delivery", &value.remote_delivery);
            });
        ui.add_space(16.0);
        if self.screen == Screen::Diagnose {
            ui.heading("Diagnostics");
            ui.monospace(format!("Reason: {}", value.reason()));

            ui.weak("Local readiness does not prove remote MCP access.");
            ui.weak("Sensitive details are hidden.");
        } else {
            ui.heading("Next step");
            ui.label("Open Diagnostics for details.");
            ui.weak("Service and credential controls are disabled.");
        }
    }
}
fn evidence_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.monospace(value);
    ui.end_row();
}

fn guidance(reason: &str) -> &'static str {
    match reason {
        "CONTROL_PLANE_CREDENTIAL_REJECTED" => "HTTP 401: credentials rejected. Expiry is unknown.",
        "CONTROL_PLANE_FORBIDDEN" => "HTTP 403: access denied. Check permissions.",
        "CONTROL_PLANE_RATE_LIMITED" => "HTTP 429: rate limited. Try again later.",
        "MCP_TOOLS_LIST_UNVERIFIED" => "MCP tools are incomplete. Remote access is unverified.",
        "MCP_HANDSHAKE_UNOBSERVED" => "MCP handshake not observed.",
        "TASK_STATUS_UNAVAILABLE" => "Tunnel task unavailable. Check installation.",
        "SERVICE_STATUS_UNAVAILABLE" => {
            "Tunnel service status unavailable. Check your user systemd service."
        }
        "SERVICE_INACTIVE" => "Tunnel service is inactive. No remote availability is verified.",
        "SERVICE_NOT_ENABLED" => "Tunnel service is not enabled for this user.",
        "LOCAL_DIAGNOSTICS_UNAVAILABLE" => "Local diagnostics unavailable. Check the client.",
        "LOCAL_EVIDENCE_CONFLICT" => "Local checks conflict. Status is unverified.",
        "REMOTE_ROUND_TRIP_UNVERIFIED" => "Local checks passed. Remote request not verified.",
        _ => "Status is incomplete. Review diagnostics.",
    }
}

impl eframe::App for OperatorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.collect();
        ui.add_space(14.0);
        let context = ui.ctx().clone();
        self.show_navigation(ui, &context);
        ui.add_space(6.0);
        match &self.presentation {
            Presentation::Loading => {
                ui.spinner();
                ui.label("Checking tunnel...");
            }
            Presentation::NoInstallation => {
                ui.label("Installation layout not found.");
            }
            Presentation::Failed(reason) => {
                ui.label(egui::RichText::new("STATUS UNAVAILABLE").color(egui::Color32::YELLOW));
                ui.label(reason.display());
                ui.weak("No changes were made.");
            }
            Presentation::Snapshot { value, received } => self.show_snapshot(ui, value, *received),
        }
        ui.add_space(22.0);
        ui.separator();
        ui.weak("Read-only - service controls unavailable.");
    }
}

fn main() -> eframe::Result {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match startup_mode(&args) {
        Ok(StartupMode::Graphical) => {}
        Ok(StartupMode::CheckInstallation) => {
            let result = std::env::current_exe()
                .map_err(|_| BackendError::UnsafeLayout)
                .and_then(|exe| installed_layout(&exe).map_err(|_| BackendError::UnsafeLayout))
                .and_then(|layout| read_installed_overview(&layout));
            match result {
                Ok(snapshot) => {
                    // All emitted values are allowlisted by parse_overview().
                    println!(
                        "state={} reason={} remote={}",
                        snapshot.verdict.state,
                        snapshot.reason(),
                        snapshot.remote_delivery
                    );
                    return Ok(());
                }
                Err(error) => {
                    eprintln!("{}", error.display());
                    std::process::exit(1);
                }
            }
        }
        Err(_) => {
            eprintln!("Unsupported operator launch options.");
            std::process::exit(2);
        }
    }
    let mut options = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        viewport: egui::ViewportBuilder::default()
            .with_title("JameDesktopCommander - Tunnel Operator")
            .with_inner_size([930.0, 640.0])
            .with_min_inner_size([650.0, 460.0]),
        ..Default::default()
    };
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(ref mut setup) = options.wgpu_options.wgpu_setup
    {
        setup.instance_descriptor.backends = native_wgpu_backends();
    }
    eframe::run_native(
        "JDC Local Operator",
        options,
        Box::new(|cc| Ok(Box::new(OperatorApp::new(&cc.egui_ctx)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn sample() -> Overview {
        jdc_tunnel_operator_ui::parse_overview(
            br#"{"kind":"tunnel_operator_overview_v1","platform":"win32","capabilities":"read_only","observedAt":"2026-11-06T15:00:00Z","taskRegistration":"observed","localHealth":"not_ready","mcpInitialize":"not_observed","toolDiscovery":"unverified","controlPlane":"unverified","remoteDelivery":"not_observed","verdict":{"state":"degraded","reasonCode":"LOCAL_NOT_READY"}}"#,
        )
        .expect("valid read-only fixture")
    }

    #[test]
    fn stale_snapshot_is_not_presented_as_current_health() {
        let value = sample();
        let recent = OffsetDateTime::parse(
            "2026-11-06T15:00:10Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(!snapshot_stale(&value, Duration::from_secs(10), recent));
        assert!(snapshot_stale(&value, Duration::from_secs(31), recent));
        let old = OffsetDateTime::parse(
            "2026-11-06T15:00:31Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(snapshot_stale(&value, Duration::ZERO, old));
        assert_eq!(
            snapshot_status_label(&value, Duration::from_secs(31), recent),
            "STALE DATA"
        );
    }

    #[test]
    fn diagnostics_do_not_report_401_without_credential_rejection_evidence() {
        assert!(guidance("SERVICE_INACTIVE").contains("inactive"));
        assert!(!guidance("SERVICE_INACTIVE").contains("401"));
        assert!(guidance("CONTROL_PLANE_CREDENTIAL_REJECTED").contains("401"));
        assert!(guidance("CONTROL_PLANE_FORBIDDEN").contains("403"));
        assert!(guidance("CONTROL_PLANE_RATE_LIMITED").contains("429"));
    }

    #[test]
    fn visible_snapshot_requests_periodic_repaint_without_polling_backend() {
        let app = OperatorApp {
            layout: None,
            screen: Screen::Overview,
            presentation: Presentation::NoInstallation,
            receiver: None,
        };
        let ctx = egui::Context::default();
        let requested = Arc::new(Mutex::new(Vec::<Duration>::new()));
        ctx.set_repaint_observer({
            let requested = requested.clone();
            move |info| requested.lock().unwrap().push(info.delay)
        });
        let value = sample();
        let output = ctx.run_ui(Default::default(), |ui| {
            app.show_snapshot(ui, &value, Instant::now());
        });
        output.drop_without_applying_deltas();
        assert!(
            requested.lock().unwrap().iter().any(|delay| {
                *delay >= Duration::from_millis(900) && *delay <= Duration::from_secs(1)
            }),
            "the visible observation must refresh age/staleness each second"
        );
        assert!(app.receiver.is_none(), "repaint must not poll the backend");
    }
}
