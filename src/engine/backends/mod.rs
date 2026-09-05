// src/engine/backends/mod.rs — Hybrid External Backend Orchestrator
// Coordinates external recovery tools (Hashcat, John the Ripper, *2john)
// when installed, capturing real execution stdout/stderr and streaming live telemetry.

pub mod detector;
pub mod orchestrator;

pub use detector::{BackendCatalog, BackendSelection, BackendType, ExternalTool};
pub use orchestrator::{BackendJob, BackendStatus, BackendTelemetry};
