use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shim -> Server: initiate an AlwaysOnline session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub license_id: Uuid,
    pub binding_id: Uuid,
    /// Fresh fingerprint commitment for this launch.
    pub fingerprint_commitment: Vec<u8>,
    /// Ephemeral X25519 public key; fresh per launch, never reused.
    pub ephemeral_pubkey: Vec<u8>,
    pub shim_version: String,
    pub client_version: String,
    pub protocol_version: u32,
}

/// Server -> Shim: session established successfully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: Uuid,
    /// Per-session key material encrypted to the shim's `ephemeral_pubkey` (X25519 ECDH + AEAD).
    pub session_material: Vec<u8>,
    /// Starting sequence number; always 0.
    pub seq_no: u64,
    /// Initial rolling token; shim must include this in the first `Heartbeat`.
    #[serde(with = "serde_bytes")]
    pub session_token: [u8; 32],
    /// UTC Unix seconds; server will reject heartbeats after this.
    pub expires_at: i64,
    pub heartbeat_interval_secs: u32,
    pub heartbeat_grace_secs: u32,
    /// Seconds the shim waits after a quarantine before SIGTERM/SIGKILL.
    pub shutdown_countdown_secs: u32,
}

/// Shim -> Server: periodic keep-alive with auth proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub session_id: Uuid,
    /// Incremented by 1 each heartbeat; server detects gaps.
    pub seq_no: u64,
    /// Rolling token from the previous `HeartbeatAck`, or from `SessionResponse`.
    #[serde(with = "serde_bytes")]
    pub session_token: [u8; 32],
    /// Fresh commitment proving hardware hasn't changed.
    pub fingerprint_commitment: Vec<u8>,
    /// HMAC-SHA256(session_id || seq_no_le || session_token || fingerprint_commitment, session_hmac_key).
    #[serde(with = "serde_bytes")]
    pub hmac: [u8; 32],
}

/// Server -> Shim: response to a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAck {
    /// Echoed back from the `Heartbeat`.
    pub seq_no: u64,
    pub status: HeartbeatStatus,
    /// Fresh rolling token; shim must include this in the next `Heartbeat`.
    #[serde(with = "serde_bytes")]
    pub new_session_token: [u8; 32],
}

/// Status carried in a `HeartbeatAck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HeartbeatStatus {
    Continue,
    Warn {
        message: String,
    },
    Quarantine {
        case_id: Uuid,
        #[serde(with = "serde_bytes")]
        vendor_sig: [u8; 64],
    },
    Terminate {
        case_id: Uuid,
        #[serde(with = "serde_bytes")]
        vendor_sig: [u8; 64],
    },
    Resume,
}

/// Shim -> Server: tamper or anomaly detection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventReport {
    /// Shim-generated UUID; used for idempotency.
    pub event_id: Uuid,
    pub license_id: Uuid,
    pub binding_id: Uuid,
    pub session_id: Option<Uuid>,
    /// When the shim detected the event (may be old if shim was offline).
    pub occurred_at_ns: i64,
    /// When this HTTP request was sent; used for replay protection.
    pub sent_at_ns: i64,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
}

/// All security event variants the shim can report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum SecurityEventType {
    PtraceAttempted {
        from_pid: u32,
    },
    DebuggerDetected {
        method: String,
    },
    UnexpectedParentProcess {
        parent_pid: u32,
        parent_name: String,
    },
    MemoryMappingAnomaly {
        region: String,
        flags: String,
    },
    VmDetected {
        hypervisor_signature: String,
    },
    SuspiciousEnvironmentVar {
        key: String,
    },
    FingerprintDrift {
        delta_score: f32,
        threshold: f32,
    },
    FingerprintExceededThreshold {
        delta_score: f32,
    },
    HeartbeatSequenceGap {
        expected: u64,
        received: u64,
    },
    MultipleSessionsDetected,
    UnexpectedChildFork,
    AbnormalExitSignal {
        signal: i32,
    },
}

/// Severity level attached to a security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Critical,
}

impl SecurityEventType {
    /// Default severity for each event type per spec.
    pub fn default_severity(&self) -> SecuritySeverity {
        match self {
            Self::DebuggerDetected { .. }
            | Self::VmDetected { .. }
            | Self::FingerprintExceededThreshold { .. }
            | Self::MultipleSessionsDetected => SecuritySeverity::Critical,
            Self::PtraceAttempted { .. }
            | Self::UnexpectedParentProcess { .. }
            | Self::MemoryMappingAnomaly { .. }
            | Self::FingerprintDrift { .. }
            | Self::HeartbeatSequenceGap { .. } => SecuritySeverity::Warning,
            Self::SuspiciousEnvironmentVar { .. }
            | Self::UnexpectedChildFork
            | Self::AbnormalExitSignal { .. } => SecuritySeverity::Info,
        }
    }
}

/// Server -> Shim: response to a `SecurityEventReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecurityResponse {
    Log,
    Warn {
        message_to_show_user: String,
    },
    /// `shutdown_countdown_secs`: how long the shim waits before SIGTERM/SIGKILL.
    Quarantine {
        reason: String,
        case_id: Uuid,
        shutdown_countdown_secs: u32,
        #[serde(with = "serde_bytes")]
        vendor_sig: [u8; 64],
    },
    Terminate {
        reason: String,
        case_id: Uuid,
        #[serde(with = "serde_bytes")]
        vendor_sig: [u8; 64],
    },
}
