//! The typed Crash Capsule object model and its canonical CBOR mapping.

use cc_canonical::Value;
use cc_schema::keys;

/// Failing component identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    /// 0 kernel, 1 kernel-module, 2 package, 3 application, 4 service.
    pub kind: u64,
    /// Package namespace or name.
    pub package: Option<String>,
    /// Package version.
    pub version: Option<String>,
    /// ELF build ID of the failing object.
    pub build_id: Option<Vec<u8>>,
    /// Executable basename; never a path.
    pub executable: Option<String>,
    /// Kernel module name.
    pub module: Option<String>,
    /// Subsystem label used for routing.
    pub subsystem: Option<String>,
}

/// Coarse hardware summary. Serials and persistent device identity are never represented here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hardware {
    /// CPU vendor and family.
    pub cpu_family: Option<String>,
    /// GPU model family.
    pub gpu_class: Option<String>,
    /// Diagnostic PCI `vendor:device` identifiers.
    pub pci_ids: Vec<String>,
    /// Firmware version, where diagnostically relevant.
    pub firmware_version: Option<String>,
}

/// System identity summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct System {
    /// Machine architecture.
    pub architecture: String,
    /// Distribution family.
    pub distro_family: Option<String>,
    /// Distribution release.
    pub distro_release: Option<String>,
    /// Kernel release string.
    pub kernel_release: Option<String>,
    /// Kernel build ID.
    pub kernel_build_id: Option<Vec<u8>>,
    /// Kernel taint mask.
    pub taint: Option<u64>,
    /// Coarse hardware summary.
    pub hardware: Option<Hardware>,
}

/// The failure event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// Failure class identifier.
    pub failure_class: u64,
    /// Signal number or exit status.
    pub signal: Option<i64>,
    /// Enumerated reason string; never free-form log text.
    pub reason: Option<String>,
    /// Occurrence-local sequence number.
    pub sequence: Option<u64>,
}

/// A normalised stack frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    /// Build ID of the object owning the frame.
    pub build_id: Option<Vec<u8>>,
    /// Normalised symbol name.
    pub symbol: Option<String>,
    /// Module-relative offset; absolute addresses are prohibited.
    pub offset: Option<u64>,
    /// Module or object identity.
    pub module: Option<String>,
}

impl Frame {
    /// Converts to the fingerprint crate's frame representation.
    #[must_use]
    pub fn to_fingerprint_frame(&self) -> cc_fingerprint::Frame {
        cc_fingerprint::Frame {
            build_id: self.build_id.clone(),
            module: self.module.clone(),
            symbol: self.symbol.clone(),
            offset: self.offset,
        }
    }
}

/// One priority-ordered piece of evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Evidence kind identifier.
    pub kind: u64,
    /// Producer-declared privacy class; the effective class is the maximum of this and the
    /// registry floor for the kind.
    pub declared_class: u8,
    /// Diagnostic priority; lower values are dropped first by the profile budget.
    pub priority: u64,
    /// Payload, interpreted according to `kind`.
    pub value: Value,
    /// Hash of the source content this evidence was derived from.
    pub source_hash: Option<Vec<u8>>,
}

impl Evidence {
    /// Effective privacy class: `max(registry floor for the kind, producer declaration)`.
    #[must_use]
    pub fn effective_class(&self) -> cc_schema::PrivacyClass {
        let floor =
            cc_schema::evidence_kind_floor(self.kind).unwrap_or(cc_schema::PrivacyClass::P4);
        let declared = cc_schema::PrivacyClass::from_id(self.declared_class)
            .unwrap_or(cc_schema::PrivacyClass::P4);
        cc_schema::PrivacyClass::effective(floor, declared)
    }
}

/// Strict and family fingerprints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprints {
    /// Strict fingerprint.
    pub strict: [u8; 32],
    /// Family fingerprint.
    pub family: [u8; 32],
    /// Optional hash binding the evidence array to the capsule.
    pub evidence: Option<[u8; 32]>,
}

/// What the producer included, excluded and redacted; drives the user-facing preview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivacyManifest {
    /// Highest effective class present in the capsule.
    pub max_class: u8,
    /// Category identifiers included.
    pub included: Vec<u64>,
    /// Category identifiers deliberately excluded.
    pub excluded: Vec<u64>,
    /// Number of values the redactor removed or tokenised.
    pub redactions: u64,
    /// Number of evidence items dropped by the profile budget.
    pub dropped_evidence: u64,
}

/// Coarse timing information; deliberately never a precise timestamp.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeInfo {
    /// Coarse uptime bucket.
    pub uptime_bucket: Option<u64>,
    /// Days since the Unix epoch.
    pub day: Option<u64>,
}

/// Producer suggestions for triage routing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingHints {
    /// Suggested subsystem.
    pub subsystem: Option<String>,
    /// Suggested upstream project identifier.
    pub project: Option<String>,
}

/// A complete Crash Capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    /// Incompatible schema generation.
    pub schema_major: u64,
    /// Additive schema revision.
    pub schema_minor: u64,
    /// Profile identifier.
    pub profile: u64,
    /// Random per-incident identifier.
    pub capsule_id: [u8; 16],
    /// Producer source kind.
    pub source_kind: u64,
    /// Producer-assigned severity.
    pub severity: u64,
    /// Failing component.
    pub component: Component,
    /// System summary.
    pub system: System,
    /// The failure event.
    pub event: Event,
    /// Stack frames, most recent first.
    pub frames: Vec<Frame>,
    /// Priority-ordered evidence.
    pub evidence: Vec<Evidence>,
    /// Fingerprints.
    pub fingerprints: Fingerprints,
    /// Privacy manifest.
    pub privacy: PrivacyManifest,
    /// Critical feature bitmap; readers fail closed on unknown bits.
    pub critical_features: u64,
    /// Coarse timing information.
    pub time_info: Option<TimeInfo>,
    /// Routing hints.
    pub routing_hints: Option<RoutingHints>,
}

impl Default for Capsule {
    fn default() -> Self {
        Self {
            schema_major: cc_schema::SCHEMA_MAJOR,
            schema_minor: cc_schema::SCHEMA_MINOR,
            profile: 2,
            capsule_id: [0; 16],
            source_kind: 0,
            severity: 0,
            component: Component::default(),
            system: System::default(),
            event: Event::default(),
            frames: Vec::new(),
            evidence: Vec::new(),
            fingerprints: Fingerprints::default(),
            privacy: PrivacyManifest::default(),
            critical_features: 0,
            time_info: None,
            routing_hints: None,
        }
    }
}

fn opt_text(entries: &mut Vec<(Value, Value)>, key: u64, value: &Option<String>) {
    if let Some(v) = value {
        entries.push((Value::Unsigned(key), Value::text(v.clone())));
    }
}

fn opt_bytes(entries: &mut Vec<(Value, Value)>, key: u64, value: &Option<Vec<u8>>) {
    if let Some(v) = value {
        entries.push((Value::Unsigned(key), Value::bytes(v.clone())));
    }
}

fn opt_uint(entries: &mut Vec<(Value, Value)>, key: u64, value: Option<u64>) {
    if let Some(v) = value {
        entries.push((Value::Unsigned(key), Value::Unsigned(v)));
    }
}

impl Component {
    fn to_value(&self) -> Value {
        let mut entries = vec![(
            Value::Unsigned(keys::component::KIND),
            Value::Unsigned(self.kind),
        )];
        opt_text(&mut entries, keys::component::PACKAGE, &self.package);
        opt_text(&mut entries, keys::component::VERSION, &self.version);
        opt_bytes(&mut entries, keys::component::BUILD_ID, &self.build_id);
        opt_text(&mut entries, keys::component::EXECUTABLE, &self.executable);
        opt_text(&mut entries, keys::component::MODULE, &self.module);
        opt_text(&mut entries, keys::component::SUBSYSTEM, &self.subsystem);
        Value::Map(entries)
    }
}

impl Hardware {
    fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        opt_text(&mut entries, keys::hardware::CPU_FAMILY, &self.cpu_family);
        opt_text(&mut entries, keys::hardware::GPU_CLASS, &self.gpu_class);
        if !self.pci_ids.is_empty() {
            entries.push((
                Value::Unsigned(keys::hardware::PCI_IDS),
                Value::Array(self.pci_ids.iter().map(Value::text).collect()),
            ));
        }
        opt_text(
            &mut entries,
            keys::hardware::FIRMWARE_VERSION,
            &self.firmware_version,
        );
        Value::Map(entries)
    }
}

impl System {
    fn to_value(&self) -> Value {
        let mut entries = vec![(
            Value::Unsigned(keys::system::ARCHITECTURE),
            Value::text(self.architecture.clone()),
        )];
        opt_text(
            &mut entries,
            keys::system::DISTRO_FAMILY,
            &self.distro_family,
        );
        opt_text(
            &mut entries,
            keys::system::DISTRO_RELEASE,
            &self.distro_release,
        );
        opt_text(
            &mut entries,
            keys::system::KERNEL_RELEASE,
            &self.kernel_release,
        );
        opt_bytes(
            &mut entries,
            keys::system::KERNEL_BUILD_ID,
            &self.kernel_build_id,
        );
        opt_uint(&mut entries, keys::system::TAINT, self.taint);
        if let Some(hardware) = &self.hardware {
            entries.push((Value::Unsigned(keys::system::HARDWARE), hardware.to_value()));
        }
        Value::Map(entries)
    }
}

impl Event {
    fn to_value(&self) -> Value {
        let mut entries = vec![(
            Value::Unsigned(keys::event::FAILURE_CLASS),
            Value::Unsigned(self.failure_class),
        )];
        if let Some(signal) = self.signal {
            entries.push((Value::Unsigned(keys::event::SIGNAL), Value::int(signal)));
        }
        opt_text(&mut entries, keys::event::REASON, &self.reason);
        opt_uint(&mut entries, keys::event::SEQUENCE, self.sequence);
        Value::Map(entries)
    }
}

impl Frame {
    fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        opt_bytes(&mut entries, keys::frame::BUILD_ID, &self.build_id);
        opt_text(&mut entries, keys::frame::SYMBOL, &self.symbol);
        opt_uint(&mut entries, keys::frame::OFFSET, self.offset);
        opt_text(&mut entries, keys::frame::MODULE, &self.module);
        Value::Map(entries)
    }
}

impl Evidence {
    fn to_value(&self) -> Value {
        let mut entries = vec![
            (
                Value::Unsigned(keys::evidence::KIND),
                Value::Unsigned(self.kind),
            ),
            (
                Value::Unsigned(keys::evidence::CLASS),
                Value::Unsigned(u64::from(self.effective_class().id())),
            ),
            (
                Value::Unsigned(keys::evidence::PRIORITY),
                Value::Unsigned(self.priority),
            ),
            (Value::Unsigned(keys::evidence::VALUE), self.value.clone()),
        ];
        opt_bytes(&mut entries, keys::evidence::SOURCE_HASH, &self.source_hash);
        Value::Map(entries)
    }
}

impl Fingerprints {
    fn to_value(&self) -> Value {
        let mut entries = vec![
            (
                Value::Unsigned(keys::fingerprints::STRICT),
                Value::bytes(self.strict.to_vec()),
            ),
            (
                Value::Unsigned(keys::fingerprints::FAMILY),
                Value::bytes(self.family.to_vec()),
            ),
        ];
        if let Some(evidence) = self.evidence {
            entries.push((
                Value::Unsigned(keys::fingerprints::EVIDENCE),
                Value::bytes(evidence.to_vec()),
            ));
        }
        Value::Map(entries)
    }
}

impl PrivacyManifest {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Unsigned(keys::privacy_manifest::MAX_CLASS),
                Value::Unsigned(u64::from(self.max_class)),
            ),
            (
                Value::Unsigned(keys::privacy_manifest::INCLUDED),
                Value::Array(self.included.iter().copied().map(Value::Unsigned).collect()),
            ),
            (
                Value::Unsigned(keys::privacy_manifest::EXCLUDED),
                Value::Array(self.excluded.iter().copied().map(Value::Unsigned).collect()),
            ),
            (
                Value::Unsigned(keys::privacy_manifest::REDACTIONS),
                Value::Unsigned(self.redactions),
            ),
            (
                Value::Unsigned(keys::privacy_manifest::DROPPED_EVIDENCE),
                Value::Unsigned(self.dropped_evidence),
            ),
        ])
    }
}

impl TimeInfo {
    fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        opt_uint(
            &mut entries,
            keys::time_info::UPTIME_BUCKET,
            self.uptime_bucket,
        );
        opt_uint(&mut entries, keys::time_info::DAY, self.day);
        Value::Map(entries)
    }
}

impl RoutingHints {
    fn to_value(&self) -> Value {
        let mut entries = Vec::new();
        opt_text(
            &mut entries,
            keys::routing_hints::SUBSYSTEM,
            &self.subsystem,
        );
        opt_text(&mut entries, keys::routing_hints::PROJECT, &self.project);
        Value::Map(entries)
    }
}

impl Capsule {
    /// Maps the capsule onto the CBOR data model. Encoding the result with
    /// [`cc_canonical::encode`] yields the canonical wire bytes.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (
                Value::Unsigned(keys::capsule::SCHEMA_MAJOR),
                Value::Unsigned(self.schema_major),
            ),
            (
                Value::Unsigned(keys::capsule::SCHEMA_MINOR),
                Value::Unsigned(self.schema_minor),
            ),
            (
                Value::Unsigned(keys::capsule::PROFILE),
                Value::Unsigned(self.profile),
            ),
            (
                Value::Unsigned(keys::capsule::CAPSULE_ID),
                Value::bytes(self.capsule_id.to_vec()),
            ),
            (
                Value::Unsigned(keys::capsule::SOURCE_KIND),
                Value::Unsigned(self.source_kind),
            ),
            (
                Value::Unsigned(keys::capsule::SEVERITY),
                Value::Unsigned(self.severity),
            ),
            (
                Value::Unsigned(keys::capsule::COMPONENT),
                self.component.to_value(),
            ),
            (
                Value::Unsigned(keys::capsule::SYSTEM),
                self.system.to_value(),
            ),
            (Value::Unsigned(keys::capsule::EVENT), self.event.to_value()),
            (
                Value::Unsigned(keys::capsule::FRAMES),
                Value::Array(self.frames.iter().map(Frame::to_value).collect()),
            ),
            (
                Value::Unsigned(keys::capsule::EVIDENCE),
                Value::Array(self.evidence.iter().map(Evidence::to_value).collect()),
            ),
            (
                Value::Unsigned(keys::capsule::FINGERPRINTS),
                self.fingerprints.to_value(),
            ),
            (
                Value::Unsigned(keys::capsule::PRIVACY_MANIFEST),
                self.privacy.to_value(),
            ),
            (
                Value::Unsigned(keys::capsule::CRITICAL_FEATURES),
                Value::Unsigned(self.critical_features),
            ),
        ];
        if let Some(time_info) = &self.time_info {
            entries.push((
                Value::Unsigned(keys::capsule::TIME_INFO),
                time_info.to_value(),
            ));
        }
        if let Some(routing) = &self.routing_hints {
            entries.push((
                Value::Unsigned(keys::capsule::ROUTING_HINTS),
                routing.to_value(),
            ));
        }
        Value::Map(entries)
    }

    /// Encodes the capsule as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        cc_canonical::encode(&self.to_value())
    }
}
