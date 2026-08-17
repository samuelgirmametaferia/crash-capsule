//! Parsing a canonical CBOR value back into the typed model.

use cc_canonical::Value;
use cc_schema::keys;

use crate::model::{
    Capsule, Component, Event, Evidence, Fingerprints, Frame, Hardware, PrivacyManifest,
    RoutingHints, System, TimeInfo,
};
use crate::{Error, Result};

fn map<'a>(value: &'a Value, field: &'static str) -> Result<&'a Value> {
    if value.as_map().is_some() {
        Ok(value)
    } else {
        Err(Error::WrongType { field })
    }
}

fn required<'a>(value: &'a Value, key: u64, field: &'static str) -> Result<&'a Value> {
    value.get(key).ok_or(Error::MissingField { field })
}

fn uint(value: &Value, key: u64, field: &'static str) -> Result<u64> {
    required(value, key, field)?
        .as_unsigned()
        .ok_or(Error::WrongType { field })
}

fn opt_uint(value: &Value, key: u64) -> Option<u64> {
    value.get(key).and_then(Value::as_unsigned)
}

fn opt_int(value: &Value, key: u64) -> Option<i64> {
    value.get(key).and_then(Value::as_int)
}

fn text(value: &Value, key: u64, field: &'static str) -> Result<String> {
    required(value, key, field)?
        .as_text()
        .map(str::to_owned)
        .ok_or(Error::WrongType { field })
}

fn opt_text(value: &Value, key: u64) -> Option<String> {
    value.get(key).and_then(Value::as_text).map(str::to_owned)
}

fn opt_bytes(value: &Value, key: u64) -> Option<Vec<u8>> {
    value.get(key).and_then(Value::as_bytes).map(<[u8]>::to_vec)
}

fn fixed<const N: usize>(value: &Value, key: u64, field: &'static str) -> Result<[u8; N]> {
    let bytes = required(value, key, field)?
        .as_bytes()
        .ok_or(Error::WrongType { field })?;
    <[u8; N]>::try_from(bytes).map_err(|_| Error::WrongType { field })
}

fn uints(value: &Value, key: u64, field: &'static str) -> Result<Vec<u64>> {
    required(value, key, field)?
        .as_array()
        .ok_or(Error::WrongType { field })?
        .iter()
        .map(|v| v.as_unsigned().ok_or(Error::WrongType { field }))
        .collect()
}

impl Capsule {
    /// Decodes canonical CBOR bytes into a capsule.
    ///
    /// Structural limits are applied by [`cc_canonical::decode`]; semantic validation is a
    /// separate step, so a caller can inspect a capsule that it will ultimately reject.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::from_value(&cc_canonical::decode(bytes)?)
    }

    /// Builds a capsule from an already-decoded CBOR value.
    pub fn from_value(value: &Value) -> Result<Self> {
        let root = map(value, "capsule")?;

        let component_value = required(root, keys::capsule::COMPONENT, "capsule.component")?;
        let system_value = required(root, keys::capsule::SYSTEM, "capsule.system")?;
        let event_value = required(root, keys::capsule::EVENT, "capsule.event")?;
        let fingerprints_value =
            required(root, keys::capsule::FINGERPRINTS, "capsule.fingerprints")?;
        let privacy_value = required(
            root,
            keys::capsule::PRIVACY_MANIFEST,
            "capsule.privacy_manifest",
        )?;

        Ok(Self {
            schema_major: uint(root, keys::capsule::SCHEMA_MAJOR, "capsule.schema_major")?,
            schema_minor: uint(root, keys::capsule::SCHEMA_MINOR, "capsule.schema_minor")?,
            profile: uint(root, keys::capsule::PROFILE, "capsule.profile")?,
            capsule_id: fixed::<16>(root, keys::capsule::CAPSULE_ID, "capsule.capsule_id")?,
            source_kind: uint(root, keys::capsule::SOURCE_KIND, "capsule.source_kind")?,
            severity: uint(root, keys::capsule::SEVERITY, "capsule.severity")?,
            component: component(component_value)?,
            system: system(system_value)?,
            event: event(event_value)?,
            frames: required(root, keys::capsule::FRAMES, "capsule.frames")?
                .as_array()
                .ok_or(Error::WrongType {
                    field: "capsule.frames",
                })?
                .iter()
                .map(frame)
                .collect::<Result<Vec<_>>>()?,
            evidence: required(root, keys::capsule::EVIDENCE, "capsule.evidence")?
                .as_array()
                .ok_or(Error::WrongType {
                    field: "capsule.evidence",
                })?
                .iter()
                .map(evidence)
                .collect::<Result<Vec<_>>>()?,
            fingerprints: fingerprints(fingerprints_value)?,
            privacy: privacy(privacy_value)?,
            critical_features: uint(
                root,
                keys::capsule::CRITICAL_FEATURES,
                "capsule.critical_features",
            )?,
            time_info: root.get(keys::capsule::TIME_INFO).map(|v| TimeInfo {
                uptime_bucket: opt_uint(v, keys::time_info::UPTIME_BUCKET),
                day: opt_uint(v, keys::time_info::DAY),
            }),
            routing_hints: root
                .get(keys::capsule::ROUTING_HINTS)
                .map(|v| RoutingHints {
                    subsystem: opt_text(v, keys::routing_hints::SUBSYSTEM),
                    project: opt_text(v, keys::routing_hints::PROJECT),
                }),
        })
    }
}

fn component(value: &Value) -> Result<Component> {
    let value = map(value, "capsule.component")?;
    Ok(Component {
        kind: uint(value, keys::component::KIND, "component.kind")?,
        package: opt_text(value, keys::component::PACKAGE),
        version: opt_text(value, keys::component::VERSION),
        build_id: opt_bytes(value, keys::component::BUILD_ID),
        executable: opt_text(value, keys::component::EXECUTABLE),
        module: opt_text(value, keys::component::MODULE),
        subsystem: opt_text(value, keys::component::SUBSYSTEM),
    })
}

fn system(value: &Value) -> Result<System> {
    let value = map(value, "capsule.system")?;
    Ok(System {
        architecture: text(value, keys::system::ARCHITECTURE, "system.architecture")?,
        distro_family: opt_text(value, keys::system::DISTRO_FAMILY),
        distro_release: opt_text(value, keys::system::DISTRO_RELEASE),
        kernel_release: opt_text(value, keys::system::KERNEL_RELEASE),
        kernel_build_id: opt_bytes(value, keys::system::KERNEL_BUILD_ID),
        taint: opt_uint(value, keys::system::TAINT),
        hardware: value.get(keys::system::HARDWARE).map(|hw| Hardware {
            cpu_family: opt_text(hw, keys::hardware::CPU_FAMILY),
            gpu_class: opt_text(hw, keys::hardware::GPU_CLASS),
            pci_ids: hw
                .get(keys::hardware::PCI_IDS)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_text)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            firmware_version: opt_text(hw, keys::hardware::FIRMWARE_VERSION),
        }),
    })
}

fn event(value: &Value) -> Result<Event> {
    let value = map(value, "capsule.event")?;
    Ok(Event {
        failure_class: uint(value, keys::event::FAILURE_CLASS, "event.failure_class")?,
        signal: opt_int(value, keys::event::SIGNAL),
        reason: opt_text(value, keys::event::REASON),
        sequence: opt_uint(value, keys::event::SEQUENCE),
    })
}

fn frame(value: &Value) -> Result<Frame> {
    let value = map(value, "capsule.frames")?;
    Ok(Frame {
        build_id: opt_bytes(value, keys::frame::BUILD_ID),
        symbol: opt_text(value, keys::frame::SYMBOL),
        offset: opt_uint(value, keys::frame::OFFSET),
        module: opt_text(value, keys::frame::MODULE),
    })
}

fn evidence(value: &Value) -> Result<Evidence> {
    let value = map(value, "capsule.evidence")?;
    let class = uint(value, keys::evidence::CLASS, "evidence.class")?;
    Ok(Evidence {
        kind: uint(value, keys::evidence::KIND, "evidence.kind")?,
        declared_class: u8::try_from(class).map_err(|_| Error::WrongType {
            field: "evidence.class",
        })?,
        priority: uint(value, keys::evidence::PRIORITY, "evidence.priority")?,
        value: required(value, keys::evidence::VALUE, "evidence.value")?.clone(),
        source_hash: opt_bytes(value, keys::evidence::SOURCE_HASH),
    })
}

fn fingerprints(value: &Value) -> Result<Fingerprints> {
    let value = map(value, "capsule.fingerprints")?;
    Ok(Fingerprints {
        strict: fixed::<32>(value, keys::fingerprints::STRICT, "fingerprints.strict")?,
        family: fixed::<32>(value, keys::fingerprints::FAMILY, "fingerprints.family")?,
        evidence: value
            .get(keys::fingerprints::EVIDENCE)
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 32]>::try_from(b).ok()),
    })
}

fn privacy(value: &Value) -> Result<PrivacyManifest> {
    let value = map(value, "capsule.privacy_manifest")?;
    let max_class = uint(
        value,
        keys::privacy_manifest::MAX_CLASS,
        "privacy_manifest.max_class",
    )?;
    Ok(PrivacyManifest {
        max_class: u8::try_from(max_class).map_err(|_| Error::WrongType {
            field: "privacy_manifest.max_class",
        })?,
        included: uints(
            value,
            keys::privacy_manifest::INCLUDED,
            "privacy_manifest.included",
        )?,
        excluded: uints(
            value,
            keys::privacy_manifest::EXCLUDED,
            "privacy_manifest.excluded",
        )?,
        redactions: uint(
            value,
            keys::privacy_manifest::REDACTIONS,
            "privacy_manifest.redactions",
        )?,
        dropped_evidence: uint(
            value,
            keys::privacy_manifest::DROPPED_EVIDENCE,
            "privacy_manifest.dropped_evidence",
        )?,
    })
}
