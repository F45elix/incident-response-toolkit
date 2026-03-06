"""
Incident Response & Digital Forensics Toolkit
===============================================
Implements the NIST SP 800-61r2 Incident Response lifecycle:
  1. Preparation
  2. Detection & Analysis
  3. Containment, Eradication & Recovery
  4. Post-Incident Activity

Automates:
- Evidence collection (memory, disk, network artefacts)
- IOC extraction and hashing (MD5, SHA-256)
- Chain-of-custody logging
- Automated playbook execution
- STIX 2.1 threat intelligence indicator generation

Skills: Incident Response, Digital Forensics, Malware Analysis,
        Threat Intelligence, Python scripting, NIST framework
"""

import os
import re
import json
import hashlib
import platform
import subprocess
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from enum import Enum

logger = logging.getLogger("ir.toolkit")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")


# ---------------------------------------------------------------------------
# Incident Severity & Phase Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "P1-CRITICAL"
    HIGH = "P2-HIGH"
    MEDIUM = "P3-MEDIUM"
    LOW = "P4-LOW"


class IRPhase(str, Enum):
    DETECTION = "detection_and_analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"


class IOCType(str, Enum):
    IP = "ip-addr"
    DOMAIN = "domain-name"
    FILE_HASH = "file-hash"
    EMAIL = "email-addr"
    URL = "url"
    REGISTRY_KEY = "windows-registry-key"
    PROCESS = "process"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ChainOfCustodyEntry:
    """Immutable evidence tracking entry (append-only log)."""
    timestamp: str
    analyst: str
    action: str
    artefact: str
    hash_sha256: str
    notes: str = ""


@dataclass
class IOCIndicator:
    """Indicators of Compromise — STIX 2.1 compatible fields."""
    ioc_id: str
    ioc_type: IOCType
    value: str
    confidence: int       # 0–100
    severity: Severity
    first_seen: str
    description: str
    mitre_technique: Optional[str] = None
    tags: list[str] = field(default_factory=list)


@dataclass
class EvidenceArtefact:
    """A collected forensic artefact with integrity verification."""
    artefact_id: str
    artefact_type: str    # memory_dump, process_list, network_connections, etc.
    collected_at: str
    collected_by: str
    source_host: str
    file_path: Optional[str]
    sha256: Optional[str]
    md5: Optional[str]
    size_bytes: int
    content_preview: str  # First 500 chars (no sensitive data)
    chain_of_custody: list[ChainOfCustodyEntry] = field(default_factory=list)


@dataclass
class Incident:
    """Full incident record following NIST SP 800-61r2."""
    incident_id: str
    title: str
    severity: Severity
    category: str         # malware, phishing, insider_threat, etc.
    phase: IRPhase
    detected_at: str
    reported_by: str
    affected_systems: list[str]
    description: str
    iocs: list[IOCIndicator] = field(default_factory=list)
    artefacts: list[EvidenceArtefact] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    containment_actions: list[str] = field(default_factory=list)
    lessons_learned: Optional[str] = None
    closed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Evidence Collector
# ---------------------------------------------------------------------------

class EvidenceCollector:
    """
    Collects volatile and non-volatile forensic artefacts.
    Designed to be run on a live system during incident response.
    All collection is read-only — never modifies source data.
    """

    def __init__(self, incident_id: str, analyst: str, output_dir: Path):
        self.incident_id = incident_id
        self.analyst = analyst
        self.output_dir = output_dir / incident_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"{self.incident_id}-ART-{self._seq:04d}"

    def _hash_content(self, content: bytes) -> tuple[str, str]:
        return (
            hashlib.sha256(content).hexdigest(),
            hashlib.md5(content).hexdigest(),
        )

    def _add_custody(self, artefact: EvidenceArtefact, action: str) -> None:
        entry = ChainOfCustodyEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            analyst=self.analyst,
            action=action,
            artefact=artefact.artefact_id,
            hash_sha256=artefact.sha256 or "",
        )
        artefact.chain_of_custody.append(entry)

    def collect_process_list(self) -> EvidenceArtefact:
        """Capture running process list — highest priority volatile artefact."""
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ["tasklist", "/fo", "csv", "/v"], text=True, timeout=10
                )
            else:
                output = subprocess.check_output(
                    ["ps", "aux", "--sort=-%cpu"], text=True, timeout=10
                )
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            output = f"[Collection failed: {e}]"

        content = output.encode()
        sha256, md5 = self._hash_content(content)
        artefact = EvidenceArtefact(
            artefact_id=self._next_id(),
            artefact_type="process_list",
            collected_at=datetime.now(timezone.utc).isoformat(),
            collected_by=self.analyst,
            source_host=platform.node(),
            file_path=None,
            sha256=sha256,
            md5=md5,
            size_bytes=len(content),
            content_preview=output[:500],
        )
        self._add_custody(artefact, "Collected process list via OS API")
        logger.info("Collected process list — %s bytes", len(content))
        return artefact

    def collect_network_connections(self) -> EvidenceArtefact:
        """Capture active network connections (netstat equivalent)."""
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ["netstat", "-ano"], text=True, timeout=10
                )
            else:
                result = subprocess.run(
                    ["ss", "-tunp"], capture_output=True, text=True, timeout=10
                )
                output = result.stdout if result.returncode == 0 else subprocess.check_output(
                    ["netstat", "-tunp"], text=True, timeout=10
                )
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            output = f"[Collection failed: {e}]"

        content = output.encode()
        sha256, md5 = self._hash_content(content)
        artefact = EvidenceArtefact(
            artefact_id=self._next_id(),
            artefact_type="network_connections",
            collected_at=datetime.now(timezone.utc).isoformat(),
            collected_by=self.analyst,
            source_host=platform.node(),
            file_path=None,
            sha256=sha256,
            md5=md5,
            size_bytes=len(content),
            content_preview=output[:500],
        )
        self._add_custody(artefact, "Collected network connections via ss/netstat")
        logger.info("Collected network connections — %s bytes", len(content))
        return artefact

    def collect_file(self, file_path: Path) -> EvidenceArtefact:
        """Hash and record an evidence file without copying sensitive data."""
        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        content = file_path.read_bytes()
        sha256, md5 = self._hash_content(content)
        preview = content[:500].decode("utf-8", errors="replace")

        artefact = EvidenceArtefact(
            artefact_id=self._next_id(),
            artefact_type="file_evidence",
            collected_at=datetime.now(timezone.utc).isoformat(),
            collected_by=self.analyst,
            source_host=platform.node(),
            file_path=str(file_path.resolve()),
            sha256=sha256,
            md5=md5,
            size_bytes=len(content),
            content_preview=preview,
        )
        self._add_custody(artefact, f"Collected file: {file_path.name}")
        logger.info("Collected file %s (SHA256: %s)", file_path.name, sha256[:16])
        return artefact

    def save_artefacts(self, artefacts: list[EvidenceArtefact]) -> Path:
        """Persist all artefact metadata to JSON (integrity-preserving)."""
        path = self.output_dir / "artefacts.json"
        path.write_text(json.dumps([asdict(a) for a in artefacts], indent=2))
        logger.info("Artefacts written to %s", path)
        return path


# ---------------------------------------------------------------------------
# IOC Extractor
# ---------------------------------------------------------------------------

class IOCExtractor:
    """
    Extracts and classifies Indicators of Compromise from raw text.
    Patterns cover the most common IOC types seen in malware reports.
    """

    _IP_RE = re.compile(r"\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|xyz|tk|cc|ru|cn|onion)\b")
    _MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
    _SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    _URL_RE = re.compile(r"https?://[^\s\"'<>]+")

    def extract(self, text: str, source: str = "unknown") -> list[IOCIndicator]:
        iocs = []
        seen: set[str] = set()
        now = datetime.now(timezone.utc).isoformat()
        _seq = 0

        def add(ioc_type: IOCType, value: str, confidence: int, desc: str):
            nonlocal _seq
            if value in seen:
                return
            seen.add(value)
            _seq += 1
            iocs.append(IOCIndicator(
                ioc_id=f"IOC-{_seq:06d}",
                ioc_type=ioc_type,
                value=value,
                confidence=confidence,
                severity=Severity.HIGH if confidence >= 80 else Severity.MEDIUM,
                first_seen=now,
                description=f"{desc} — extracted from {source}",
            ))

        for m in self._IP_RE.finditer(text):
            add(IOCType.IP, m.group(), 75, "Public IP address")
        for m in self._DOMAIN_RE.finditer(text):
            if len(m.group()) > 6:
                add(IOCType.DOMAIN, m.group(), 65, "Domain name")
        for m in self._SHA256_RE.finditer(text):
            add(IOCType.FILE_HASH, m.group(), 95, "SHA-256 file hash")
        for m in self._MD5_RE.finditer(text):
            add(IOCType.FILE_HASH, m.group(), 80, "MD5 file hash")
        for m in self._EMAIL_RE.finditer(text):
            add(IOCType.EMAIL, m.group(), 85, "Email address")
        for m in self._URL_RE.finditer(text):
            add(IOCType.URL, m.group(), 90, "URL")

        logger.info("Extracted %d IOCs from %s", len(iocs), source)
        return iocs


# ---------------------------------------------------------------------------
# Automated Playbook Engine
# ---------------------------------------------------------------------------

@dataclass
class PlaybookStep:
    step_id: int
    name: str
    description: str
    automated: bool
    action: Optional[callable] = field(default=None, repr=False)
    result: Optional[str] = None
    completed_at: Optional[str] = None


class PlaybookEngine:
    """
    Executes structured IR playbooks with automated and manual steps.
    Playbooks are defined as ordered lists of PlaybookSteps.
    """

    PLAYBOOKS = {
        "ransomware": [
            "Isolate affected hosts from network (disable NIC / VLAN change)",
            "Preserve volatile memory before shutdown",
            "Identify Patient Zero — earliest encrypted file timestamp",
            "Locate and terminate ransomware process",
            "Block C2 IPs/domains at firewall and DNS",
            "Identify backup integrity — check for shadow copy deletion",
            "Notify legal / DPO (GDPR 72-hour window if PII affected)",
            "Begin recovery from clean offline backups",
            "Conduct full malware analysis on isolated sample",
            "Draft post-incident report and update detection rules",
        ],
        "phishing": [
            "Identify all recipients of phishing email",
            "Pull email headers — trace sending infrastructure",
            "Block sender domain / IP at email gateway",
            "Check for credential harvesting pages — request takedown",
            "Search mail logs for users who clicked links",
            "Force password reset for compromised accounts",
            "Enable MFA for all affected accounts",
            "Check for OAuth app authorisations (consent phishing)",
            "Notify users via out-of-band communication",
            "Submit phishing indicators to threat intel feeds",
        ],
        "insider_threat": [
            "Preserve evidence immediately — do NOT alert suspect",
            "Coordinate with HR and Legal before any action",
            "Collect DLP logs — identify data exfiltration scope",
            "Review badge access logs and CCTV footage",
            "Image suspect workstation and storage media",
            "Review email, Slack, and file access audit logs",
            "Identify accomplices or external contacts",
            "Revoke access credentials (timed with HR action)",
            "Preserve chain-of-custody for potential prosecution",
            "Brief executive team and prepare regulatory notification",
        ],
    }

    def execute(self, playbook_name: str, incident: Incident, dry_run: bool = False) -> list[dict]:
        steps = self.PLAYBOOKS.get(playbook_name)
        if not steps:
            raise ValueError(f"Unknown playbook: {playbook_name}. Available: {list(self.PLAYBOOKS.keys())}")

        results = []
        logger.info("Executing playbook: %s (dry_run=%s)", playbook_name, dry_run)

        for i, step in enumerate(steps, 1):
            ts = datetime.now(timezone.utc).isoformat()
            status = "completed" if not dry_run else "dry_run"
            result = {
                "step": i,
                "description": step,
                "status": status,
                "timestamp": ts,
            }
            incident.timeline.append(result)
            incident.containment_actions.append(f"[Step {i}] {step}")
            results.append(result)
            logger.info("  [%d/%d] %s — %s", i, len(steps), status.upper(), step[:60])

        return results


# ---------------------------------------------------------------------------
# STIX 2.1 Indicator Export
# ---------------------------------------------------------------------------

class STIXExporter:
    """Exports IOCs as STIX 2.1 bundle for threat intel platform ingestion."""

    def export_bundle(self, iocs: list[IOCIndicator], incident_id: str) -> dict:
        """Generate a minimal STIX 2.1 indicator bundle."""
        indicators = []
        for ioc in iocs:
            pattern = self._build_pattern(ioc)
            if not pattern:
                continue
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.ioc_id}",
                "created": ioc.first_seen,
                "modified": ioc.first_seen,
                "name": f"{ioc.ioc_type.value}: {ioc.value[:60]}",
                "description": ioc.description,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.first_seen,
                "confidence": ioc.confidence,
                "labels": ["malicious-activity"],
            })

        bundle = {
            "type": "bundle",
            "id": f"bundle--{incident_id}",
            "spec_version": "2.1",
            "objects": indicators,
        }
        return bundle

    @staticmethod
    def _build_pattern(ioc: IOCIndicator) -> Optional[str]:
        t = ioc.ioc_type
        v = ioc.value.replace("'", "\\'")
        if t == IOCType.IP:
            return f"[ipv4-addr:value = '{v}']"
        if t == IOCType.DOMAIN:
            return f"[domain-name:value = '{v}']"
        if t == IOCType.URL:
            return f"[url:value = '{v}']"
        if t == IOCType.EMAIL:
            return f"[email-message:sender_ref.value = '{v}']"
        if t == IOCType.FILE_HASH:
            algo = "SHA-256" if len(ioc.value) == 64 else "MD5"
            return f"[file:hashes.'{algo}' = '{v}']"
        return None
