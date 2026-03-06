"""
Incident Response Toolkit — CLI
Usage:
    python main.py --demo                          # Full ransomware IR simulation
    python main.py --playbook phishing             # Run phishing playbook
    python main.py --extract-iocs --input file.txt # Extract IOCs from file
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from src.ir_toolkit import (
    Incident, Severity, IRPhase, EvidenceCollector,
    IOCExtractor, PlaybookEngine, STIXExporter
)
from dataclasses import asdict

DEMO_THREAT_REPORT = """
Ransomware Campaign — ThreatActor: ALPHV/BlackCat

Observed IOCs:
  C2 Server: 185.220.101.47
  Malware hash: 3f4a6b2c1d8e7f9a0b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2
  Dropper MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  Phishing domain: malicious-update.xyz
  Exfil URL: http://185.220.101.47:8080/upload
  Contact email: blackcat-support@proton.me

Affected: 3 Windows servers, 1 ESXi host
Ransom demand: 0.5 BTC
"""


def run_demo():
    print("\n" + "="*60)
    print("  🚨 INCIDENT RESPONSE TOOLKIT — RANSOMWARE SIMULATION")
    print("="*60)

    # 1. Create incident
    incident = Incident(
        incident_id="INC-2024-001",
        title="ALPHV/BlackCat Ransomware Infection",
        severity=Severity.CRITICAL,
        category="ransomware",
        phase=IRPhase.DETECTION,
        detected_at=datetime.now(timezone.utc).isoformat(),
        reported_by="SOC-Analyst-1",
        affected_systems=["WIN-SRV-01", "WIN-SRV-02", "ESX-01"],
        description="Ransomware infection detected via EDR alert. Multiple encrypted files observed.",
    )
    print(f"\n[✓] Incident created: {incident.incident_id} — {incident.severity.value}")

    # 2. Extract IOCs
    print("\n[*] Extracting IOCs from threat report...")
    extractor = IOCExtractor()
    iocs = extractor.extract(DEMO_THREAT_REPORT, source="analyst_report")
    incident.iocs = iocs
    for ioc in iocs:
        print(f"    [{ioc.ioc_type.value.upper():<15}] {ioc.value[:60]}  (confidence: {ioc.confidence}%)")

    # 3. Collect evidence
    print("\n[*] Collecting volatile evidence...")
    collector = EvidenceCollector(
        incident_id=incident.incident_id,
        analyst="SOC-Analyst-1",
        output_dir=Path("evidence"),
    )
    artefacts = [
        collector.collect_process_list(),
        collector.collect_network_connections(),
    ]
    incident.artefacts = artefacts
    for a in artefacts:
        print(f"    [{a.artefact_type}] SHA256: {a.sha256[:32]}...")

    # 4. Run ransomware playbook
    print("\n[*] Executing ransomware response playbook...")
    engine = PlaybookEngine()
    engine.execute("ransomware", incident, dry_run=True)
    print(f"    Playbook complete — {len(incident.containment_actions)} steps executed")

    # 5. Export STIX bundle
    print("\n[*] Generating STIX 2.1 threat intelligence bundle...")
    exporter = STIXExporter()
    bundle = exporter.export_bundle(iocs, incident.incident_id)
    stix_path = Path("evidence") / incident.incident_id / "stix_bundle.json"
    stix_path.parent.mkdir(parents=True, exist_ok=True)
    stix_path.write_text(json.dumps(bundle, indent=2))
    print(f"    STIX bundle → {stix_path} ({len(bundle['objects'])} indicators)")

    # 6. Save full incident
    report_path = Path("evidence") / incident.incident_id / "incident_report.json"
    report_path.write_text(json.dumps(asdict(incident), indent=2, default=str))

    print(f"\n{'='*60}")
    print(f"  ✅ IR Simulation Complete")
    print(f"  IOCs extracted    : {len(iocs)}")
    print(f"  Artefacts         : {len(artefacts)}")
    print(f"  Playbook steps    : {len(incident.containment_actions)}")
    print(f"  STIX indicators   : {len(bundle['objects'])}")
    print(f"  Incident report   : {report_path}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Incident Response & Forensics Toolkit")
    parser.add_argument("--demo", action="store_true", help="Run ransomware IR simulation")
    parser.add_argument("--playbook", choices=["ransomware", "phishing", "insider_threat"],
                        help="Run a specific playbook")
    parser.add_argument("--extract-iocs", action="store_true", help="Extract IOCs from a file")
    parser.add_argument("--input", type=Path, help="Input file for IOC extraction")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.playbook:
        incident = Incident(
            incident_id="INC-CLI-001", title=f"{args.playbook} Incident",
            severity=Severity.HIGH, category=args.playbook,
            phase=IRPhase.CONTAINMENT,
            detected_at=datetime.now(timezone.utc).isoformat(),
            reported_by="cli-user", affected_systems=["TBD"],
            description=f"Running {args.playbook} playbook",
        )
        engine = PlaybookEngine()
        engine.execute(args.playbook, incident, dry_run=True)
    elif args.extract_iocs and args.input:
        text = args.input.read_text(errors="replace")
        iocs = IOCExtractor().extract(text, source=args.input.name)
        for ioc in iocs:
            print(f"[{ioc.ioc_type.value}] {ioc.value}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
