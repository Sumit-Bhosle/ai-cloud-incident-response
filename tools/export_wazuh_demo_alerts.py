#!/usr/bin/env python3
"""Export only academic SOC-demo Wazuh JSON alerts (private data).

Use sudo to read the Wazuh alert archive; output must reside in ignored
`data/lab_evidence/`. It keeps duplicates so the verifier can diagnose them.
This is NOT an AWS or Wazuh configuration tool; it only reads log records.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from src.demo.wazuh_pipeline import _alert_files, _iter_alerts


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True,help="Current or archived Wazuh alerts path")
    parser.add_argument("--out",type=Path,required=True,help="Private output JSONL under data/lab_evidence/")
    parser.add_argument("--force",action="store_true",help="Explicitly replace an existing export")
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    private=(root/"data"/"lab_evidence").resolve()
    output=args.out.resolve()
    if not output.is_relative_to(private):
        raise SystemExit("REFUSING: output must be inside private data/lab_evidence")
    if output.exists() and not args.force:
        raise SystemExit("REFUSING: export exists; choose a new filename or explicitly use --force")
    output.parent.mkdir(parents=True,exist_ok=True)
    n=0
    seen=set()
    mode="w" if args.force else "x"
    with output.open(mode,encoding="utf-8") as dest:
        output.chmod(0o600)
        for alert in _iter_alerts(_alert_files(args.source)):
            data=alert.get("data")
            if not isinstance(data,dict) or data.get("soc_demo")!="research_simulation":
                continue
            dest.write(json.dumps(alert,ensure_ascii=False,separators=(",",":"))+"\n")
            n+=1
            seen.add(str(data.get("sim_event_id")))
    print(f"EXPORTED: {n} simulation-tagged Wazuh alert rows ({len(seen)} distinct candidate event IDs)")
    print("PRIVATE OUTPUT:",output)
    print("NOTE: verify authenticity and deduplicate via wazuh_pipeline audit; this export does not itself establish valid evidence")

if __name__ == "__main__":
    main()
