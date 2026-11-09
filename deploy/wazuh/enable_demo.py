"""Opt-in demo configuration for local Wazuh MANAGER (run with sudo --apply).

Backs up ossec.conf, installs a dedicated custom-rule file, validates XML and
restores the previous configuration if the manager fails its configuration test.
Does not inject any synthetic events until instructed separately.
"""
from __future__ import annotations
import argparse
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

PROJECT = Path(__file__).resolve().parents[2]
CONFIG = Path('/var/ossec/etc/ossec.conf')
RULES = Path('/var/ossec/etc/rules/soc_demo_rules.xml')
SOURCE_RULES = PROJECT/'deploy/wazuh/soc_demo_rules.xml'
LOG = Path('/var/log/soc_demo_cloud.jsonl')
MARKER = '<location>/var/log/soc_demo_cloud.jsonl</location>'
STANZA = '\n  <localfile>\n    <location>/var/log/soc_demo_cloud.jsonl</location>\n    <log_format>json</log_format>\n  </localfile>\n'


def insert_stanza(text):
    if MARKER in text:
        return text
    target = '</ossec_config>'
    if target not in text:
        raise ValueError('Cannot find ossec_config closing tag; no changes made')
    return text.replace(target, STANZA+'\n'+target,1)


def main():
    p=argparse.ArgumentParser(description='Careful opt-in Wazuh manager SOC demo setup')
    p.add_argument('--apply',action='store_true',help='Actually modify local manager config after backup')
    args=p.parse_args()
    ET.parse(SOURCE_RULES)
    if not CONFIG.is_file():
        raise SystemExit('Wazuh manager config missing; do not install anything')
    original=CONFIG.read_text(encoding='utf-8')
    proposed=insert_stanza(original)
    if RULES.exists() and RULES.read_bytes()!=SOURCE_RULES.read_bytes():
        raise SystemExit('Existing SOC demo rule file differs; refusing overwrite')
    print('Wazuh config:',CONFIG)
    print('New monitor needed:',proposed!=original)
    print('Custom rules:',SOURCE_RULES)
    if not args.apply:
        print('DRY RUN ONLY: no changes made. Use sudo python3 deploy/wazuh/enable_demo.py --apply')
        return
    if os.geteuid()!=0:
        raise SystemExit('Use sudo for --apply')
    stamp=datetime.now().strftime('%Y%m%d-%H%M%S')
    backup=CONFIG.with_name('ossec.conf.soc-demo-backup-'+stamp)
    shutil.copy2(CONFIG,backup)
    changed_rule=not RULES.exists()
    try:
        if proposed!=original:
            CONFIG.write_text(proposed,encoding='utf-8')
        if changed_rule:
            shutil.copy2(SOURCE_RULES,RULES)
            RULES.chmod(0o640)
        LOG.touch(exist_ok=True)
        LOG.chmod(0o644)
        validator=Path('/var/ossec/bin/wazuh-analysisd')
        if not validator.exists():
            raise RuntimeError('Wazuh analysisd validation binary missing')
        result=subprocess.run([str(validator),'-t'],capture_output=True,text=True,timeout=45)
        print('RULE VALIDATION EXIT:',result.returncode)
        if result.returncode:
            print((result.stdout+'\n'+result.stderr)[-1500:])
            raise RuntimeError('Wazuh analysisd rejected the rules')
        # Restart only after validation, with recovery on failure.
        subprocess.run(['systemctl','restart','wazuh-manager'],check=True,timeout=90)
        subprocess.run(['systemctl','is-active','--quiet','wazuh-manager'],check=True,timeout=15)
    except Exception as exc:
        print('FAILED: rolling back Wazuh config:',exc)
        shutil.copy2(backup,CONFIG)
        if changed_rule and RULES.exists(): RULES.unlink()
        try:
            subprocess.run(['systemctl','restart','wazuh-manager'],check=False,timeout=90)
        except Exception:
            pass
        raise SystemExit('Rolled back Wazuh config; inspect backup and ossec.log') from exc
    print('WAZUH MANAGER ACTIVE. BACKUP:',backup)
    print('NO DEMO EVENTS HAVE BEEN INJECTED YET.')

if __name__=='__main__':
    main()
