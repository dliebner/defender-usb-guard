#!/usr/bin/env python3
"""Cross-check DefenderUsbGuard.ps1 against Microsoft's published ASR rules reference.

Verifies that every ASR rule GUID in the script exists in the reference, that "Warn" is
offered exactly for the rules Microsoft says support it, and reports rules that Microsoft
documents but the script's display-name map does not know about (informational).

Usage: python3 tools/check_asr_docs.py [--doc PATH]   (PATH = a local copy of the reference)
"""
import re
import sys
import urllib.request

DOC_URL = ("https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/"
           "defender-endpoint/attack-surface-reduction-rules-reference.md")
SCRIPT = "DefenderUsbGuard.ps1"
GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


def parse_docs(text):
    """Return {guid: (rule name, supports_warn)} from the '#### <rule>' sections."""
    rules = {}
    for section in re.split(r"^#### ", text, flags=re.M)[1:]:
        name = section.split("\n", 1)[0].strip()
        m = re.search(r"\*\*GUID\*\*:\s*`(" + GUID + r")`", section)
        if m:
            rules[m.group(1).lower()] = (name, "doesn't support **Warn** mode" not in section)
    return rules


def parse_script(text):
    """Return ([(key, guid, offers_warn)], [display-map guids])."""
    block = re.search(r"\$SettingDefs = @\((.*?)^\)", text, re.S | re.M).group(1)
    settings = []
    for chunk in re.split(r"(?=@\{\s*Key=)", block)[1:]:
        key = re.search(r"Key='([^']+)'", chunk).group(1)
        guid = re.search(r"Guid='(" + GUID + r")'", chunk)
        if not guid:
            continue
        options = re.search(r"Options=(\$AsrOptions|@\([^)]*\))", chunk).group(1)
        offers_warn = options == "$AsrOptions" or "'Warn'" in options
        settings.append((key, guid.group(1).lower(), offers_warn))
    names_block = re.search(r"\$AsrNames = @\{(.*?)^\}", text, re.S | re.M).group(1)
    names = [g.lower() for g in re.findall(r"'(" + GUID + r")'\s*=", names_block)]
    return settings, names


def main():
    doc_path = sys.argv[sys.argv.index("--doc") + 1] if "--doc" in sys.argv else None
    if doc_path:
        doc = open(doc_path, encoding="utf-8").read()
    else:
        with urllib.request.urlopen(DOC_URL, timeout=60) as r:
            doc = r.read().decode("utf-8")
    docs = parse_docs(doc)
    if len(docs) < 15:
        print(f"::error::Only {len(docs)} rules parsed from the reference; its format may have changed.")
        return 1
    settings, names = parse_script(open(SCRIPT, encoding="ascii").read())

    errors = 0
    for key, guid, offers_warn in settings:
        if guid not in docs:
            print(f"::error file={SCRIPT}::{key}: GUID {guid} is not in Microsoft's ASR reference.")
            errors += 1
            continue
        name, supports_warn = docs[guid]
        if offers_warn and not supports_warn:
            print(f"::error file={SCRIPT}::{key}: offers Warn, but Microsoft says '{name}' does not support Warn mode.")
            errors += 1
        elif supports_warn and not offers_warn:
            print(f"::error file={SCRIPT}::{key}: does not offer Warn, but Microsoft says '{name}' supports it.")
            errors += 1
        else:
            print(f"ok  {key:18} {guid}  warn={'yes' if supports_warn else 'no'}  {name}")
    for guid in names:
        if guid not in docs:
            print(f"::error file={SCRIPT}::display-name map: GUID {guid} is not in Microsoft's ASR reference.")
            errors += 1
    for guid, (name, _) in docs.items():
        if guid not in names:
            print(f"::warning file={SCRIPT}::Microsoft documents '{name}' ({guid}) but the display-name map does not list it.")

    print(f"{len(settings)} settings and {len(names)} display names checked against {len(docs)} documented rules; {errors} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
