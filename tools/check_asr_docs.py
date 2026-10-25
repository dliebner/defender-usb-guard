#!/usr/bin/env python3
"""Cross-check DefenderUsbGuard.ps1 against Microsoft's published ASR rules reference.

Verifies that every ASR rule GUID in the script exists in the reference, that "Warn" is
offered exactly for the rules Microsoft says support it, and reports rules that Microsoft
documents but the script's display-name map does not know about (informational).

Sources are tried in order: the Microsoft Learn page (HTML), then the docs source repository
on GitHub (Markdown; archived in September 2026 but kept in case it returns).

Usage: python3 tools/check_asr_docs.py [--doc PATH]   (PATH = a local copy, HTML or Markdown)
"""
import html
import re
import sys
import urllib.error
import urllib.request

SOURCES = [
    "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference",
    "https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/defender-endpoint/attack-surface-reduction-rules-reference.md",
]
SCRIPT = "DefenderUsbGuard.ps1"
GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
NO_WARN = re.compile(r"doesn.t\s+support\W{0,6}Warn\W{0,6}mode", re.I)   # tolerates **, tags, curly apostrophes


def clean(fragment):
    """Strip tags, unescape entities, collapse whitespace."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def parse_markdown(text):
    """{guid: (rule name, supports_warn)} from the '#### <rule>' sections of the docs source."""
    rules = {}
    for section in re.split(r"^#{3,4} ", text, flags=re.M)[1:]:
        name = section.split("\n", 1)[0].strip()
        m = re.search(r"\*\*GUID\*\*:\s*`(" + GUID + r")`", section)
        if m:
            rules[m.group(1).lower()] = (name, not NO_WARN.search(section))
    return rules


def parse_html(page):
    """{guid: (rule name, supports_warn)} from the rendered Learn page: each rule is a heading
    followed by a section that contains its GUID and, for some rules, the no-Warn note."""
    rules = {}
    parts = re.split(r"(?i)<h[2-4]\b[^>]*>", page)[1:]
    for part in parts:
        m = re.match(r"(?is)(.*?)</h[2-4]\s*>", part)
        if not m:
            continue
        name = clean(m.group(1))
        body = part[m.end():]
        g = re.search(r"(?i)<code[^>]*>\s*(" + GUID + r")\s*</code>", body) or re.search(GUID, body)
        if not g or not name:
            continue
        guid = g.group(1).lower() if g.lastindex else g.group(0).lower()
        if guid not in rules:
            rules[guid] = (name, not NO_WARN.search(clean(body)))
    return rules


def parse_docs(text):
    return parse_html(text) if re.search(r"(?i)<h[2-4]\b|<html|<body", text) else parse_markdown(text)


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


def fetch_reference():
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "defender-usb-guard docs check"})
            with urllib.request.urlopen(req, timeout=60) as r:
                print(f"Reference: {url}")
                return r.read().decode("utf-8", "replace")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            print(f"::warning::Could not fetch {url}: {e}")
    print("::error::No reference source could be fetched.")
    return None


def main():
    if "--doc" in sys.argv:
        doc = open(sys.argv[sys.argv.index("--doc") + 1], encoding="utf-8", errors="replace").read()
    else:
        doc = fetch_reference()
        if doc is None:
            return 1
    docs = parse_docs(doc)
    if len(docs) < 15:
        print(f"::error::Only {len(docs)} rules parsed from the reference; its format may have changed.")
        for guid, (name, _) in docs.items():
            print(f"    parsed: {guid}  {name}")
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
