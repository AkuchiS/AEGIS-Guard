#!/usr/bin/env python3
"""
AEGIS Guard — unified CLI.

  aegis check  <file|->            Scan untrusted INPUT for prompt-injection (exit 2 = quarantine)
  aegis qc     <file|->  [--json]  QC an agent OUTPUT (exit 2 = reject)
  aegis guard  <file|->            Combined input gate (injection + secret checks), exit 2 = block
  aegis selftest                   Run all self-tests (exit 0 = all pass)

Reads from a file path, or '-' for stdin. Pure-Python, offline, zero required deps.
"""
import json
import sys
from aegis.injection_guard import scan_text, selftest as inj_selftest
from aegis.output_qc import check_output, selftest as qc_selftest


def _read(arg: str) -> str:
    if arg == "-":
        return sys.stdin.read()
    with open(arg, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    rest = argv[1:]

    if cmd == "selftest":
        return 1 if (inj_selftest() or qc_selftest()) else 0

    if cmd in ("check", "guard"):
        text = _read(rest[0]) if rest else sys.stdin.read()
        r = scan_text(text)
        print(json.dumps(r, indent=2))
        return 2 if r["action"] == "quarantine" else (1 if r["action"] == "flag" and cmd == "guard" else 0)

    if cmd == "qc":
        require_json = "--json" in rest
        files = [a for a in rest if not a.startswith("--")]
        text = _read(files[0]) if files else sys.stdin.read()
        r = check_output(text, require_json=require_json)
        print(json.dumps(r, indent=2))
        return 2 if r["action"] == "reject" else 0

    sys.stderr.write(f"unknown command: {cmd}\n")
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
