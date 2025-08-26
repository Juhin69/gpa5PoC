#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
safe_poc_console.py
A SAFE, NON-DESTRUCTIVE proof-of-concept console (simulation) for demonstrations and
responsible disclosure packages.

Features:
 - msf-like interactive console (set/show/check/run/login/sanitize/write-readme/exit)
 - colored output (colorama)
 - generates simulated evidence JSON files in ./reports/
 - sanitization utility to redact phone numbers/tokens in JSON evidence
 - explicit confirmation (type "yes") before any simulated destructive action

IMPORTANT:
 - This script DOES NOT perform any network requests. It's a simulation/demo tool only.
 - Only use real exploit steps on targets you own AND after following responsible disclosure practices.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import textwrap
from datetime import datetime
from getpass import getpass

# optional nice colors
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
except Exception:
    class _Fake:
        def __getattr__(self, n): return ""
    Fore = Style = _Fake()

TOOL_VERSION = "safe_poc_console 1.0"
CONFIRM_PHRASE = "yes"   # you said you wanted "yes"

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def ensure_reports_dir():
    os.makedirs("reports", exist_ok=True)

def print_banner():
    banner = r"""
  ____   ____    _   ___   ___
 / ___| |  _ \  / | / _ \ / _ \ ___   _   _
| |  _  | |_) | | || | | | | | / _ \ | | | |
| |_| | |  __/  | || |_| | |_| | (_) || |_| |
 \____| |_|     |_| \___/ \___/ \___/  \__, |
                                       |___/
"""
    print(Fore.CYAN + Style.BRIGHT + banner + Style.RESET_ALL)
    print(Fore.RED + Style.BRIGHT + "                 ACCOUNT TAKEOVER" + Style.RESET_ALL)
    print(Fore.MAGENTA + Style.DIM + "                 Author: Juhin69" + Style.RESET_ALL)
    print()

class Simulator:
    def __init__(self, verbose: bool=False):
        self.verbose = verbose
        self.cfg = {
            "target_url": "<fill_with_allowed_url>",
            "phone": None,
            "password": None,
            "report_path": "reports/evidence_simulated.json"
        }

    def debug(self, *a):
        if self.verbose:
            print(Fore.CYAN + "[DEBUG]" + Style.RESET_ALL, *a)

    def set(self, key: str, value: str):
        if key in self.cfg:
            self.cfg[key] = value
            print(Fore.GREEN + "OK" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "Unknown key" + Style.RESET_ALL)

    def show(self):
        print(json.dumps(self.cfg, indent=2))

    def check(self):
        phone = self.cfg.get("phone")
        if not phone:
            print(Fore.YELLOW + "Set phone first: set phone <number>" + Style.RESET_ALL); return
        # Simulate a harmless check that returns 200 and a message
        print(Fore.YELLOW + "[i] Simulated check response:" + Style.RESET_ALL)
        print("    HTTP 200")
        print('    Body: {"status_code":200,"message":"Simulated: OTP/verification not required (DEMO)"}')

    def run(self):
        phone = self.cfg.get("phone")
        password = self.cfg.get("password")
        if not phone or not password:
            print(Fore.YELLOW + "set phone and password before running" + Style.RESET_ALL); return
        confirm = input(Fore.YELLOW + f"Type confirmation phrase to proceed ({CONFIRM_PHRASE}): " + Style.RESET_ALL).strip()
        if confirm != CONFIRM_PHRASE:
            print(Fore.RED + "Confirmation failed. Aborting." + Style.RESET_ALL); return

        # Simulate "exploit"
        print(Fore.GREEN + f"[+] Simulated: password for {phone} would be set to: {password}" + Style.RESET_ALL)
        evidence = {
            "timestamp": now_iso(),
            "tool_version": TOOL_VERSION,
            "note": "THIS IS A SIMULATED EVIDENCE FILE — no network requests were performed.",
            "target_phone": phone,
            "new_password": password,
            "simulated_response": {"status_code": 200, "message": "Simulated success: use new password to login"},
        }
        ensure_reports_dir()
        path = self.cfg.get("report_path") or f"reports/evidence_{phone}.json"
        # avoid overwriting unless user wants that
        if os.path.exists(path):
            base, ext = os.path.splitext(path)
            path = f"{base}.{int(datetime.utcnow().timestamp())}{ext}"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"[+] Simulated evidence written to {path}" + Style.RESET_ALL)

    def login(self, login_url: str | None = None):
        phone = self.cfg.get("phone")
        password = self.cfg.get("password")
        if not phone or not password:
            print(Fore.YELLOW + "set phone and password first" + Style.RESET_ALL); return
        # simulate login heuristics
        print(Fore.YELLOW + "[i] Simulated login attempts (no network calls):" + Style.RESET_ALL)
        attempts = []
        if login_url:
            attempts.append((login_url, "json"))
        attempts.extend([
            ("https://example.com/api/login", "json"),
            ("https://example.com/login", "form"),
        ])
        for url, kind in attempts:
            # simplistic heuristic: if password length > 6 we "succeed"
            success = len(password) >= 6
            print(f"  - {url} -> success={success} (simulated)")
        if len(password) >= 6:
            print(Fore.GREEN + "[+] Simulated login success; session cookie captured (simulated)" + Style.RESET_ALL)
        else:
            print(Fore.RED + "[-] Simulated login failed (incorrect credentials)" + Style.RESET_ALL)

    def sanitize(self, path: str, keep_phone: str | None = None, inplace: bool=False):
        if not os.path.exists(path):
            print(Fore.RED + f"[!] File not found: {path}" + Style.RESET_ALL); return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            print(Fore.RED + "[!] Failed to load JSON:" + Style.RESET_ALL, e); return

        def redact_str(s: str):
            # redact phone numbers (Bangladesh-style) except keep_phone
            def repl_phone(m):
                ph = m.group(0)
                return ph if keep_phone and ph == keep_phone else "REDACTED_PHONE"
            s = re.sub(r"01\\d{9}", repl_phone, s)
            # redact long hex-like tokens
            s = re.sub(r"[0-9a-fA-F]{20,}", "REDACTED_TOKEN", s)
            # redact jwt-like (starts with eyJ)
            s = re.sub(r"eyJ[A-Za-z0-9_\\-\\.]{10,}", "REDACTED_TOKEN", s)
            return s

        def walk(o):
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            if isinstance(o, list):
                return [walk(x) for x in o]
            if isinstance(o, str):
                return redact_str(o)
            return o

        redacted = walk(data)
        out_path = path if inplace else (os.path.splitext(path)[0] + ".sanitized.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(redacted, fh, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"[+] Sanitized evidence written to {out_path}" + Style.RESET_ALL)

    def write_readme(self, path="README_safe_poc.md"):
        text = f"""# Safe PoC Console README

This is a simulated PoC tool (no network activity). Use for demo and evidence packaging.

Quick commands:
 - set phone 017...
 - set password <newpass>
 - check
 - run   (will ask for confirmation 'yes' before writing simulated evidence)
 - login
 - sanitize <evidence.json> --keep-phone 017...
"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(Fore.GREEN + f"[+] README written to {path}" + Style.RESET_ALL)

def repl(sim: Simulator):
    print("Type 'help' for commands. 'exit' to quit.")
    while True:
        try:
            line = input(Fore.BLUE + "safe-poc> " + Style.RESET_ALL).strip()
        except (KeyboardInterrupt, EOFError):
            print(); break
        if not line:
            continue
        args = line.split()
        cmd = args[0].lower()
        if cmd == "help":
            print(textwrap.dedent("""\
                Available commands:
                  set url <url>
                  set phone <phone>
                  set password <pwd>        (or 'set password -' to enter hidden)
                  show
                  check
                  run
                  login [login_url]
                  sanitize <path> [--keep <phone>] [--inplace]
                  write-readme
                  exit
                """))
        elif cmd == "set":
            if len(args) < 3:
                print("Usage: set <key> <value>"); continue
            key = args[1].lower()
            if key == "password" and args[2] == "-":
                val = getpass("Password (hidden): ")
            else:
                val = " ".join(args[2:])
            if key == "url":
                sim.set("target_url", val)
            elif key == "phone":
                sim.set("phone", val)
            elif key == "password":
                sim.set("password", val)
            else:
                print("Unknown key")
        elif cmd == "show":
            sim.show()
        elif cmd == "check":
            sim.check()
        elif cmd == "run":
            sim.run()
        elif cmd == "login":
            login_url = args[1] if len(args) > 1 else None
            sim.login(login_url)
        elif cmd == "sanitize":
            if len(args) < 2:
                print("Usage: sanitize <path> [--keep <phone>] [--inplace]"); continue
            path = args[1]
            keep = None
            inplace = False
            if "--keep" in args:
                try:
                    keep = args[args.index("--keep") + 1]
                except Exception:
                    keep = None
            if "--inplace" in args:
                inplace = True
            sim.sanitize(path, keep_phone=keep, inplace=inplace)
        elif cmd == "write-readme":
            sim.write_readme()
        elif cmd == "exit":
            break
        else:
            print("Unknown command. Type 'help' for commands.")

def main():
    parser = argparse.ArgumentParser(prog="safe_poc_console", description="Safe, non-destructive PoC console (simulation)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    sim = Simulator(verbose=args.verbose)
    repl(sim)
    print("Goodbye.")

if __name__ == "__main__":
    main()
