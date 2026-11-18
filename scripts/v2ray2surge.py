#!/usr/bin/env python3
"""
v2ray2surge.py - convert a v2ray (v2rayN) subscription into a Surge profile by
driving the local subconverter engine in generator mode:

    subconverter -g --artifact <section-name>      # reads sections from generate.ini

Why generator mode: the engine has no ports to manage and no server to keep alive.
The artifact section we inject accepts exactly the same arguments as the HTTP
interface (/sub?target=surge&ver=4&url=...), so nothing is lost.

Notes taken from the subconverter source (this repo):
  * src/handler/multithread.cpp   fetchFile() accepts local file paths for url=
  * src/parser/subparser.cpp      a subscription body is urlSafeBase64Decode()d
                                  first, so a plain "vmess://..." text file is
                                  rejected -> we always hand over base64
  * src/generator/config/subexport.cpp  proxyToSurge(): VMess/Trojan/WireGuard/
                                  Hysteria need surge_ver >= 4; VMess transport
                                  is limited to tcp/ws, anything else `continue`s
  * src/handler/interfaces.cpp    generateArtifact() leaks arguments between
                                  artifact sections -> one section per run

Usage:
    python3 scripts/v2ray2surge.py                     # uses SUBSCRIPTION below
    python3 scripts/v2ray2surge.py -f my_sub.txt -o out.conf
    python3 scripts/v2ray2surge.py --url https://example.com/sub --ver 3
    python3 scripts/v2ray2surge.py --dry-run           # show what would run

SUBSCRIPTION may be either the subscription body (base64 blob or one link per
line) or a subscription URL - a single http(s) line is detected and handed to
the engine as url= instead of being parsed locally.

Engine capability warning: node types are limited by the engine *build* you point
--engine at, not only by Surge. The prebuilt v0.9.0 macOS release knows vmess,
ss, ssr, trojan, socks, http, snell, wireguard - it has no parser for
hysteria2/anytls/vless, so those links are dropped at the parse stage (verified:
'strings subconverter | grep -c -i "^hysteria2$"' -> 0, and the same links also
produce nothing for target=clash). The source tree in this repo does parse
hysteria2 and anytls (still no vless); build it if you need those.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter
from urllib.parse import unquote

# =============================================================================
#  PASTE YOUR V2RAYN SUBSCRIPTION HERE
#  Both shapes are accepted: the base64 blob v2rayN exports, or one link per line.
# =============================================================================
SUBSCRIPTION = r"""
https://su.hihi.us/?sid=539&uid=43&token=Ib2fWEBAAP92&app=v2rayn
"""

DEFAULT_ENGINE = "/tmp/subconverter_release/subconverter"
ARTIFACT_PREFIX = "py_subconv"


# --------------------------------------------------------------------------- #
# subscription normalisation
# --------------------------------------------------------------------------- #
def clean_links(raw: str) -> list[str]:
    """Split a subscription body into individual links (base64 blob or plain)."""
    body = raw.strip().strip('"')
    if not body:
        return []

    # v2rayN-style blob: single line of base64 -> decode and recurse
    collapsed = "".join(body.split())
    if "\n" not in body and _looks_like_base64(collapsed):
        try:
            decoded = base64.b64decode(collapsed + "=" * (-len(collapsed) % 4),
                                       validate=False).decode("utf-8", "replace")
        except (binascii.Error, UnicodeDecodeError):
            decoded = ""
        if "://" in decoded:
            body = decoded

    links: list[str] = []
    for line in re.split(r"[\r\n]+", body):
        line = line.strip()
        if not line:
            continue
        # some providers base64-encode every single line
        if not "://" in line and _looks_like_base64(line):
            try:
                dec = base64.b64decode(line + "=" * (-len(line) % 4),
                                       validate=False).decode("utf-8", "replace")
                if "://" in dec:
                    line = dec
            except (binascii.Error, UnicodeDecodeError):
                pass
        links.append(line)
    return links


def to_base64_blob(links: list[str]) -> str:
    """subconverter base64-decodes the subscription body, so feed it base64."""
    return base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")


def _looks_like_base64(s: str) -> bool:
    return len(s) >= 16 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", s) is not None


# --------------------------------------------------------------------------- #
# link inspection (used for the drop report, mirrors proxyToSurge rules)
# --------------------------------------------------------------------------- #
SUPPORTED_TRANSPORTS = {"tcp", "ws", "none", ""}

# What this codebase / the shipped release binary can actually parse.
ENGINE_SCHEME_NOTES = {
    "vless": "no VLESS support in this codebase at all (grep 'vless' src/ finds nothing)",
    "hysteria2": "parsed by the source tree (src/parser/subparser.cpp:1535) but NOT by the "
                 "prebuilt release binary - build the source to get it",
    "hy2": "see hysteria2",
    "anytls": "parsed by the source tree (src/parser/subparser.cpp:1392) but NOT by the "
              "prebuilt release binary - build the source to get it",
}


def link_info(link: str) -> dict:
    """Best-effort {type, remark, transport} for a proxy link."""
    scheme = link.split("://", 1)[0].split("/", 1)[0].lower()
    info = {"type": scheme, "remark": None, "transport": None}

    if scheme in ("vmess", "vmess1"):
        payload = link.split("://", 1)[1].split("?")[0].split("@")[0]
        try:
            data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4),
                                               validate=False).decode("utf-8", "replace"))
            info["remark"] = data.get("ps")
            info["transport"] = (data.get("net") or "tcp").lower()
        except Exception:
            pass
    else:
        if "#" in link:
            info["remark"] = link.rsplit("#", 1)[1]
        if scheme in ("vmess", "trojan", "anytls"):
            info["transport"] = "tcp"
        if scheme in ("hysteria", "hy2"):
            info["transport"] = "udp"
    return info


def predicted_surge_verdict(info: dict, target: str, ver: int) -> tuple[bool, str]:
    """Predict whether proxyToSurge() would emit this node (subexport.cpp)."""
    if target != "surge":
        return True, ""
    t, transport, v = info["type"], info["transport"], ver
    modern_only = {"vmess", "trojan", "wireguard", "hysteria2", "hy2", "anytls"}
    if t in modern_only and v not in (-3, 4) and v < 4:
        return False, f"Surge {v} cannot express {t}; needs ver=4"
    if t in ("vmess", "vmess1") and transport not in SUPPORTED_TRANSPORTS:
        return False, f"VMess transport '{transport}' has no Surge mapping (only tcp/ws)"
    if t == "ssr":
        return False, "SSR needs an external ssr-local binary ([surge_external_proxy] surge_ssr_path)"
    return True, ""


# --------------------------------------------------------------------------- #
# engine invocation
# --------------------------------------------------------------------------- #
def engine_command(binary: str) -> list[str]:
    """The shipped macOS release is an unsigned x86_64 binary -> needs Rosetta on arm64."""
    cmd = [binary]
    archs = ""
    if sys.platform == "darwin":
        try:
            archs = subprocess.run(["lipo", "-archs", binary], capture_output=True,
                                   text=True, timeout=15).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            archs = ""
    if "x86_64" in archs and "arm64" not in archs and platform.machine() == "arm64":
        cmd = ["arch", "-x86_64", binary]
    return cmd


def build_artifact(section: str, out_path: str, target: str, ver: int, url: str,
                   profile: str | None, extra: dict[str, str]) -> str:
    lines = [f"[{section}]", f"path={out_path}", f"target={target}"]
    if target == "surge":
        lines.append(f"ver={ver}")
    lines.append(f"url={url}")
    if profile:
        lines.append(f"config={profile}")
    for k, v in extra.items():
        lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


def run_generator(binary: str, artifact_text: str, section: str, timeout: int,
                  verbose: bool) -> tuple[int, str]:
    """Temporarily append our artifact section to the engine's generate.ini, run, restore."""
    engine_dir = os.path.dirname(os.path.abspath(binary))
    gen_ini = os.path.join(engine_dir, "generate.ini")

    original = None
    if os.path.exists(gen_ini):
        with open(gen_ini, "rb") as fh:
            original = fh.read()
    try:
        with open(gen_ini, "wb") as fh:
            if original:
                fh.write(original)
                if not original.endswith(b"\n"):
                    fh.write(b"\n")
                fh.write(b"\n")
            fh.write(artifact_text.encode("utf-8"))

        cmd = engine_command(binary) + ["-g", "--artifact", section]
        if verbose:
            print(f"[run] {' '.join(cmd)}  (cwd={engine_dir})", file=sys.stderr)
        proc = subprocess.run(cmd, cwd=engine_dir, capture_output=True, text=True,
                              timeout=timeout)
        log = proc.stdout + proc.stderr
        if proc.returncode in (137, -9) and cmd[0] == binary:
            # unsigned x86_64 binary killed by macOS: retry through Rosetta
            cmd = ["arch", "-x86_64", binary, "-g", "--artifact", section]
            proc = subprocess.run(cmd, cwd=engine_dir, capture_output=True, text=True,
                                  timeout=timeout)
            log = proc.stdout + proc.stderr
        return proc.returncode, log
    finally:
        if original is None:
            try:
                os.remove(gen_ini)
            except FileNotFoundError:
                pass
        else:
            with open(gen_ini, "wb") as fh:
                fh.write(original)


def engine_warnings(log: str) -> list[str]:
    return [l.strip() for l in log.splitlines() if re.search(r"\[(WARN|ERRO)\]", l)]


def profile_entries(profile_text: str) -> list[tuple[str, str]]:
    """(name, type) of the proxy entries the engine really wrote.

    The [Proxy] section also carries bare group aliases (e.g. '\U0001f3af \u5168\u7403\u76f4\u8fde = direct'),
    so entries whose value is plain 'direct' are excluded along with DIRECT itself.
    """
    m = re.search(r"^\[Proxy\]\n(.*?)(?=^\[|\Z)", profile_text, re.M | re.S)
    if not m:
        return []
    entries = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, body = (p.strip() for p in line.split("=", 1))
        if not name or body.lower() == "direct":
            continue
        entries.append((name, body.split(",")[0].strip().lower()))
    return entries


def looks_like_url(text: str) -> bool:
    return bool(re.match(r"(?i)^https?://", text)) or text.startswith("surge:///install-config")


def fetch_links(source: str, timeout: int) -> list[str]:
    """Read a remote (or local) subscription so we can compare input vs. output."""
    try:
        if os.path.isfile(source):
            body = open(source, encoding="utf-8").read()
        else:
            req = urllib.request.Request(source, headers={"User-Agent": "v2rayN/7.15 subconverter-helper"})
            body = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    except Exception as exc:          # offline/proxy-blocked: coverage report is best effort
        print(f"note: could not fetch the subscription for coverage analysis: {exc}", file=sys.stderr)
        return []
    return clean_links(body)


def coverage_report(links: list[str], entries: list[tuple[str, str]], target: str, ver: int) -> list[str]:
    """Print what the subscription held vs. what the profile contains; return warnings."""
    infos = [link_info(l) for l in links]
    written = {name.lower(): _ for name, _ in entries}
    notes: list[str] = []

    in_schemes = Counter(i["type"] or "?" for i in infos)
    print(f"subscription : {len(links)} node(s) -> "
          + ", ".join(f"{count} {scheme}" for scheme, count in sorted(in_schemes.items())))
    print(f"in profile   : {len(entries)} proxy entr{'y' if len(entries) == 1 else 'ies'} "
          "(DIRECT and group aliases excluded)")
    if entries:
        out_types = Counter(t for _, t in entries)
        print(f"               -> " + ", ".join(f"{count} {t}" for t, count in sorted(out_types.items())))

    missing = []
    for info in infos:
        remark = unquote(info.get("remark") or "")
        if remark and remark.lower() in written:
            continue
        keep, why = predicted_surge_verdict(info, target, ver)
        if not why:
            why = ENGINE_SCHEME_NOTES.get(info["type"], "not emitted by the engine build")
        missing.append((remark or "<unnamed node>", info["type"], why))

    if missing:
        print(f"missing      : {len(missing)} node(s) not in the profile")
        for remark, scheme, why in missing:
            print(f"   - {remark} [{scheme}]: {why}")
            note = ENGINE_SCHEME_NOTES.get(scheme)
            if note and note not in notes:
                notes.append(note)
    return notes


def drop_managed_config(profile_text: str) -> str:
    return "\n".join(l for l in profile_text.splitlines()
                     if not l.startswith("#!MANAGED-CONFIG")) + "\n"


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                               formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-s", "--subscription", default=SUBSCRIPTION,
                    help="inline subscription body OR a subscription URL (defaults to the SUBSCRIPTION block)")
    ap.add_argument("-f", "--subscription-file", help="read the subscription from a file instead")
    ap.add_argument("--url", help="let the engine fetch a remote subscription URL instead")
    ap.add_argument("-o", "--out", default="surge_profile.conf", help="output file")
    ap.add_argument("--target", default="surge",
                    help="surge | clash | clashr | quan | quanx | loon | surfboard | v2ray | ss | ssr")
    ap.add_argument("--ver", type=int, default=4, help="Surge version (2/3/4)")
    ap.add_argument("--profile", help="config= argument, e.g. config/ACL4SSR_Online_Full.ini or profiles/x.ini")
    ap.add_argument("--arg", action="append", default=[], metavar="K=V",
                    help="extra generate.ini argument, repeatable (e.g. --arg include_remarks=HK)")
    ap.add_argument("--list-profiles", action="store_true", help="list bundled config/ and profiles/ names")
    ap.add_argument("--engine", default=DEFAULT_ENGINE, help="path to the subconverter binary")
    ap.add_argument("--out-dir", default=None, help="scratch dir for engine temp files (default: system temp)")
    ap.add_argument("--ephemeral", action="store_true",
                    help="keep the normalized subscription only in a temp dir (default: store it next to --out)")
    ap.add_argument("--no-managed", action="store_true",
                    help="strip the #!MANAGED-CONFIG header (produce a fully static profile)")
    ap.add_argument("--timeout", type=int, default=180, help="engine timeout in seconds")
    ap.add_argument("--print", action="store_true", help="print the generated profile to stdout")
    ap.add_argument("--keep-temp", action="store_true", help="keep the intermediate subscription/output files")
    ap.add_argument("--dry-run", action="store_true", help="show what would be executed")
    ap.add_argument("-v", "--verbose", action="store_true", help="show the engine log")
    args = ap.parse_args()

    binary = os.path.abspath(args.engine)
    if not os.path.isfile(binary):
        print(f"error: subconverter binary not found: {binary}", file=sys.stderr)
        return 2

    engine_dir = os.path.dirname(binary)

    if args.list_profiles:
        for sub in ("config", "profiles"):
            d = os.path.join(engine_dir, sub)
            if os.path.isdir(d):
                print(f"{sub}/")
                for name in sorted(os.listdir(d)):
                    if name.endswith((".ini", ".conf", ".tpl")):
                        print(f"  {sub}/{name}")
        return 0

    # ---- gather the subscription ------------------------------------------------
    source_url: str | None = args.url
    links: list[str] = []
    if source_url is None:
        raw = open(args.subscription_file, encoding="utf-8").read() if args.subscription_file else args.subscription
        raw = raw.strip()
        # A single http(s) line is a subscription link, not a subscription body:
        # hand it to the engine as url= and let it do the downloading.
        if "\n" not in raw and looks_like_url(raw):
            source_url = raw
            print(f"note: SUBSCRIPTION holds a URL, passing it to the engine as url={source_url}",
                  file=sys.stderr)
        else:
            links = clean_links(raw)
            if not links:
                print("error: the subscription is empty - paste the subscription body or a subscription "
                      "URL into SUBSCRIPTION, or pass -f/--url", file=sys.stderr)
                return 2

    # ---- scratch + durable files ----------------------------------------------
    out_path = os.path.abspath(args.out)
    scratch = tempfile.mkdtemp(prefix="v2ray2surge.", dir=args.out_dir)
    tmp_out = os.path.join(scratch, "profile.out")

    # The engine echoes the url= it was given into the #!MANAGED-CONFIG header, so if we
    # hand it a file in a temp dir that header points at something that no longer exists.
    # Store the normalized subscription next to the output unless --ephemeral is asked for.
    sub_file = None
    if source_url is None:
        if args.ephemeral:
            sub_file = os.path.join(scratch, "subscription.b64")
        else:
            out_dir = os.path.dirname(out_path) or os.getcwd()
            os.makedirs(out_dir, exist_ok=True)
            sub_file = os.path.join(out_dir, os.path.basename(out_path) + ".subscription.b64")
        with open(sub_file, "w", encoding="utf-8") as fh:
            fh.write(to_base64_blob(links))
        source_url = sub_file

    extra = {}
    for item in args.arg:
        if "=" not in item:
            print(f"error: bad --arg {item!r} (expected K=V)", file=sys.stderr)
            return 2
        k, v = item.split("=", 1)
        extra[k] = v

    section = f"{ARTIFACT_PREFIX}_{os.getpid()}"
    artifact = build_artifact(section, tmp_out, args.target, args.ver, source_url,
                            args.profile, extra)

    if args.dry_run:
        print(f"# generate.ini section that would be appended to {engine_dir}/generate.ini")
        print(artifact)
        print(f"# engine command: {' '.join(engine_command(binary))} -g --artifact {section}")
        if sub_file:
            print(f"# subscription file: {sub_file}\n#   {open(sub_file, encoding='utf-8').read()[:160]}...")
        return 0

    # ---- run -------------------------------------------------------------------
    try:
        rc, log = run_generator(binary, artifact, section, args.timeout, args.verbose)
        if args.verbose:
            print(log, file=sys.stderr)

        if not os.path.exists(tmp_out):
            print(f"error: engine produced no output (exit {rc})", file=sys.stderr)
            for line in engine_warnings(log):
                print(f"  engine: {line}", file=sys.stderr)
            return 1

        with open(tmp_out, "rb") as fh:
            profile_bytes = fh.read()
        profile_text = profile_bytes.decode("utf-8-sig", "replace")
        if not profile_text.strip():
            print("error: generated profile is empty", file=sys.stderr)
            for line in engine_warnings(log):
                print(f"  engine: {line}", file=sys.stderr)
            return 1

        if args.no_managed:
            profile_text = drop_managed_config(profile_text)
            profile_bytes = profile_text.encode("utf-8")

        with open(out_path, "wb") as fh:
            fh.write(profile_bytes.lstrip(b"\xef\xbb\xbf"))

        # ---- report -------------------------------------------------------------
        print(f"engine   : {binary}")
        print(f"target   : {args.target}" + (f" (ver={args.ver})" if args.target == "surge" else ""))
        print(f"output   : {out_path} ({len(profile_text.splitlines())} lines)")

        if profile_text.startswith("#!MANAGED-CONFIG"):
            header = profile_text.splitlines()[0]
            print(f"header   : {header[:110]}...")
            if sub_file and not args.ephemeral:
                print(f"           auto-update needs the server running and reads {sub_file}")
            print("           use --no-managed for a fully static profile")

        if not links:                       # remote subscription: fetch it ourselves to compare
            links = fetch_links(source_url, args.timeout)
        notes = []
        if links:
            if args.target == "surge":
                notes = coverage_report(links, profile_entries(profile_text), args.target, args.ver)
            else:
                print(f"subscription : {len(links)} node(s)")
            for line in engine_warnings(log):
                print(f"engine warning: {line}")
        for note in notes:
            print(f"why        : {note}")
    finally:
        try:
            os.remove(tmp_out)
        except OSError:
            pass
        if sub_file and sub_file.startswith(scratch):   # only the throwaway copy
            try:
                os.remove(sub_file)
            except OSError:
                pass
        if args.keep_temp:
            print(f"scratch kept: {scratch}")
        else:
            try:
                os.rmdir(scratch)
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
