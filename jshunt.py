#!/usr/bin/env python3
"""
jshunt - Hunt for leaked credentials and API keys in JavaScript files.

Pipeline:
  1. Collect JS URLs (subjs / domain / URL list)
  2. Bulk download JS files
  3. Scan contents with gitleaks + curated gf patterns
  4. Generate consolidated Markdown report
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

# Relevant pattern classes for leaked credentials and sensitive endpoints
GF_PATTERNS = ["sec", "aws-keys", "s3-buckets", "firebase", "http-auth", "json-sec"]


def resolve_bin(name):
    """Find binary from PATH or common Go/security bin directories."""
    custom_bin = os.environ.get("TOOLS_BIN")
    if custom_bin:
        cand = Path(custom_bin) / name
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)

    found = shutil.which(name)
    if found:
        return found

    candidates = [
        Path.home() / "go" / "bin" / name,
        Path.home() / ".local" / "bin" / name,
        Path("/usr/local/bin") / name,
        Path("/opt/tools/bin") / name,
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return str(c)

    return name


def sh(cmd, timeout=300, stdin=None):
    """Execute shell command and return (returncode, stdout+stderr)."""
    try:
        p = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "[timeout]"
    except FileNotFoundError as e:
        return 127, f"[command not found] {e}"


def collect_js(args, outdir):
    """Collect target JavaScript URLs from domain, file list, or direct URL."""
    jslist = outdir / "js-urls.txt"

    if args.url:
        jslist.write_text(args.url + "\n", encoding="utf-8")
        print("[1/4] Single JS URL specified via argument")
        return jslist

    if args.list:
        src = Path(args.list).read_text(encoding="utf-8").splitlines()
        js = [u for u in src if ".js" in u]
        jslist.write_text("\n".join(js) + "\n", encoding="utf-8")
        print(f"[1/4] Loaded {len(js)} JS URLs from {args.list}")
        return jslist

    # From target domain: resolve subdomains and crawl with subjs
    print(f"[1/4] Enumerating live hosts for domain: {args.domain} ...")
    subfinder = resolve_bin("subfinder")
    rc, out = sh([subfinder, "-d", args.domain, "-silent"], timeout=240)
    hosts = [h.strip() for h in out.splitlines() if h.strip()]
    if not hosts:
        print("  [-] Subfinder returned no subdomains")
        return None

    httpx = resolve_bin("httpx") if shutil.which("httpx") else resolve_bin("httpx-pd")
    rc, out = sh([httpx, "-silent", "-l", "/dev/stdin"], timeout=300, stdin="\n".join(hosts))
    live = [h.strip() for h in out.splitlines() if h.strip()]
    print(f"  [+] {len(hosts)} subdomains -> {len(live)} live hosts")

    subjs = resolve_bin("subjs")
    rc, out = sh([subjs, "-i", "/dev/stdin"], timeout=300, stdin="\n".join(live))
    urls = sorted({u.strip() for u in out.splitlines() if u.strip().endswith(".js")})
    if not urls:
        print("  [-] No JavaScript files discovered")
        return None
    jslist.write_text("\n".join(urls) + "\n", encoding="utf-8")
    print(f"  [+] Discovered {len(urls)} JavaScript files")
    return jslist


def download(jslist, outdir):
    """Download discovered JavaScript files locally for static analysis."""
    jsdir = outdir / "downloaded"
    jsdir.mkdir(parents=True, exist_ok=True)
    urls = [u for u in jslist.read_text(encoding="utf-8").splitlines() if u.strip()]
    ok = 0
    for i, u in enumerate(urls, 1):
        parsed = urlparse(u).path
        name = f"{i:04d}_" + Path(parsed).name.replace("/", "_")[:80] or f"{i:04d}.js"
        if not name.endswith(".js"):
            name += ".js"
        rc, _ = sh(["curl", "-s", "-m", "20", "-o", str(jsdir / name), u], timeout=30)
        if rc == 0 and (jsdir / name).exists() and (jsdir / name).stat().st_size > 0:
            ok += 1
    print(f"[2/4] Successfully downloaded {ok}/{len(urls)} JS files -> {jsdir}")
    return jsdir


def scan(jsdir, outdir):
    """Scan JS files using gitleaks and curated gf pattern matching."""
    findings = []
    ansi = re.compile(r"\x1b\[[0-9;]*m")

    print("[3/4] Running gitleaks detect ...")
    gitleaks = resolve_bin("gitleaks")
    rc, out = sh(
        [
            gitleaks,
            "detect",
            "--no-git",
            "-v",
            "--no-banner",
            "--source",
            str(jsdir),
            "--report-format",
            "json",
            "--report-path",
            str(outdir / "gitleaks.json"),
        ],
        timeout=300,
    )
    if out.strip():
        findings.append(("gitleaks", ansi.sub("", out.strip())))

    print("[3/4] Running gf pattern matches ...")
    gf = resolve_bin("gf")
    content = ""
    for f in sorted(jsdir.glob("*.js")):
        content += f.read_text(errors="ignore") + "\n"

    for pat in GF_PATTERNS:
        rc, out = sh([gf, pat], timeout=120, stdin=content)
        hits = [
            line
            for line in out.splitlines()
            if line.strip()
            and not line.startswith("#")
            and "not found" not in line.lower()
            and "tidak ada" not in line.lower()
        ]
        if hits:
            findings.append((f"gf:{pat}", "\n".join(hits[:50])))

    return findings


def report(findings, outdir):
    """Write summary report of discovered patterns."""
    print("[4/4] Writing report ...")
    rep = outdir / "report.md"
    lines = ["# JavaScript Credential & Secret Audit Report", ""]
    if not findings:
        lines.append("No sensitive findings detected. Downloaded JS files are clean of queried patterns.")
    for name, body in findings:
        lines += [f"## {name}", "```", body, "```", ""]
    rep.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [+] Report saved -> {rep}")
    if findings:
        print(f"  [!] Identified {len(findings)} finding categories. Review {rep}")
    else:
        print("  [+] Clean.")
    return rep


def main():
    parser = argparse.ArgumentParser(
        description="Hunt for leaked credentials, secrets, and API keys in JavaScript files"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target domain (e.g. target.com)")
    group.add_argument("-u", "--url", help="Single JavaScript URL")
    group.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-o", "--outdir", help="Output directory (default: ./jshunt-<target>)")
    args = parser.parse_args()

    tag = args.domain or Path(args.url or args.list).stem
    outdir = Path(args.outdir) if args.outdir else Path(f"jshunt-{tag}")
    outdir.mkdir(parents=True, exist_ok=True)

    jslist = collect_js(args, outdir)
    if not jslist:
        sys.exit(1)
    jsdir = download(jslist, outdir)
    if not any(jsdir.iterdir()):
        print("[-] No JS files were downloaded.")
        sys.exit(1)
    findings = scan(jsdir, outdir)
    report(findings, outdir)


if __name__ == "__main__":
    main()
