#!/usr/bin/env python3
"""Build social-media and anti-bypass Pi-hole lists from selected UT1 categories."""
from __future__ import annotations

import argparse
import io
import ipaddress
import json
import re
import shutil
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

BASE_URL = "https://dsi.ut-capitole.fr/blacklists/download"
USER_AGENT = "pihole-kids-blocklists/1.0 (https://github.com/digcyber/pihole-kids-blocklists)"
HTTP_RETRIES = 4
HTTP_TIMEOUT = 90
MAX_DROP_FRACTION = 0.30
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)

SOCIAL_CATEGORIES = {
    "social_networks": 100,
    "dating": 1000,
    "chat": 50,
}
ANTI_BYPASS_CATEGORIES = {
    "doh": 500,
    "vpn": 1000,
    "residential-proxies": 20,
    "redirector": 10_000,
}


class BuildError(RuntimeError):
    pass


def normalize_hostname(value: str) -> str | None:
    raw = value.strip()
    if not raw or raw.startswith("#") or any(ch.isspace() for ch in raw):
        return None
    candidate = raw if "://" in raw else "//" + raw
    try:
        parsed = urlsplit(candidate, allow_fragments=True)
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(host) > 253 or "." not in host:
        return None
    labels = host.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels) or labels[-1].isdigit():
        return None
    return host


def read_domains(path: Path) -> set[str]:
    if not path.exists():
        return set()
    result: set[str] = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        domain = normalize_hostname(value)
        if not domain:
            raise BuildError(f"invalid hostname in {path} line {lineno}: {value!r}")
        result.add(domain)
    return result


def write_domains(path: Path, domains: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{d}\n" for d in sorted(domains)), encoding="utf-8", newline="\n")


def suffix_excluded(domain: str, roots: set[str]) -> bool:
    return any(domain == root or domain.endswith("." + root) for root in roots)


def apply_suffix_exceptions(domains: set[str], roots: set[str]) -> tuple[set[str], int]:
    removed = {d for d in domains if suffix_excluded(d, roots)}
    return domains - removed, len(removed)


def _retry_delay(exc: Exception, attempt: int) -> float:
    if isinstance(exc, HTTPError) and exc.headers:
        retry_after = exc.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 60.0)
    return min(2 ** attempt, 20)


def download(url: str, destination: Path) -> None:
    last: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=HTTP_TIMEOUT) as response, destination.open("wb") as out:
                shutil.copyfileobj(response, out, length=1024 * 1024)
            if destination.stat().st_size < 500:
                raise BuildError(f"download unexpectedly small: {url}")
            return
        except (HTTPError, URLError, TimeoutError, OSError, BuildError) as exc:
            last = exc
            destination.unlink(missing_ok=True)
            if attempt < HTTP_RETRIES - 1:
                time.sleep(_retry_delay(exc, attempt))
    raise BuildError(f"failed to download {url}: {last}")


def parse_ut1_category_archive(path: Path, category: str) -> set[str]:
    try:
        tar = tarfile.open(path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BuildError(f"malformed UT1 {category} archive: {exc}") from exc
    domains: set[str] = set()
    seen = {"domains": False, "urls": False}
    records = invalid = 0
    with tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            basename = Path(member.name).name
            if basename not in seen:
                continue
            seen[basename] = True
            f = tar.extractfile(member)
            if f is None:
                continue
            try:
                text = io.TextIOWrapper(f, encoding="utf-8", errors="strict")
                for line in text:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    records += 1
                    domain = normalize_hostname(value)
                    if domain:
                        domains.add(domain)
                    else:
                        invalid += 1
            except UnicodeDecodeError as exc:
                raise BuildError(f"UT1 {category}/{basename} is not valid UTF-8") from exc
    if not all(seen.values()):
        raise BuildError(f"UT1 {category} archive lacks expected domains/urls files")
    if records == 0:
        raise BuildError(f"UT1 {category} archive contains no records")
    if invalid > max(100, int(records * 0.10)):
        raise BuildError(f"UT1 {category} has too many malformed records: {invalid}/{records}")
    return domains


def fetch_category(category: str, minimum: int) -> set[str]:
    with tempfile.TemporaryDirectory(prefix=f"ut1-{category}-") as tmp:
        archive = Path(tmp) / f"{category}.tar.gz"
        download(f"{BASE_URL}/{category}.tar.gz", archive)
        domains = parse_ut1_category_archive(archive, category)
    if len(domains) < minimum:
        raise BuildError(f"UT1 {category} suspiciously small: {len(domains):,}; minimum is {minimum:,}")
    return domains


def guard_drop(name: str, previous: set[str], current: set[str]) -> None:
    if len(previous) < 50:
        return
    minimum = int(len(previous) * (1.0 - MAX_DROP_FRACTION))
    if len(current) < minimum:
        drop = (len(previous) - len(current)) / len(previous) * 100
        raise BuildError(f"{name} dropped {drop:.1f}% ({len(previous):,} -> {len(current):,}); refusing replacement")


def validate(domains: set[str]) -> None:
    if not domains:
        raise BuildError("output is empty")
    for domain in domains:
        if normalize_hostname(domain) != domain:
            raise BuildError(f"invalid output hostname: {domain}")


def build(args: argparse.Namespace) -> dict:
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    social_manual = read_domains(args.manual_social)
    social_ex = read_domains(args.social_exceptions)
    anti_ex = read_domains(args.anti_bypass_exceptions)

    social_parts = {cat: fetch_category(cat, minimum) for cat, minimum in SOCIAL_CATEGORIES.items()}
    anti_parts = {cat: fetch_category(cat, minimum) for cat, minimum in ANTI_BYPASS_CATEGORIES.items()}

    social_merged = set().union(*social_parts.values(), social_manual)
    social_final, social_removed = apply_suffix_exceptions(social_merged, social_ex)
    anti_merged = set().union(*anti_parts.values())
    anti_final, anti_removed = apply_suffix_exceptions(anti_merged, anti_ex)

    validate(social_final)
    validate(anti_final)
    guard_drop("social-media", read_domains(args.previous_social), social_final)
    guard_drop("anti-bypass", read_domains(args.previous_anti_bypass), anti_final)

    write_domains(out / "social-media.txt", social_final)
    write_domains(out / "anti-bypass.txt", anti_final)
    write_domains(out / "ut1-social.txt", set().union(*social_parts.values()))
    write_domains(out / "ut1-anti-bypass.txt", anti_merged)

    stats = {
        "social": {**{k: len(v) for k, v in social_parts.items()}, "manual": len(social_manual), "exceptions_applied": social_removed, "final": len(social_final)},
        "anti_bypass": {**{k: len(v) for k, v in anti_parts.items()}, "exceptions_applied": anti_removed, "final": len(anti_final)},
    }
    (out / "policy-stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return stats


def print_summary(path: Path) -> None:
    s = json.loads(path.read_text(encoding="utf-8"))
    print("## UT1 household policy lists\n")
    print("### Social media\n")
    print("| Source | Domains |\n|---|---:|")
    for key in ("social_networks", "dating", "chat", "manual", "exceptions_applied", "final"):
        print(f"| {key} | {s['social'][key]:,} |")
    print("\n### Anti-bypass\n")
    print("| Source | Domains |\n|---|---:|")
    for key in ("doh", "vpn", "residential-proxies", "redirector", "exceptions_applied", "final"):
        print(f"| {key} | {s['anti_bypass'][key]:,} |")


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--output-dir", type=Path, required=True)
    b.add_argument("--manual-social", type=Path, default=Path("manual-social-media.txt"))
    b.add_argument("--social-exceptions", type=Path, default=Path("social-exceptions.txt"))
    b.add_argument("--anti-bypass-exceptions", type=Path, default=Path("anti-bypass-exceptions.txt"))
    b.add_argument("--previous-social", type=Path, default=Path("blocklists/social-media.txt"))
    b.add_argument("--previous-anti-bypass", type=Path, default=Path("blocklists/anti-bypass.txt"))
    s = sub.add_parser("summary")
    s.add_argument("path", type=Path)
    args = p.parse_args()
    try:
        if args.command == "build":
            print(json.dumps(build(args), indent=2, sort_keys=True))
        else:
            print_summary(args.path)
        return 0
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
