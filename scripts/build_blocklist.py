#!/usr/bin/env python3
"""Build an auditable Pi-hole shopping-domain blocklist from open sources."""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import ipaddress
import json
import re
import shutil
import sys
import tarfile
import tempfile
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

CURLIE_URL = "https://curlie.org/directory-dl"
UT1_URL = "https://dsi.ut-capitole.fr/blacklists/download/shopping.tar.gz"
WDQS_URL = "https://query.wikidata.org/sparql"
USER_AGENT = "pihole-shopping-blocklist/1.1 (https://github.com/digcyber/pihole-kids-blocklists)"

CURLIE_ROOTS = (
    "Shopping",
    "World/Nederlands/Webwinkelen",
    "World/Deutsch/Online-Shops",
    "World/Français/Boutiques_en_ligne",
    "World/Español/Compras",
    "World/Italiano/Acquisti_Online",
    "World/Polski/Zakupy",
)
WIKIDATA_ROOT_CLASSES = ("Q4382945", "Q3390477")

MIN_CURLIE_ARCHIVE_BYTES = 50_000_000
MIN_CURLIE_DOMAINS = 10_000
MIN_UT1_ARCHIVE_BYTES = 100_000
MIN_UT1_DOMAINS = 10_000
MIN_WIKIDATA_DOMAINS = 50
MIN_MANUAL_DOMAINS = 10
MAX_DROP_FRACTION = 0.30
HTTP_RETRIES = 4
HTTP_TIMEOUT = 50
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)


class BuildError(RuntimeError):
    pass


@dataclass
class Stats:
    curlie_domains: int
    ut1_domains: int
    wikidata_domains: int
    manual_domains: int
    duplicates: int
    exceptions_configured: int
    exceptions_applied: int
    final_domains: int
    previous_domains: int
    difference: int
    difference_percent: float | None


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
    if not host or host.startswith("."):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(ascii_host) > 253 or "." not in ascii_host:
        return None
    labels = ascii_host.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return ascii_host


def parse_domain_lines(lines: Iterable[str], *, strict: bool = False) -> set[str]:
    domains: set[str] = set()
    bad: list[str] = []
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        domain = normalize_hostname(stripped)
        if domain is None:
            bad.append(f"line {line_number}: {stripped!r}")
        else:
            domains.add(domain)
    if strict and bad:
        raise BuildError(f"invalid domain input ({len(bad)} line(s)): {', '.join(bad[:5])}")
    return domains


def read_domain_file(path: Path, *, strict: bool = False) -> set[str]:
    if not path.exists():
        return set()
    return parse_domain_lines(path.read_text(encoding="utf-8").splitlines(), strict=strict)


def write_domains(path: Path, domains: Iterable[str]) -> None:
    values = sorted(set(domains))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{d}\n" for d in values), encoding="utf-8", newline="\n")


def _retry_delay(exc: Exception, attempt: int) -> float:
    if isinstance(exc, HTTPError):
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 60.0)
    return min(2 ** attempt, 20)


def _open_url(url: str, *, accept: str | None = None, compressed: bool = False, timeout: int = HTTP_TIMEOUT):
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    if compressed:
        headers["Accept-Encoding"] = "gzip, deflate"
    return urlopen(Request(url, headers=headers), timeout=timeout)


def _read_response_body(response) -> bytes:
    payload = response.read()
    encoding = (response.headers.get("Content-Encoding") or "").lower().strip()
    if encoding == "gzip":
        return gzip.decompress(payload)
    if encoding == "deflate":
        return zlib.decompress(payload)
    return payload


def download_with_retries(url: str, destination: Path, *, min_bytes: int = 1) -> int:
    last_error: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            with _open_url(url, timeout=90) as response, destination.open("wb") as out:
                shutil.copyfileobj(response, out, length=1024 * 1024)
            size = destination.stat().st_size
            if size < min_bytes:
                raise BuildError(f"download suspiciously small: {size:,} bytes from {url}")
            return size
        except (HTTPError, URLError, TimeoutError, OSError, BuildError) as exc:
            last_error = exc
            destination.unlink(missing_ok=True)
            if attempt == HTTP_RETRIES - 1:
                break
            time.sleep(_retry_delay(exc, attempt))
    raise BuildError(f"failed to download {url}: {last_error}")


def _category_matches(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def parse_curlie_archive(archive_path: Path, roots: Sequence[str] = CURLIE_ROOTS) -> tuple[set[str], dict[str, int]]:
    category_ids: set[str] = set()
    root_matches = {root: 0 for root in roots}
    try:
        tar = tarfile.open(archive_path, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BuildError(f"Curlie archive is malformed: {exc}") from exc
    with tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        category_members = [m for m in members if m.name.endswith("-s.tsv")]
        site_members = [m for m in members if m.name.endswith("-c.tsv")]
        if not category_members or not site_members:
            raise BuildError("Curlie archive lacks expected *-s.tsv / *-c.tsv files")
        for member in category_members:
            fileobj = tar.extractfile(member)
            if fileobj is None:
                continue
            text = io.TextIOWrapper(fileobj, encoding="utf-8", errors="strict", newline="")
            try:
                for row in csv.reader(text, delimiter="\t"):
                    if len(row) < 2:
                        continue
                    category_id, category_path = row[0].strip(), row[1].strip()
                    for root in roots:
                        if _category_matches(category_path, root):
                            category_ids.add(category_id)
                            root_matches[root] += 1
            except UnicodeDecodeError as exc:
                raise BuildError(f"Curlie category TSV is not valid UTF-8: {member.name}") from exc
        missing_roots = [root for root, count in root_matches.items() if count == 0]
        if missing_roots:
            raise BuildError("Curlie category roots not found: " + ", ".join(missing_roots))
        domains: set[str] = set()
        selected_rows = 0
        invalid_rows = 0
        for member in site_members:
            fileobj = tar.extractfile(member)
            if fileobj is None:
                continue
            text = io.TextIOWrapper(fileobj, encoding="utf-8", errors="strict", newline="")
            try:
                for row in csv.reader(text, delimiter="\t"):
                    if len(row) < 4 or row[-1].strip() not in category_ids:
                        continue
                    selected_rows += 1
                    domain = normalize_hostname(row[0])
                    if domain is None:
                        invalid_rows += 1
                    else:
                        domains.add(domain)
            except UnicodeDecodeError as exc:
                raise BuildError(f"Curlie site TSV is not valid UTF-8: {member.name}") from exc
    if selected_rows == 0:
        raise BuildError("Curlie Shopping trees contained no site rows")
    if invalid_rows > max(100, int(selected_rows * 0.05)):
        raise BuildError(f"Curlie had suspiciously many malformed site URLs: {invalid_rows:,}/{selected_rows:,}")
    return domains, root_matches


def fetch_curlie() -> tuple[set[str], dict[str, int]]:
    with tempfile.TemporaryDirectory(prefix="curlie-") as tmp:
        archive = Path(tmp) / "curlie-rdf-all.tar.gz"
        download_with_retries(CURLIE_URL, archive, min_bytes=MIN_CURLIE_ARCHIVE_BYTES)
        domains, roots = parse_curlie_archive(archive)
    if len(domains) < MIN_CURLIE_DOMAINS:
        raise BuildError(f"Curlie source suspiciously small: {len(domains):,} domains; minimum is {MIN_CURLIE_DOMAINS:,}")
    return domains, roots


def parse_ut1_archive(archive_path: Path) -> set[str]:
    try:
        tar = tarfile.open(archive_path, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BuildError(f"UT1 archive is malformed: {exc}") from exc
    domains: set[str] = set()
    records = 0
    invalid = 0
    found_domains = False
    found_urls = False
    with tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            basename = Path(member.name).name
            if basename not in {"domains", "urls"}:
                continue
            if basename == "domains":
                found_domains = True
            else:
                found_urls = True
            fileobj = tar.extractfile(member)
            if fileobj is None:
                continue
            try:
                text = io.TextIOWrapper(fileobj, encoding="utf-8", errors="strict")
                for line in text:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    records += 1
                    domain = normalize_hostname(value)
                    if domain is None:
                        invalid += 1
                    else:
                        domains.add(domain)
            except UnicodeDecodeError as exc:
                raise BuildError(f"UT1 {basename} file is not valid UTF-8") from exc
    if not found_domains or not found_urls:
        raise BuildError("UT1 shopping archive lacks expected domains and urls files")
    if records == 0:
        raise BuildError("UT1 shopping archive contained no records")
    if invalid > max(100, int(records * 0.10)):
        raise BuildError(f"UT1 had suspiciously many malformed records: {invalid:,}/{records:,}")
    return domains


def fetch_ut1() -> set[str]:
    with tempfile.TemporaryDirectory(prefix="ut1-") as tmp:
        archive = Path(tmp) / "shopping.tar.gz"
        download_with_retries(UT1_URL, archive, min_bytes=MIN_UT1_ARCHIVE_BYTES)
        domains = parse_ut1_archive(archive)
    if len(domains) < MIN_UT1_DOMAINS:
        raise BuildError(f"UT1 source suspiciously small: {len(domains):,} domains; minimum is {MIN_UT1_DOMAINS:,}")
    return domains


def wdqs_json(query: str) -> dict:
    url = WDQS_URL + "?" + urlencode({"query": query, "format": "json"})
    last_error: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            with _open_url(url, accept="application/sparql-results+json", compressed=True) as response:
                payload = _read_response_body(response)
            data = json.loads(payload)
            if not isinstance(data, dict) or "results" not in data:
                raise BuildError("WDQS returned malformed JSON results")
            return data
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, BuildError) as exc:
            last_error = exc
            if attempt == HTTP_RETRIES - 1:
                break
            time.sleep(_retry_delay(exc, attempt))
    raise BuildError(f"WDQS request failed after retries: {last_error}")


def _qid_from_uri(uri: str) -> str | None:
    value = uri.rsplit("/", 1)[-1]
    return value if re.fullmatch(r"Q[1-9][0-9]*", value) else None


def discover_wikidata_classes(root_qid: str) -> set[str]:
    query = f"""
PREFIX wd: <http://www.wikidata.org/entity/>
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
SELECT DISTINCT ?class WHERE {{
  {{ BIND(wd:{root_qid} AS ?class) }}
  UNION {{ ?class wdt:P279+ wd:{root_qid} . }}
}}
"""
    data = wdqs_json(query)
    classes = {qid for binding in data["results"].get("bindings", []) if (qid := _qid_from_uri(binding.get("class", {}).get("value", "")))}
    classes.add(root_qid)
    return classes


def chunks(values: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


def fetch_wikidata() -> set[str]:
    classes: set[str] = set()
    for root in WIKIDATA_ROOT_CLASSES:
        classes.update(discover_wikidata_classes(root))
    if not classes:
        raise BuildError("Wikidata class discovery returned no classes")
    domains: set[str] = set()
    for batch in chunks(sorted(classes), 25):
        values = " ".join(f"wd:{qid}" for qid in batch)
        query = f"""
PREFIX wd: <http://www.wikidata.org/entity/>
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
SELECT DISTINCT ?item ?website WHERE {{
  VALUES ?class {{ {values} }}
  ?item wdt:P31 ?class .
  {{ ?item wdt:P856 ?website . }}
  UNION
  {{ ?item wdt:P10225 ?website . }}
}}
"""
        data = wdqs_json(query)
        for binding in data["results"].get("bindings", []):
            domain = normalize_hostname(binding.get("website", {}).get("value", ""))
            if domain:
                domains.add(domain)
    if len(domains) < MIN_WIKIDATA_DOMAINS:
        raise BuildError(f"Wikidata source suspiciously small: {len(domains):,} domains; minimum is {MIN_WIKIDATA_DOMAINS:,}")
    return domains


def guard_drop(name: str, previous: set[str], current: set[str], *, max_drop: float = MAX_DROP_FRACTION) -> None:
    if not previous or len(previous) < 50:
        return
    minimum = int(len(previous) * (1.0 - max_drop))
    if len(current) < minimum:
        drop = 100.0 * (len(previous) - len(current)) / len(previous)
        raise BuildError(f"{name} dropped {drop:.1f}% ({len(previous):,} -> {len(current):,}); refusing to replace last known-good data")


def validate_domains(domains: Iterable[str]) -> list[str]:
    values = list(domains)
    if values != sorted(values):
        raise BuildError("output is not sorted")
    if len(values) != len(set(values)):
        raise BuildError("output contains duplicates")
    invalid = [d for d in values if normalize_hostname(d) != d]
    if invalid:
        raise BuildError(f"output contains invalid domains, e.g. {invalid[:3]}")
    return values


def validate_file(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise BuildError("blocklist is empty")
    validate_domains(lines)
    return len(lines)


def build(output_dir: Path, previous_file: Path, previous_sources: Path, manual_file: Path, exceptions_file: Path) -> Stats:
    output_dir.mkdir(parents=True, exist_ok=True)
    manual = read_domain_file(manual_file, strict=True)
    exceptions = read_domain_file(exceptions_file, strict=True)
    if len(manual) < MIN_MANUAL_DOMAINS:
        raise BuildError(f"manual source has only {len(manual)} domains; minimum is {MIN_MANUAL_DOMAINS}")
    curlie, root_matches = fetch_curlie()
    ut1 = fetch_ut1()
    wikidata = fetch_wikidata()
    previous_curlie = read_domain_file(previous_sources / "curlie.txt")
    previous_ut1 = read_domain_file(previous_sources / "ut1.txt")
    previous_wikidata = read_domain_file(previous_sources / "wikidata.txt")
    previous_final = read_domain_file(previous_file)
    guard_drop("Curlie", previous_curlie, curlie)
    guard_drop("UT1", previous_ut1, ut1)
    guard_drop("Wikidata", previous_wikidata, wikidata)
    source_total = len(curlie) + len(ut1) + len(wikidata) + len(manual)
    merged = curlie | ut1 | wikidata | manual
    duplicates = source_total - len(merged)
    applied_exceptions = merged & exceptions
    final = merged - exceptions
    guard_drop("final blocklist", previous_final, final)
    if len(final) < MIN_CURLIE_DOMAINS:
        raise BuildError(f"final blocklist suspiciously small: {len(final):,}")
    ordered_final = sorted(final)
    validate_domains(ordered_final)
    write_domains(output_dir / "curlie.txt", curlie)
    write_domains(output_dir / "ut1.txt", ut1)
    write_domains(output_dir / "wikidata.txt", wikidata)
    write_domains(output_dir / "shopping.txt", ordered_final)
    previous_count = len(previous_final)
    difference = len(final) - previous_count
    difference_percent = None if previous_count == 0 else (difference / previous_count) * 100.0
    stats = Stats(len(curlie), len(ut1), len(wikidata), len(manual), duplicates, len(exceptions), len(applied_exceptions), len(final), previous_count, difference, difference_percent)
    metadata = asdict(stats)
    metadata["curlie_category_matches"] = root_matches
    (output_dir / "stats.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return stats


def print_summary(stats_path: Path) -> None:
    data = json.loads(stats_path.read_text(encoding="utf-8"))
    diff_pct = data.get("difference_percent")
    diff_text = f"{data['difference']:+,}"
    if diff_pct is not None:
        diff_text += f" ({diff_pct:+.2f}%)"
    print("## Shopping blocklist update\n")
    print("| Metric | Count |\n|---|---:|")
    print(f"| Curlie domains | {data['curlie_domains']:,} |")
    print(f"| UT1 domains | {data['ut1_domains']:,} |")
    print(f"| Wikidata domains | {data['wikidata_domains']:,} |")
    print(f"| Manual domains | {data['manual_domains']:,} |")
    print(f"| Duplicates removed | {data['duplicates']:,} |")
    print(f"| Exceptions applied | {data['exceptions_applied']:,} |")
    print(f"| Final domains | {data['final_domains']:,} |")
    print(f"| Difference from previous | {diff_text} |\n")
    print("### Curlie category-tree matches")
    for root, count in sorted(data.get("curlie_category_matches", {}).items()):
        print(f"- `{root}`: {count:,} categories")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_p = sub.add_parser("build")
    build_p.add_argument("--output-dir", type=Path, required=True)
    build_p.add_argument("--previous", type=Path, default=Path("blocklists/shopping.txt"))
    build_p.add_argument("--previous-sources", type=Path, default=Path("sources"))
    build_p.add_argument("--manual", type=Path, default=Path("manual-blocks.txt"))
    build_p.add_argument("--exceptions", type=Path, default=Path("exceptions.txt"))
    validate_p = sub.add_parser("validate")
    validate_p.add_argument("path", type=Path)
    summary_p = sub.add_parser("summary")
    summary_p.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if args.command == "build":
            print(json.dumps(asdict(build(args.output_dir, args.previous, args.previous_sources, args.manual, args.exceptions)), indent=2, sort_keys=True))
        elif args.command == "validate":
            print(f"validated {validate_file(args.path):,} domains")
        elif args.command == "summary":
            print_summary(args.path)
        return 0
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
