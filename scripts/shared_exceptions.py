#!/usr/bin/env python3
"""Shared exact/suffix exception parsing for generated Pi-hole lists."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Exceptions:
    exact: frozenset[str]
    suffix: frozenset[str]

    @property
    def configured(self) -> int:
        return len(self.exact) + len(self.suffix)


def read_exceptions(path: Path, normalize: Callable[[str], str | None], error_type: type[Exception]) -> Exceptions:
    exact: set[str] = set()
    suffix: set[str] = set()
    if not path.exists():
        return Exceptions(frozenset(), frozenset())
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if ":" not in value:
            raise error_type(f"invalid exception in {path} line {lineno}: expected exact: or suffix: prefix")
        mode, raw_domain = value.split(":", 1)
        if mode not in {"exact", "suffix"}:
            raise error_type(f"invalid exception mode in {path} line {lineno}: {mode!r}")
        domain = normalize(raw_domain)
        if not domain:
            raise error_type(f"invalid exception hostname in {path} line {lineno}: {raw_domain!r}")
        (exact if mode == "exact" else suffix).add(domain)
    return Exceptions(frozenset(exact), frozenset(suffix))


def is_excluded(domain: str, exceptions: Exceptions) -> bool:
    if domain in exceptions.exact:
        return True
    return any(domain == root or domain.endswith("." + root) for root in exceptions.suffix)


def apply_exceptions(domains: set[str], exceptions: Exceptions) -> tuple[set[str], int]:
    removed = {domain for domain in domains if is_excluded(domain, exceptions)}
    return domains - removed, len(removed)
