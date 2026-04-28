"""Payload mutation engine.

Loads payloads from disk, applies WAF evasion transforms, learns from
historical effectiveness via the Memory layer, and yields prioritized
variants for scanners to fire.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Iterable

from .memory import Memory
from .utils import random_token
from .waf_evasion import evade


class PayloadEngine:
    def __init__(self, payload_dir: str | Path, memory: Memory, evasion_techniques: Iterable[str]) -> None:
        self.payload_dir = Path(payload_dir)
        self.memory = memory
        self.evasion_techniques = list(evasion_techniques)
        self._cache: dict[str, list[str]] = {}

    def _load(self, category: str) -> list[str]:
        if category in self._cache:
            return self._cache[category]
        path = self.payload_dir / f"{category}.txt"
        if not path.exists():
            self._cache[category] = []
            return []
        items: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
        self._cache[category] = items
        return items

    def base(self, category: str) -> list[str]:
        return list(self._load(category))

    def for_category(self, category: str, *, limit: int = 40, with_evasion: bool = True) -> list[str]:
        """Return prioritized payloads, optionally expanded with evasion variants.

        Priority order:
          1. payloads with the best historical hit-rate (from memory)
          2. baseline payloads from disk that aren't already in (1)
        Then each is expanded with WAF evasion variants and a unique token is
        substituted for any '{TOKEN}' placeholders so we can correlate hits.
        """
        learned = self.memory.best_payloads(category)
        base = self._load(category)
        ordered: list[str] = []
        seen = set()
        for p in learned + base:
            if p in seen:
                continue
            ordered.append(p)
            seen.add(p)

        out: list[str] = []
        for raw in ordered:
            token = random_token(8)
            seeded = raw.replace("{TOKEN}", token)
            variants = evade(seeded, self.evasion_techniques) if with_evasion else [seeded]
            random.shuffle(variants)
            out.extend(variants)
            if len(out) >= limit:
                break
        return out[:limit]
