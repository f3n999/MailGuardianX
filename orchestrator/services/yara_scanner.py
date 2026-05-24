"""
Scanner YARA in-memory.

Compile l'ensemble des règles `.yar` / `.yara` du dossier `yara-rules/` au
démarrage, puis fournit `scan_bytes()` async (exécution dans thread pool —
yara-python est synchrone).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import yara  # yara-python
    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover
    yara = None  # type: ignore
    _YARA_AVAILABLE = False
    logger.warning("yara-python non installé — scanner YARA désactivé")


@dataclass
class YaraMatch:
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings_matched: int = 0

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity", "unknown")).lower()


@dataclass
class YaraScanResult:
    matched: bool
    matches: list[YaraMatch] = field(default_factory=list)
    score: float = 0.0          # 0.0–1.0
    threat_name: Optional[str] = None
    error: Optional[str] = None

    @property
    def rule_names(self) -> list[str]:
        return [m.rule for m in self.matches]


class YaraScanner:
    """Scanner YARA — règles compilées une fois, scan multi-threadé."""

    # Pondération par sévérité (déclarée dans meta:)
    SEVERITY_WEIGHTS = {
        "critical": 0.95,
        "high": 0.75,
        "medium": 0.50,
        "low": 0.25,
        "unknown": 0.40,
    }

    def __init__(
        self,
        rules_path: str = "yara-rules",
        enabled: bool = True,
        timeout: int = 60,
    ):
        self.rules_path = Path(rules_path)
        self.enabled = enabled and _YARA_AVAILABLE
        self.timeout = timeout
        self._rules: Optional["yara.Rules"] = None
        self._rule_files: list[Path] = []

    def load(self) -> int:
        """
        Compile les règles. Retourne le nombre de fichiers chargés.
        Lève RuntimeError si la compilation échoue.
        """
        if not self.enabled:
            logger.info("YARA scanner désactivé")
            return 0

        if not self.rules_path.exists():
            logger.warning("Dossier YARA introuvable : %s", self.rules_path)
            return 0

        files = sorted(self.rules_path.rglob("*.yar")) + sorted(
            self.rules_path.rglob("*.yara")
        )
        if not files:
            logger.warning("Aucun fichier .yar trouvé dans %s", self.rules_path)
            return 0

        filepaths = {f"rule_{i}": str(p) for i, p in enumerate(files)}
        try:
            self._rules = yara.compile(filepaths=filepaths)  # type: ignore[union-attr]
        except yara.SyntaxError as exc:  # type: ignore[union-attr]
            logger.error("YARA syntax error : %s", exc)
            raise RuntimeError(f"YARA compilation failed: {exc}") from exc

        self._rule_files = files
        logger.info("YARA : %d fichier(s) compilé(s) — %s", len(files), self.rules_path)
        return len(files)

    async def scan_bytes(self, data: bytes) -> YaraScanResult:
        """Scan asynchrone d'un buffer en mémoire."""
        if not self.enabled or self._rules is None:
            return YaraScanResult(matched=False)
        if not data:
            return YaraScanResult(matched=False)

        loop = asyncio.get_running_loop()
        try:
            raw_matches = await loop.run_in_executor(None, self._scan_sync, data)
        except Exception as exc:  # noqa: BLE001
            logger.error("YARA scan exception : %s", exc)
            return YaraScanResult(matched=False, error=str(exc))

        if not raw_matches:
            return YaraScanResult(matched=False)

        matches = [
            YaraMatch(
                rule=m.rule,
                tags=list(m.tags),
                meta=dict(m.meta),
                strings_matched=len(m.strings),
            )
            for m in raw_matches
        ]

        score = max(self.SEVERITY_WEIGHTS.get(m.severity, 0.4) for m in matches)
        first = matches[0]
        threat_name = first.meta.get("family") or first.meta.get("description") or first.rule

        return YaraScanResult(
            matched=True,
            matches=matches,
            score=round(score, 3),
            threat_name=f"YARA/{threat_name}"[:255],
        )

    def _scan_sync(self, data: bytes):
        """Exécution synchrone (appelée depuis le thread pool)."""
        assert self._rules is not None
        return self._rules.match(data=data, timeout=self.timeout)

    def health_check(self) -> bool:
        return self.enabled and self._rules is not None

    @property
    def rules_count(self) -> int:
        return len(self._rule_files)
