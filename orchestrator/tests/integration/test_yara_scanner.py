"""
Tests YARA scanner — vérifient la compilation et le scan en mémoire.
Skip si yara-python n'est pas installé.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.services.yara_scanner import YaraScanner


@pytest.fixture
def temp_yara_rules(tmp_path: Path) -> Path:
    """Crée un fichier YARA temporaire avec une règle simple."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(
        """
rule TestRule_SuspiciousString {
    meta:
        description = "Test rule"
        severity = "high"
        family = "TestFamily"
    strings:
        $a = "MALICIOUS_MARKER_42"
    condition:
        $a
}
""",
        encoding="utf-8",
    )
    return tmp_path


@pytest.mark.asyncio
class TestYaraScanner:
    def test_load_compiles_rules(self, temp_yara_rules):
        scanner = YaraScanner(rules_path=str(temp_yara_rules), enabled=True)
        try:
            count = scanner.load()
        except (RuntimeError, ImportError):
            pytest.skip("yara-python non installé")
        assert count == 1
        assert scanner.health_check() is True

    async def test_scan_match(self, temp_yara_rules):
        scanner = YaraScanner(rules_path=str(temp_yara_rules), enabled=True)
        try:
            scanner.load()
        except (RuntimeError, ImportError):
            pytest.skip("yara-python non installé")

        result = await scanner.scan_bytes(b"some content with MALICIOUS_MARKER_42 inside")
        assert result.matched is True
        assert "TestRule_SuspiciousString" in result.rule_names
        assert result.score >= 0.75

    async def test_scan_no_match(self, temp_yara_rules):
        scanner = YaraScanner(rules_path=str(temp_yara_rules), enabled=True)
        try:
            scanner.load()
        except (RuntimeError, ImportError):
            pytest.skip("yara-python non installé")

        result = await scanner.scan_bytes(b"completely innocent content")
        assert result.matched is False
        assert result.matches == []

    async def test_disabled_returns_no_match(self, temp_yara_rules):
        scanner = YaraScanner(rules_path=str(temp_yara_rules), enabled=False)
        result = await scanner.scan_bytes(b"MALICIOUS_MARKER_42")
        assert result.matched is False
