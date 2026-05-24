"""
Tâches Celery pour CAPE Sandbox.

Les analyses CAPE prennent 2 à 10 minutes — on ne peut pas tenir une connexion
HTTP ouverte tout ce temps. Le pattern :

  1. Client appelle /api/v1/upload → la route soumet la tâche Celery → retourne 202 + task_id
  2. Worker Celery exécute analyze_with_cape() → stocke le résultat en Redis (backend)
  3. Client poll /api/v1/verdict/{task_id} → lit le résultat depuis Redis
"""
from __future__ import annotations

import asyncio
import base64
import logging
from typing import Optional

from celery import Task

from orchestrator.celery_app import celery_app
from orchestrator.core.config import get_settings
from orchestrator.services.cache import CacheService
from orchestrator.services.cape_client import CAPEClient
from orchestrator.services.clamav_client import ClamAVClient
from orchestrator.services.yara_scanner import YaraScanner
from orchestrator.models.schemas import Verdict

logger = logging.getLogger(__name__)


class CapeTask(Task):
    """Base task — réutilise les clients entre les exécutions du worker."""
    _cape: Optional[CAPEClient] = None
    _yara: Optional[YaraScanner] = None
    _clamav: Optional[ClamAVClient] = None
    _cache: Optional[CacheService] = None

    @property
    def cape(self) -> CAPEClient:
        if self._cape is None:
            s = get_settings()
            self._cape = CAPEClient(
                cape_url=s.cape_api_url,
                api_token=s.cape_api_token,
                timeout=s.cape_timeout,
            )
        return self._cape

    @property
    def yara(self) -> YaraScanner:
        if self._yara is None:
            s = get_settings()
            self._yara = YaraScanner(
                rules_path=s.yara.rules_path,
                enabled=s.yara.enabled,
                timeout=s.yara.timeout,
            )
            try:
                self._yara.load()
            except Exception as exc:  # noqa: BLE001
                logger.warning("YARA load failed in worker : %s", exc)
        return self._yara

    @property
    def clamav(self) -> ClamAVClient:
        if self._clamav is None:
            s = get_settings()
            self._clamav = ClamAVClient(
                host=s.clamav.host,
                port=s.clamav.port,
                unix_socket=s.clamav.unix_socket,
                timeout=s.clamav.timeout,
                enabled=s.clamav.enabled,
            )
        return self._clamav

    @property
    def cache(self) -> CacheService:
        if self._cache is None:
            s = get_settings()
            self._cache = CacheService(redis_url=s.redis_url)
        return self._cache


@celery_app.task(
    bind=True,
    base=CapeTask,
    name="cape.analyze_attachment",
    autoretry_for=(ConnectionError,),
    retry_kwargs={"max_retries": 3, "countdown": 30},
    soft_time_limit=600,
    time_limit=900,
)
def analyze_attachment_task(
    self, sha256: str, filename: str, content_b64: str
) -> dict:
    """
    Tâche d'analyse complète d'une pièce jointe (YARA → ClamAV → CAPE).
    Retourne un dict sérialisable (stocké comme result Celery).
    """
    try:
        content = base64.b64decode(content_b64)
    except Exception as exc:
        logger.error("Décodage base64 échoué : %s", exc)
        return {
            "sha256": sha256, "verdict": Verdict.ERROR.value,
            "error": "invalid base64 payload",
        }

    return asyncio.run(_run_async(self, sha256, filename, content))


async def _run_async(
    task: CapeTask, sha256: str, filename: str, content: bytes
) -> dict:
    """Exécution async (réutilise les clients du worker)."""
    await task.cache.connect()

    # 1) YARA
    if task.yara.enabled and task.yara.health_check():
        y = await task.yara.scan_bytes(content)
        if y.matched and y.score >= 0.90:
            verdict = Verdict.BLOCK
            await task.cache.set_hash_verdict(
                sha256, verdict,
                threat_name=y.threat_name, confidence=y.score,
                source="yara", ttl=86400 * 7,
            )
            return {
                "sha256": sha256, "verdict": verdict.value,
                "confidence": y.score, "threat_name": y.threat_name,
                "signatures": y.rule_names, "source": "yara",
            }

    # 2) ClamAV
    if task.clamav.enabled:
        c = await task.clamav.scan_bytes(content)
        if c.infected:
            verdict = Verdict.BLOCK
            await task.cache.set_hash_verdict(
                sha256, verdict,
                threat_name=f"ClamAV/{c.signature}", confidence=1.0,
                source="clamav", ttl=86400 * 7,
            )
            return {
                "sha256": sha256, "verdict": verdict.value,
                "confidence": 1.0, "threat_name": f"ClamAV/{c.signature}",
                "signatures": [f"clamav:{c.signature}"], "source": "clamav",
            }

    # 3) CAPE Sandbox
    result = await task.cape.analyze_and_verdict(content, filename)
    verdict_obj = result.get("verdict", Verdict.ERROR)
    if not isinstance(verdict_obj, Verdict):
        verdict_obj = Verdict(verdict_obj)
    await task.cache.set_hash_verdict(
        sha256, verdict_obj,
        threat_name=result.get("threat_name"),
        confidence=result.get("confidence", 0.0),
        source="cape", ttl=86400 * 7,
    )
    return {
        "sha256": sha256,
        "verdict": verdict_obj.value,
        "confidence": result.get("confidence", 0.0),
        "cape_score": result.get("cape_score", 0.0),
        "threat_name": result.get("threat_name"),
        "signatures": result.get("signatures_matched", []),
        "cape_task_id": result.get("cape_task_id"),
        "source": "cape",
    }
