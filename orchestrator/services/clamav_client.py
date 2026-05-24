"""
Client ClamAV (clamd) — scan in-memory de pièces jointes.

Utilise la lib `clamd` (synchrone) wrappée en thread pool pour rester
compatible avec l'event loop async.
"""
from __future__ import annotations

import asyncio
import io
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import clamd  # type: ignore
    _CLAMD_AVAILABLE = True
except ImportError:  # pragma: no cover
    clamd = None  # type: ignore
    _CLAMD_AVAILABLE = False
    logger.warning("clamd non installé — client ClamAV désactivé")


@dataclass
class ClamAVResult:
    """Résultat d'un scan ClamAV."""
    infected: bool
    signature: Optional[str] = None
    status: str = "OK"          # OK, FOUND, ERROR
    error: Optional[str] = None

    @property
    def score(self) -> float:
        """Score normalisé : 1.0 si infecté, 0.0 sinon."""
        return 1.0 if self.infected else 0.0


class ClamAVClient:
    """Client async pour clamd via TCP ou socket Unix."""

    def __init__(
        self,
        host: str = "clamav",
        port: int = 3310,
        unix_socket: Optional[str] = None,
        timeout: int = 30,
        max_file_size: int = 100 * 1024 * 1024,
        enabled: bool = True,
    ):
        self.host = host
        self.port = port
        self.unix_socket = unix_socket
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.enabled = enabled and _CLAMD_AVAILABLE
        self._client: Optional[object] = None

    def _make_client(self):
        """Construit un client clamd (synchrone)."""
        if self.unix_socket:
            return clamd.ClamdUnixSocket(  # type: ignore[union-attr]
                path=self.unix_socket, timeout=self.timeout
            )
        return clamd.ClamdNetworkSocket(  # type: ignore[union-attr]
            host=self.host, port=self.port, timeout=self.timeout
        )

    async def scan_bytes(self, data: bytes) -> ClamAVResult:
        """Scan asynchrone d'un buffer en mémoire."""
        if not self.enabled:
            return ClamAVResult(infected=False, status="DISABLED")
        if not data:
            return ClamAVResult(infected=False, status="EMPTY")
        if len(data) > self.max_file_size:
            return ClamAVResult(
                infected=False,
                status="ERROR",
                error=f"file too large ({len(data)} > {self.max_file_size})",
            )

        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(None, self._scan_sync, data)
        except Exception as exc:  # noqa: BLE001
            logger.error("ClamAV scan exception : %s", exc)
            return ClamAVResult(infected=False, status="ERROR", error=str(exc))

        return self._parse_response(raw)

    def _scan_sync(self, data: bytes):
        """Appel synchrone à clamd (depuis thread pool)."""
        client = self._make_client()
        return client.instream(io.BytesIO(data))  # type: ignore[union-attr]

    def _parse_response(self, raw: dict) -> ClamAVResult:
        """
        Parse la réponse clamd. Format :
          {"stream": ("OK", None)}                 -> sain
          {"stream": ("FOUND", "Eicar-Test-Signature")}
          {"stream": ("ERROR", "message")}
        """
        if not raw or "stream" not in raw:
            return ClamAVResult(infected=False, status="UNKNOWN", error="empty response")

        status, signature = raw["stream"]
        status_upper = (status or "").upper()

        if status_upper == "FOUND":
            return ClamAVResult(infected=True, signature=signature, status="FOUND")
        if status_upper == "OK":
            return ClamAVResult(infected=False, status="OK")
        return ClamAVResult(
            infected=False, status="ERROR", error=str(signature or "unknown clamd error")
        )

    async def health_check(self) -> bool:
        """Vérifie que clamd répond (PING)."""
        if not self.enabled:
            return False
        loop = asyncio.get_running_loop()
        try:
            ok = await loop.run_in_executor(None, self._ping_sync)
            return ok
        except Exception as exc:  # noqa: BLE001
            logger.warning("ClamAV health_check failed : %s", exc)
            return False

    def _ping_sync(self) -> bool:
        client = self._make_client()
        try:
            response = client.ping()  # type: ignore[union-attr]
            return str(response).upper() == "PONG"
        except Exception:
            return False

    async def version(self) -> Optional[str]:
        """Version clamd + signatures."""
        if not self.enabled:
            return None
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, self._version_sync)
        except Exception:
            return None

    def _version_sync(self) -> Optional[str]:
        client = self._make_client()
        try:
            return str(client.version())  # type: ignore[union-attr]
        except Exception:
            return None
