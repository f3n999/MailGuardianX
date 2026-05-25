"""
Configuration centralisée — MailGuardianX Orchestrator.

Lecture en cascade :
1. Docker Secrets montés dans /run/secrets/<name>     (prioritaire)
2. Variables d'environnement                          (fallback)
3. Fichier .env                                       (dev local)
4. Valeurs par défaut                                 (dernier recours)

AUCUN secret en dur. AUCUN secret dans les images Docker.
"""
from pathlib import Path
from functools import lru_cache
from typing import Optional, Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SECRETS_DIR = Path("/run/secrets")


def _read_secret_file(name: str) -> Optional[str]:
    """Lit un secret Docker depuis /run/secrets/<name>. None si absent."""
    p = SECRETS_DIR / name
    if p.is_file():
        try:
            return p.read_text(encoding="utf-8").strip()
        except OSError:
            return None
    return None


def _resolve(env_value: Optional[str], secret_name: str) -> Optional[str]:
    """
    Résout une valeur : Docker Secret prioritaire, sinon valeur env/.env.
    Permet de basculer dev (env vars) → prod (secrets) sans changer le code.
    """
    secret = _read_secret_file(secret_name)
    return secret if secret else env_value


# ============================================================
# Sous-configurations par domaine
# ============================================================

class AzureSettings(BaseSettings):
    """Application Azure AD (mode app-only Client Credentials)."""
    tenant_id: Optional[str] = Field(default=None, alias="AZURE_TENANT_ID")
    client_id: Optional[str] = Field(default=None, alias="AZURE_CLIENT_ID")
    client_secret: Optional[str] = Field(default=None, alias="AZURE_CLIENT_SECRET")
    graph_scope: str = Field(default="https://graph.microsoft.com/.default")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @model_validator(mode="after")
    def resolve_secrets(self) -> "AzureSettings":
        self.tenant_id = _resolve(self.tenant_id, "azure_tenant_id")
        self.client_id = _resolve(self.client_id, "azure_client_id")
        self.client_secret = _resolve(self.client_secret, "azure_client_secret")
        return self

    @property
    def is_configured(self) -> bool:
        return all([self.tenant_id, self.client_id, self.client_secret])


class ClamAVSettings(BaseSettings):
    """Client clamd (socket Unix ou TCP)."""
    host: str = Field(default="clamav", alias="CLAMAV_HOST")
    port: int = Field(default=3310, alias="CLAMAV_PORT")
    unix_socket: Optional[str] = Field(default=None, alias="CLAMAV_UNIX_SOCKET")
    timeout: int = Field(default=30, alias="CLAMAV_TIMEOUT")
    max_file_size: int = Field(default=100 * 1024 * 1024, alias="CLAMAV_MAX_FILE_SIZE")
    enabled: bool = Field(default=True, alias="CLAMAV_ENABLED")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


class YaraSettings(BaseSettings):
    """Scanner YARA in-memory."""
    rules_path: str = Field(default="yara-rules", alias="YARA_RULES_PATH")
    enabled: bool = Field(default=True, alias="YARA_ENABLED")
    timeout: int = Field(default=60, alias="YARA_TIMEOUT")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


class CelerySettings(BaseSettings):
    """Celery pour tâches longues (analyses CAPE)."""
    broker_url: str = Field(default="redis://redis:6379/1", alias="CELERY_BROKER_URL")
    result_backend: str = Field(default="redis://redis:6379/2", alias="CELERY_RESULT_BACKEND")
    task_time_limit: int = Field(default=900, alias="CELERY_TASK_TIME_LIMIT")  # 15 min
    task_soft_time_limit: int = Field(default=600, alias="CELERY_TASK_SOFT_TIME_LIMIT")  # 10 min

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @model_validator(mode="after")
    def resolve_celery_secrets(self) -> "CelerySettings":
        """Lit les URLs Redis depuis Docker Secrets si disponibles."""
        self.broker_url = _resolve(self.broker_url, "celery_broker_url")
        self.result_backend = _resolve(self.result_backend, "celery_result_backend")
        return self


class ScheduleSettings(BaseSettings):
    """Scheduler de scan automatique Graph API."""
    enabled: bool = Field(default=False, alias="SCHEDULE_ENABLED")
    interval_minutes: int = Field(default=15, alias="SCHEDULE_INTERVAL_MINUTES")
    emails_per_user: int = Field(default=25, alias="SCHEDULE_EMAILS_PER_USER")
    max_users_per_scan: int = Field(default=500, alias="SCHEDULE_MAX_USERS")
    differential: bool = Field(default=True, alias="SCHEDULE_DIFFERENTIAL")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


# ============================================================
# Configuration principale (agrège les domaines)
# ============================================================

class Settings(BaseSettings):
    """Configuration globale orchestrateur."""

    # --- API ---
    app_name: str = "MailGuardianX Orchestrator"
    app_version: str = "2.0.0"
    debug: bool = Field(default=False, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    secret_key: Optional[str] = Field(default=None, alias="SECRET_KEY")
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["https://dashboard.mailguardianx.local"],
        alias="ALLOWED_ORIGINS",
    )

    # --- Database ---
    database_url: Optional[str] = Field(default=None, alias="DATABASE_URL")

    # --- Redis ---
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    cache_ttl_known_hash: int = 86400      # 24h
    cache_ttl_verdict: int = 3600          # 1h

    # --- CAPE Sandbox ---
    cape_api_url: str = Field(default="http://cape:8000", alias="CAPE_API_URL")
    cape_api_token: Optional[str] = Field(default=None, alias="CAPE_API_TOKEN")
    cape_timeout: int = Field(default=300, alias="CAPE_TIMEOUT")
    cape_poll_interval: int = Field(default=10, alias="CAPE_POLL_INTERVAL")
    cape_max_file_size: int = Field(default=50 * 1024 * 1024, alias="CAPE_MAX_FILE_SIZE")

    # --- MISP ---
    misp_url: str = Field(default="http://misp:80", alias="MISP_URL")
    misp_api_key: Optional[str] = Field(default=None, alias="MISP_API_KEY")
    misp_verify_ssl: bool = Field(default=False, alias="MISP_VERIFY_SSL")

    # --- Scoring ---
    score_threshold_allow: float = Field(default=0.3, alias="SCORE_THRESHOLD_ALLOW")
    score_threshold_suspect: float = Field(default=0.6, alias="SCORE_THRESHOLD_SUSPECT")
    score_threshold_block: float = Field(default=0.8, alias="SCORE_THRESHOLD_BLOCK")
    max_analysis_time: int = Field(default=600, alias="MAX_ANALYSIS_TIME")

    # --- Auth ---
    api_key_pepper: Optional[str] = Field(default=None, alias="API_KEY_PEPPER")
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60

    # --- Sub-configurations ---
    azure: AzureSettings = Field(default_factory=AzureSettings)
    clamav: ClamAVSettings = Field(default_factory=ClamAVSettings)
    yara: YaraSettings = Field(default_factory=YaraSettings)
    celery: CelerySettings = Field(default_factory=CelerySettings)
    schedule: ScheduleSettings = Field(default_factory=ScheduleSettings)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Validators & secret resolution ---

    @model_validator(mode="after")
    def resolve_top_level_secrets(self) -> "Settings":
        """Lit les secrets Docker prioritairement sur les env vars."""
        self.secret_key = _resolve(self.secret_key, "secret_key")
        self.database_url = _resolve(self.database_url, "database_url")
        self.cape_api_token = _resolve(self.cape_api_token, "cape_api_token")
        self.misp_api_key = _resolve(self.misp_api_key, "misp_api_key")
        self.api_key_pepper = _resolve(self.api_key_pepper, "api_key_pepper")
        # Redis URL (inclut le mot de passe — généré par setup-secrets.sh)
        self.redis_url = _resolve(self.redis_url, "redis_url")
        return self

    @field_validator("database_url")
    @classmethod
    def validate_db_url(cls, v: Optional[str]) -> Optional[str]:
        if v and ("SecurePass123" in v or "CHANGE" in v.upper()):
            raise ValueError(
                "Mot de passe par défaut détecté dans DATABASE_URL — "
                "configurer un vrai secret avant démarrage."
            )
        return v

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: Any) -> list[str]:
        """Accepte une liste JSON ou une string virgule-séparée."""
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                import json
                return json.loads(v)
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    def validate_runtime(self) -> list[str]:
        """
        Vérifie la cohérence runtime (appelée au startup).
        Retourne une liste d'avertissements non-bloquants.
        """
        warnings = []
        if not self.secret_key:
            raise ValueError("SECRET_KEY est obligatoire (env var ou docker secret).")
        if not self.database_url:
            raise ValueError("DATABASE_URL est obligatoire.")
        if self.schedule.enabled and not self.azure.is_configured:
            warnings.append(
                "SCHEDULE_ENABLED=true mais Azure AD non configuré — scheduler désactivé."
            )
            self.schedule.enabled = False
        if self.clamav.enabled and not (self.clamav.host or self.clamav.unix_socket):
            warnings.append("CLAMAV_ENABLED=true sans host/socket — désactivation.")
            self.clamav.enabled = False
        return warnings


@lru_cache()
def get_settings() -> Settings:
    """Singleton de configuration."""
    return Settings()
