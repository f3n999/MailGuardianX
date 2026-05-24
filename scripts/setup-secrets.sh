#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════
#  setup-secrets.sh — Génère tous les secrets Docker au premier déploiement.
#
#  Usage :
#      ./scripts/setup-secrets.sh
#
#  Idempotent : ne réécrit pas un secret déjà présent.
# ════════════════════════════════════════════════════════════
set -euo pipefail

SECRETS_DIR="$(dirname "$0")/../secrets"
mkdir -p "$SECRETS_DIR"
cd "$SECRETS_DIR"

write_if_missing() {
    local name="$1" value="$2"
    if [[ -f "${name}.txt" ]]; then
        echo "  [skip] ${name}.txt existe déjà"
        return
    fi
    printf "%s" "$value" > "${name}.txt"
    chmod 600 "${name}.txt"
    echo "  [new ] ${name}.txt généré"
}

gen_random() {
    openssl rand -base64 48 | tr -d '\n' | tr -d '=' | tr '/+' '_-'
}

echo "── Génération des secrets MailGuardianX ──"

# Secrets aléatoires
write_if_missing "secret_key"            "$(gen_random)"
write_if_missing "api_key_pepper"        "$(gen_random)"
write_if_missing "postgres_password"     "$(gen_random)"
write_if_missing "mysql_root_password"   "$(gen_random)"
write_if_missing "mysql_misp_password"   "$(gen_random)"
write_if_missing "redis_password"        "$(gen_random)"
write_if_missing "grafana_password"      "$(openssl rand -base64 24 | tr -d '\n')"
write_if_missing "misp_admin_passphrase" "$(gen_random)"

# Valeurs fixes
write_if_missing "postgres_user"      "postgres"
write_if_missing "misp_admin_email"   "admin@mailguardianx.local"

# DB URLs (composées à partir des passwords générés)
PG_PASS="$(cat postgres_password.txt)"
write_if_missing "database_url" \
    "postgresql+asyncpg://orchestrator_user:${PG_PASS}@postgres:5432/orchestrator_db"
write_if_missing "cape_db_url" \
    "postgresql://cape_user:${PG_PASS}@postgres:5432/cape_db"

# Placeholders à remplir manuellement
write_if_missing "azure_tenant_id"      "FILL_WITH_AZURE_TENANT_ID"
write_if_missing "azure_client_id"      "FILL_WITH_AZURE_CLIENT_ID"
write_if_missing "azure_client_secret"  "FILL_WITH_AZURE_CLIENT_SECRET"
write_if_missing "cape_api_token"       "GENERATED_AT_FIRST_RUN"
write_if_missing "misp_api_key"         "GENERATED_AT_FIRST_RUN"

echo
echo "✅ Secrets prêts dans $SECRETS_DIR"
echo
echo "Étapes restantes :"
echo "  1. Remplir azure_tenant_id.txt / azure_client_id.txt / azure_client_secret.txt"
echo "  2. Démarrer la stack : docker compose up -d"
echo "  3. Récupérer le CAPE API token après boot CAPE → mettre à jour cape_api_token.txt"
echo "  4. Récupérer la MISP API key depuis l'UI MISP → misp_api_key.txt"
echo "  5. Restart orchestrator : docker compose restart orchestrator celery-worker"
