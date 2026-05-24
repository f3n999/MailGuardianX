# Secrets MailGuardianX

Ce dossier contient les **fichiers de secrets Docker** montés dans les conteneurs sous `/run/secrets/<nom>`.

**⚠️ Aucun fichier de ce dossier ne doit être committé.** Le `.gitignore` les exclut.

---

## Liste des secrets requis

| Fichier | Contenu | Génération |
|--------|---------|-----------|
| `secret_key.txt` | Clé SECRET_KEY (JWT/sessions) | `python -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `database_url.txt` | URL PostgreSQL complète | `postgresql+asyncpg://orchestrator_user:PASS@postgres:5432/orchestrator_db` |
| `cape_api_token.txt` | Token API CAPE | Généré par CAPE au premier démarrage |
| `cape_db_url.txt` | URL PostgreSQL CAPE | `postgresql://cape_user:PASS@postgres:5432/cape_db` |
| `misp_api_key.txt` | Clé d'automation MISP | UI MISP → Administration → Auth keys |
| `misp_admin_email.txt` | Email admin MISP | `admin@mailguardianx.local` |
| `misp_admin_passphrase.txt` | Passphrase initiale MISP | `openssl rand -base64 32` |
| `api_key_pepper.txt` | Pepper bcrypt API keys | `openssl rand -base64 64` |
| `azure_tenant_id.txt` | Tenant ID Azure AD | Portail Azure → AAD → Overview |
| `azure_client_id.txt` | Application (client) ID | App registration |
| `azure_client_secret.txt` | Client secret (app-only) | App registration → Certificates & secrets |
| `postgres_user.txt` | User Postgres | `postgres` |
| `postgres_password.txt` | Password Postgres | `openssl rand -base64 32` |
| `mysql_root_password.txt` | Root password MySQL | `openssl rand -base64 32` |
| `mysql_misp_password.txt` | Password user `misp` MySQL | `openssl rand -base64 32` |
| `redis_password.txt` | Password Redis | `openssl rand -base64 32` |
| `grafana_password.txt` | Admin Grafana | `openssl rand -base64 24` |

---

## Création rapide

```bash
mkdir -p secrets
cd secrets

# Secrets aléatoires
for name in secret_key api_key_pepper postgres_password mysql_root_password \
            mysql_misp_password redis_password grafana_password \
            misp_admin_passphrase; do
    openssl rand -base64 48 > "${name}.txt"
done

# Valeurs fixes (à éditer selon ton environnement)
echo "postgres" > postgres_user.txt
echo "admin@mailguardianx.local" > misp_admin_email.txt

# DB URLs (à reformer après génération des passwords)
PG_PASS=$(cat postgres_password.txt)
echo "postgresql+asyncpg://orchestrator_user:${PG_PASS}@postgres:5432/orchestrator_db" > database_url.txt
echo "postgresql://cape_user:${PG_PASS}@postgres:5432/cape_db" > cape_db_url.txt

# Secrets Azure (à remplir manuellement)
echo "REMPLIR_AVEC_TENANT_ID" > azure_tenant_id.txt
echo "REMPLIR_AVEC_CLIENT_ID" > azure_client_id.txt
echo "REMPLIR_AVEC_CLIENT_SECRET" > azure_client_secret.txt

# CAPE + MISP (à récupérer après premier boot)
echo "GENERATED_AT_FIRST_RUN" > cape_api_token.txt
echo "GENERATED_AT_FIRST_RUN" > misp_api_key.txt

# Permissions strictes
chmod 600 *.txt
```

---

## Rotation des secrets

1. Générer la nouvelle valeur.
2. Écrire dans le fichier `<nom>.txt`.
3. Restart du service concerné : `docker compose restart <service>`.
4. Pour les API keys MailGuardianX : `DELETE /api/v1/admin/keys/<id>` puis recréer.
