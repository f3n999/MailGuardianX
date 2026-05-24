-- Initialisation des bases de données PostgreSQL
-- Exécuté UNE SEULE FOIS au premier démarrage du conteneur postgres.
--
-- Les tables applicatives (scan_sessions, email_analyses, ...) sont
-- créées par Alembic au démarrage de l'orchestrateur.

-- Base CAPE (séparée, gérée par CAPE lui-même)
CREATE DATABASE cape_db;

-- User orchestrateur — mot de passe fixé via init plus tard
-- (le password vient de Docker Secrets, pas en dur ici)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'orchestrator_user') THEN
        -- Mot de passe placeholder — DOIT être changé par ALTER USER au déploiement
        CREATE USER orchestrator_user WITH PASSWORD 'CHANGE_ME_VIA_ALTER_USER';
    END IF;
END
$$;

-- User CAPE
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cape_user') THEN
        CREATE USER cape_user WITH PASSWORD 'CHANGE_ME_VIA_ALTER_USER';
    END IF;
END
$$;

-- Privilèges sur les bases
-- (orchestrator_db est créée par POSTGRES_DB env var)
GRANT ALL PRIVILEGES ON DATABASE orchestrator_db TO orchestrator_user;
GRANT ALL PRIVILEGES ON DATABASE cape_db TO cape_user;

-- Extensions utiles
\c orchestrator_db
CREATE EXTENSION IF NOT EXISTS "pg_trgm";       -- recherche fuzzy sur threat_name
CREATE EXTENSION IF NOT EXISTS "btree_gin";     -- index composites JSONB
GRANT ALL PRIVILEGES ON SCHEMA public TO orchestrator_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO orchestrator_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO orchestrator_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO orchestrator_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO orchestrator_user;
