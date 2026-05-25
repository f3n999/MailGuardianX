-- ════════════════════════════════════════════════════════════
--  init-db.sql — Initialisation PostgreSQL au premier démarrage.
--  Exécuté UNE SEULE FOIS automatiquement par le container postgres.
--
--  Le superuser "postgres" (POSTGRES_USER_FILE) gère tout.
--  Les tables applicatives sont créées par Alembic (pas ici).
-- ════════════════════════════════════════════════════════════

-- Base CAPE (séparée, gérée par CAPE lui-même)
-- orchestrator_db est créée automatiquement via POSTGRES_DB env var
CREATE DATABASE cape_db;

-- Extensions utiles dans orchestrator_db
\c orchestrator_db
CREATE EXTENSION IF NOT EXISTS "pg_trgm";       -- recherche fuzzy sur threat_name
CREATE EXTENSION IF NOT EXISTS "btree_gin";     -- index composites JSONB + GIN

-- Extensions dans cape_db
\c cape_db
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
