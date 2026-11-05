-- TASK-016 prerequisite only; application tables/history come from Django migrate.
-- Target: vdemkykykybnxlixondr. Apply only after authenticated target inventory.
-- New names deliberately fail on collision; never adopt an existing namespace.
BEGIN;
CREATE ROLE kapit_m1_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT kapit_m1_app TO CURRENT_USER;
CREATE SCHEMA kapit_m1 AUTHORIZATION kapit_m1_app;
REVOKE ALL ON SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role;
-- Role-owned defaults, without IN SCHEMA, also remove PostgreSQL's global
-- PUBLIC function/type defaults. A per-schema REVOKE cannot undo those.
ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app REVOKE ALL ON TYPES FROM PUBLIC, anon, authenticated, service_role;
COMMIT;
-- Activate this dedicated LOGIN and its password through the authorized
-- administrator's private credential workflow; no password belongs in this file.
