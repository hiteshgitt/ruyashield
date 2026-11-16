-- Runtime role used by the app and workers. It is NOT the table owner and has
-- no BYPASSRLS, so row-level security policies always apply to it.
CREATE ROLE ruya_app LOGIN PASSWORD 'ruya_app_dev' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE ruyashield TO ruya_app;
