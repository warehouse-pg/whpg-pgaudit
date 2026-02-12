-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgaudit" to load this file.\quit

CREATE FUNCTION pgaudit_sql_drop()
	RETURNS event_trigger
	SECURITY DEFINER
	SET search_path = 'pg_catalog, pg_temp'
	LANGUAGE C
	AS 'MODULE_PATHNAME', 'pgaudit_sql_drop';

CREATE EVENT TRIGGER pgaudit_sql_drop
	ON sql_drop
	EXECUTE PROCEDURE pgaudit_sql_drop();
