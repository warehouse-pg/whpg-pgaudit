\set VERBOSITY terse

-- Create pgaudit extension
CREATE EXTENSION IF NOT EXISTS pgaudit;

--
-- WHPG-specific audit tests
--

SET pgaudit.log = 'DDL, READ';
SET pgaudit.log_client = ON;
SET pgaudit.log_level = 'notice';

-- Setup base table
CREATE TABLE src (id int, data text);
INSERT INTO src VALUES (1, 'one'), (2, 'two');

-- SELECT INTO (rewritten to CTAS internally, is_select_into=true)
SELECT * INTO dst_select_into FROM src;

-- CREATE MATERIALIZED VIEW
CREATE MATERIALIZED VIEW mv_src AS SELECT * FROM src;

-- REFRESH MATERIALIZED VIEW
REFRESH MATERIALIZED VIEW mv_src;

-- CREATE TYPE (composite)
CREATE TYPE comp_type AS (x int, y text);
DROP TYPE comp_type;

-- CREATE TYPE (enum)
CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');
DROP TYPE mood;

-- CREATE RULE (tests pg_rewrite resolution)
CREATE TABLE rule_base (id int);
CREATE VIEW rule_view AS SELECT * FROM rule_base;
CREATE RULE rule_ins AS ON INSERT TO rule_view DO INSTEAD INSERT INTO rule_base VALUES (NEW.id);
DROP RULE rule_ins ON rule_view;
DROP VIEW rule_view;
DROP TABLE rule_base;

-- CREATE CAST (tests pg_cast resolution)
CREATE TYPE casttesttype;
CREATE FUNCTION casttesttype_in(cstring) RETURNS casttesttype AS 'textin' LANGUAGE internal STRICT;
CREATE FUNCTION casttesttype_out(casttesttype) RETURNS cstring AS 'textout' LANGUAGE internal STRICT;
CREATE TYPE casttesttype (internallength = variable, input = casttesttype_in, output = casttesttype_out);
CREATE CAST (text AS casttesttype) WITHOUT FUNCTION;
DROP CAST (text AS casttesttype);
DROP TYPE casttesttype CASCADE;

-- ALTER TABLE/VIEW SET DEFAULT (tests pg_attrdef resolution)
-- The object_access_hook passes objectId=relid, subId=attnum for pg_attrdef
CREATE TABLE attrdef_test (id int, name text);
ALTER TABLE attrdef_test ALTER COLUMN name SET DEFAULT 'test default';
DROP TABLE attrdef_test;

-- Cleanup
DROP MATERIALIZED VIEW mv_src;
DROP TABLE dst_select_into;
DROP TABLE src;

RESET pgaudit.log;
RESET pgaudit.log_client;
RESET pgaudit.log_level;
