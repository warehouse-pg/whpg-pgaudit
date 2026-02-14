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

-- Cleanup
DROP MATERIALIZED VIEW mv_src;
DROP TABLE dst_select_into;
DROP TABLE src;

RESET pgaudit.log;
RESET pgaudit.log_client;
RESET pgaudit.log_level;
