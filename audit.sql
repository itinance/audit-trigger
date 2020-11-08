-- An audit history is important on most tables. Provide an audit trigger that logs to
-- a dedicated audit table for the major relations.
--
-- This file should be generic and not depend on application roles or structures,
-- as it's being listed here:
--
--    https://wiki.postgresql.org/wiki/Audit_trigger_91plus    
--
-- This trigger was originally based on
--   http://wiki.postgresql.org/wiki/Audit_trigger
-- but has been completely rewritten.
--
-- Should really be converted into a relocatable EXTENSION, with control and upgrade files.



CREATE EXTENSION IF NOT EXISTS hstore;

CREATE SCHEMA audit;
REVOKE ALL ON SCHEMA audit FROM public;

COMMENT ON SCHEMA audit IS 'Out-of-table audit/history logging tables and trigger functions';

--
-- Table logged_schemas
--

CREATE SEQUENCE audit.seq_logged_schemas;
CREATE TABLE audit.logged_schemas (
    id smallint NOT NULL PRIMARY KEY DEFAULT nextval('audit.seq_logged_schemas'),
    name TEXT NOT NULL UNIQUE,
    creation_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER SEQUENCE audit.seq_logged_schemas OWNED BY audit.logged_schemas.id;
CREATE INDEX "idx_logged_schemas_name" ON audit.logged_schemas ("name");
CREATE INDEX "idx_logged_schemas_creation_date" ON audit.logged_schemas ("creation_date");

--
-- Table logged_tables
--

CREATE SEQUENCE audit.seq_logged_tables;
CREATE TABLE audit.logged_tables (
    id smallint NOT NULL PRIMARY KEY DEFAULT nextval('audit.seq_logged_tables'),
    name TEXT NOT NULL UNIQUE,
    creation_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER SEQUENCE audit.seq_logged_tables OWNED BY audit.logged_tables.id;
CREATE INDEX "idx_logged_tables_name" ON audit.logged_tables ("name");
CREATE INDEX "idx_logged_tables_creation_date" ON audit.logged_tables ("creation_date");

--
-- Table logged_applications
--

CREATE SEQUENCE audit.seq_logged_applications;
CREATE TABLE audit.logged_applications (
    id smallint NOT NULL PRIMARY KEY DEFAULT nextval('audit.seq_logged_applications'),
    name TEXT NOT NULL UNIQUE,
    creation_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER SEQUENCE audit.seq_logged_applications OWNED BY audit.logged_applications.id;
CREATE INDEX "idx_logged_applications_name" ON audit.logged_applications ("name");
CREATE INDEX "idx_logged_applications_creation_date" ON audit.logged_applications ("creation_date");

--
-- Table logged_users
--

CREATE SEQUENCE audit.seq_logged_users;
CREATE TABLE audit.logged_users (
    id smallint NOT NULL PRIMARY KEY DEFAULT nextval('audit.seq_logged_users'),
    name TEXT NOT NULL UNIQUE,
    creation_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER SEQUENCE audit.seq_logged_users OWNED BY audit.logged_users.id;
CREATE INDEX "idx_logged_users_name" ON audit.logged_users ("name");
CREATE INDEX "idx_logged_users_creation_date" ON audit.logged_users ("creation_date");

--
-- Function getSchemaId
--

CREATE OR REPLACE FUNCTION audit.getSchemaId(_name TEXT) RETURNS SMALLINT AS $$
DECLARE schemaId SMALLINT;
BEGIN
    SELECT INTO schemaId id FROM audit.logged_schemas WHERE name=_name;

    IF schemaId IS NULL THEN
        INSERT INTO audit.logged_schemas (name) VALUES (_name) RETURNING id INTO schemaId;
    END IF;

    RETURN schemaId;
END; $$
LANGUAGE PLPGSQL;
SELECT audit.getSchemaId('public');

--
-- Function getTableId
--

CREATE OR REPLACE FUNCTION audit.getTableId(_name TEXT) RETURNS SMALLINT AS $$
DECLARE tableId SMALLINT;
BEGIN
    SELECT INTO tableId id FROM audit.logged_tables WHERE name=_name;

    IF tableId IS NULL THEN
        INSERT INTO audit.logged_tables (name) VALUES (_name) RETURNING id INTO tableId;
    END IF;

    RETURN tableId;
END; $$
LANGUAGE PLPGSQL;


--
-- Function getApplicationId
--

CREATE OR REPLACE FUNCTION audit.getApplicationId(_name TEXT) RETURNS SMALLINT AS $$
DECLARE applicationId SMALLINT;
BEGIN
    SELECT INTO applicationId id FROM audit.logged_applications WHERE name=_name;

    IF applicationId IS NULL THEN
        INSERT INTO audit.logged_applications (name) VALUES (_name) RETURNING id INTO applicationId;
    END IF;

    RETURN applicationId;
END; $$
LANGUAGE PLPGSQL;

--
-- Function getUserId
--

CREATE OR REPLACE FUNCTION audit.getUserId(_name TEXT) RETURNS SMALLINT AS $$
DECLARE userId SMALLINT;
BEGIN
    SELECT INTO userId id FROM audit.logged_users WHERE name=_name;

    IF userId IS NULL THEN
        INSERT INTO audit.logged_users (name) VALUES (_name) RETURNING id INTO userId;
    END IF;

    RETURN userId;
END; $$
LANGUAGE PLPGSQL;

CREATE TYPE audit.logged_action AS ENUM ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE');

--
-- Audited data. Lots of information is available, it's just a matter of how much
-- you really want to record. See:
--
--   http://www.postgresql.org/docs/9.1/static/functions-info.html
--
-- Remember, every column you add takes up more audit table space and slows audit
-- inserts.
--
-- Every index you add has a big impact too, so avoid adding indexes to the
-- audit table unless you REALLY need them. The hstore GIST indexes are
-- particularly expensive.
--
-- It is sometimes worth copying the audit table, or a coarse subset of it that
-- you're interested in, into a temporary table where you CREATE any useful
-- indexes and do your analysis.
--
DROP TABLE IF EXISTS audit.logged_actions;
CREATE TABLE audit.logged_actions (
    event_id bigserial primary key,
    schema_id smallint not null references audit.logged_schemas(id),
    table_id smallint not null references audit.logged_tables(id),
    relid oid not null,
    session_user_id smallint not null references audit.logged_users(id),
    action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
    transaction_id bigint,
    application_id smallint not null references audit.logged_applications(id),
    client_addr inet,
    client_port integer,
    client_query text,
    action audit.logged_action NOT NULL,
    row_data hstore,
    changed_fields hstore,
    statement_only boolean not null
);

REVOKE ALL ON audit.logged_actions FROM public;

COMMENT ON TABLE audit.logged_actions IS 'History of auditable actions on audited tables, from audit.if_modified_func()';
COMMENT ON COLUMN audit.logged_actions.event_id IS 'Unique identifier for each auditable event';
COMMENT ON COLUMN audit.logged_actions.schema_id IS 'Database schema audited table for this event is in';
COMMENT ON COLUMN audit.logged_actions.table_id IS 'Non-schema-qualified table name of table event occured in';
COMMENT ON COLUMN audit.logged_actions.relid IS 'Table OID. Changes with drop/create. Get with ''tablename''::regclass';
COMMENT ON COLUMN audit.logged_actions.session_user_id IS 'Login / session user whose statement caused the audited event';
COMMENT ON COLUMN audit.logged_actions.action_tstamp_tx IS 'Transaction start timestamp for tx in which audited event occurred';
COMMENT ON COLUMN audit.logged_actions.action_tstamp_stm IS 'Statement start timestamp for tx in which audited event occurred';
COMMENT ON COLUMN audit.logged_actions.action_tstamp_clk IS 'Wall clock time at which audited event''s trigger call occurred';
COMMENT ON COLUMN audit.logged_actions.transaction_id IS 'Identifier of transaction that made the change. May wrap, but unique paired with action_tstamp_tx.';
COMMENT ON COLUMN audit.logged_actions.client_addr IS 'IP address of client that issued query. Null for unix domain socket.';
COMMENT ON COLUMN audit.logged_actions.client_port IS 'Remote peer IP port address of client that issued query. Undefined for unix socket.';
COMMENT ON COLUMN audit.logged_actions.client_query IS 'Top-level query that caused this auditable event. May be more than one statement.';
COMMENT ON COLUMN audit.logged_actions.application_id IS 'Application name set when this audit event occurred. Can be changed in-session by client.';
COMMENT ON COLUMN audit.logged_actions.action IS 'Action type; INSERT, UPDATE, DELETE, TRUNCATE';
COMMENT ON COLUMN audit.logged_actions.row_data IS 'Record value. Null for statement-level trigger. For INSERT this is the new tuple. For DELETE and UPDATE it is the old tuple.';
COMMENT ON COLUMN audit.logged_actions.changed_fields IS 'New values of fields changed by UPDATE. Null except for row-level UPDATE events.';
COMMENT ON COLUMN audit.logged_actions.statement_only IS '''t'' if audit event is from an FOR EACH STATEMENT trigger, ''f'' for FOR EACH ROW';

CREATE INDEX logged_actions_schema_id_idx ON audit.logged_actions(schema_id);
CREATE INDEX logged_actions_table_id_idx ON audit.logged_actions(table_id);
CREATE INDEX logged_actions_session_user_id_idx ON audit.logged_actions(session_user_id);
CREATE INDEX logged_actions_application_id_idx ON audit.logged_actions(application_id);
CREATE INDEX logged_actions_relid_idx ON audit.logged_actions(relid);
CREATE INDEX logged_actions_action_tstamp_tx_stm_idx ON audit.logged_actions(action_tstamp_stm);
CREATE INDEX logged_actions_action_idx ON audit.logged_actions(action);

CREATE OR REPLACE FUNCTION audit.if_modified_func() RETURNS TRIGGER AS $body$
DECLARE
    audit_row audit.logged_actions;
    include_values boolean;
    log_diffs boolean;
    h_old hstore;
    h_new hstore;
    excluded_cols text[] = ARRAY[]::text[];
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'audit.if_modified_func() may only run as an AFTER trigger';
    END IF;

    audit_row = ROW(
        nextval('audit.logged_actions_event_id_seq'), -- event_id
        audit.getSchemaId(TG_TABLE_SCHEMA::text),                        -- schema_name
        audit.gettableid(TG_TABLE_NAME::text),                          -- table_name
        TG_RELID,                                     -- relation OID for much quicker searches
        audit.getUserId( session_user::text),                           -- session_user_name
        current_timestamp,                            -- action_tstamp_tx
        statement_timestamp(),                        -- action_tstamp_stm
        clock_timestamp(),                            -- action_tstamp_clk
        txid_current(),                               -- transaction ID
        audit.getApplicationId( current_setting('application_name')),          -- client application
        inet_client_addr(),                           -- client_addr
        inet_client_port(),                           -- client_port
        current_query(),                              -- top-level query or queries (if multistatement) from client
        TG_OP::audit.logged_action,                         -- action
        NULL, NULL,                                   -- row_data, changed_fields
        'f'                                           -- statement_only
        );

    IF NOT TG_ARGV[0]::boolean IS DISTINCT FROM 'f'::boolean THEN
        audit_row.client_query = NULL;
    END IF;

    IF TG_ARGV[1] IS NOT NULL THEN
        excluded_cols = TG_ARGV[1]::text[];
    END IF;
    
    IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = hstore(OLD.*) - excluded_cols;
        audit_row.changed_fields =  (hstore(NEW.*) - audit_row.row_data) - excluded_cols;
        IF audit_row.changed_fields = hstore('') THEN
            -- All changed fields are ignored. Skip this update.
            RETURN NULL;
        END IF;
    ELSIF (TG_OP = 'DELETE' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = hstore(OLD.*) - excluded_cols;
    ELSIF (TG_OP = 'INSERT' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = hstore(NEW.*) - excluded_cols;
    ELSIF (TG_LEVEL = 'STATEMENT' AND TG_OP IN ('INSERT','UPDATE','DELETE','TRUNCATE')) THEN
        audit_row.statement_only = 't';
    ELSE
        RAISE EXCEPTION '[audit.if_modified_func] - Trigger func added as trigger for unhandled case: %, %',TG_OP, TG_LEVEL;
        RETURN NULL;
    END IF;
    INSERT INTO audit.logged_actions VALUES (audit_row.*);
    RETURN NULL;
END;
$body$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;


COMMENT ON FUNCTION audit.if_modified_func() IS $body$
Track changes to a table at the statement and/or row level.

Optional parameters to trigger in CREATE TRIGGER call:

param 0: boolean, whether to log the query text. Default 't'.

param 1: text[], columns to ignore in updates. Default [].

         Updates to ignored cols are omitted from changed_fields.

         Updates with only ignored cols changed are not inserted
         into the audit log.

         Almost all the processing work is still done for updates
         that ignored. If you need to save the load, you need to use
         WHEN clause on the trigger instead.

         No warning or error is issued if ignored_cols contains columns
         that do not exist in the target table. This lets you specify
         a standard set of ignored columns.

There is no parameter to disable logging of values. Add this trigger as
a 'FOR EACH STATEMENT' rather than 'FOR EACH ROW' trigger if you do not
want to log row values.

Note that the user name logged is the login role for the session. The audit trigger
cannot obtain the active role because it is reset by the SECURITY DEFINER invocation
of the audit trigger its self.
$body$;



CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean, ignored_cols text[]) RETURNS void AS $body$
DECLARE
  stm_targets text = 'INSERT OR UPDATE OR DELETE OR TRUNCATE';
  _q_txt text;
  _ignored_cols_snip text = '';
BEGIN
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || target_table;
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || target_table;

    IF audit_rows THEN
        IF array_length(ignored_cols,1) > 0 THEN
            _ignored_cols_snip = ', ' || quote_literal(ignored_cols);
        END IF;
        _q_txt = 'CREATE TRIGGER audit_trigger_row AFTER INSERT OR UPDATE OR DELETE ON ' || 
                 target_table || 
                 ' FOR EACH ROW EXECUTE PROCEDURE audit.if_modified_func(' ||
                 quote_literal(audit_query_text) || _ignored_cols_snip || ');';
        RAISE NOTICE '%',_q_txt;
        EXECUTE _q_txt;
        stm_targets = 'TRUNCATE';
    ELSE
    END IF;

    _q_txt = 'CREATE TRIGGER audit_trigger_stm AFTER ' || stm_targets || ' ON ' ||
             target_table ||
             ' FOR EACH STATEMENT EXECUTE PROCEDURE audit.if_modified_func('||
             quote_literal(audit_query_text) || ');';
    RAISE NOTICE '%',_q_txt;
    EXECUTE _q_txt;

END;
$body$
language 'plpgsql';

COMMENT ON FUNCTION audit.audit_table(regclass, boolean, boolean, text[]) IS $body$
Add auditing support to a table.

Arguments:
   target_table:     Table name, schema qualified if not on search_path
   audit_rows:       Record each row change, or only audit at a statement level
   audit_query_text: Record the text of the client query that triggered the audit event?
   ignored_cols:     Columns to exclude from update diffs, ignore updates that change only ignored cols.
$body$;

-- Pg doesn't allow variadic calls with 0 params, so provide a wrapper
CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean) RETURNS void AS $body$
SELECT audit.audit_table($1, $2, $3, ARRAY[]::text[]);
$body$ LANGUAGE SQL;

-- And provide a convenience call wrapper for the simplest case
-- of row-level logging with no excluded cols and query logging enabled.
--
CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass) RETURNS void AS $body$
SELECT audit.audit_table($1, BOOLEAN 't', BOOLEAN 't');
$body$ LANGUAGE 'sql';

COMMENT ON FUNCTION audit.audit_table(regclass) IS $body$
Add auditing support to the given table. Row-level changes will be logged with full client query text. No cols are ignored.
$body$;

CREATE OR REPLACE VIEW audit.tableslist AS 
 SELECT DISTINCT triggers.trigger_schema AS schema,
    triggers.event_object_table AS auditedtable
   FROM information_schema.triggers
    WHERE triggers.trigger_name::text IN ('audit_trigger_row'::text, 'audit_trigger_stm'::text)  
ORDER BY schema, auditedtable;

COMMENT ON VIEW audit.tableslist IS $body$
View showing all tables with auditing set up. Ordered by schema, then table.
$body$;

CREATE OR REPLACE VIEW audit.view_logged_actions AS
SELECT l.event_id, schemas.name AS schema, tables.name AS table, users.name AS session_user,
       applications.name AS application, l.action,
       l.action_tstamp_tx, l.action_tstamp_stm, l.action_tstamp_clk, l.relid, l.transaction_id,
       l.client_addr, l.client_port, l.client_query, l.row_data, l.changed_fields, l.statement_only
FROM audit.logged_actions l
INNER JOIN audit.logged_schemas schemas ON l.schema_id = schemas.id
INNER JOIN audit.logged_tables tables ON l.table_id = tables.id
INNER JOIN audit.logged_users users ON l.session_user_id = users.id
INNER JOIN audit.logged_applications applications ON l.application_id = applications.id;
