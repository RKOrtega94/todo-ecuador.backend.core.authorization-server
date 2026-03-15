-- Update the auto-audit event trigger to also exclude auth_sessions from being audited.
-- auth_sessions manages its own timestamps and state columns, so the generic audit trigger
-- must not add conflicting columns (status, created_at, updated_at, deleted_at, etc.).

CREATE OR REPLACE FUNCTION event_trigger_auto_audit()
    RETURNS event_trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    v_obj                      RECORD;
    v_schema                   TEXT;
    v_table                    TEXT;
    C_PG_CATALOG     CONSTANT  TEXT := 'pg_catalog';
    C_INFO_SCHEMA    CONSTANT  TEXT := 'information_schema';
    C_PG_TOAST       CONSTANT  TEXT := 'pg_toast';
    C_PG_PATTERN     CONSTANT  TEXT := 'pg_%';
    C_SQL_PATTERN    CONSTANT  TEXT := 'sql_%';
    C_SPRING_SESSION CONSTANT  TEXT := 'spring_session%';
    C_AUTH_SESSIONS  CONSTANT  TEXT := 'auth_sessions%';
BEGIN
    FOR v_obj IN
        SELECT *
        FROM pg_event_trigger_ddl_commands()
    LOOP
        IF v_obj.object_type = 'table' THEN
            v_schema := v_obj.schema_name;

            IF v_obj.object_identity LIKE '%.%' THEN
                v_table := regexp_replace(v_obj.object_identity, '^.*\.', '');
            ELSE
                v_table := v_obj.object_identity;
            END IF;

            v_schema := replace(v_schema, '"', '');
            v_table  := replace(v_table,  '"', '');

            IF v_schema NOT IN (C_PG_CATALOG, C_INFO_SCHEMA, C_PG_TOAST)
               AND v_table NOT LIKE C_PG_PATTERN
               AND v_table NOT LIKE C_SQL_PATTERN
               AND v_table NOT LIKE C_SPRING_SESSION
               AND v_table NOT LIKE C_AUTH_SESSIONS THEN

                BEGIN
                    PERFORM setup_audit_for_table(v_schema, v_table);
                EXCEPTION
                    WHEN OTHERS THEN
                        NULL;
                END;
            END IF;
        END IF;
    END LOOP;
END;
$$;
