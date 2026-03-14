-- Actualizar función de trigger de evento para excluir tablas de spring_session del auto-audit
CREATE OR REPLACE FUNCTION event_trigger_auto_audit()
    RETURNS event_trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    v_obj RECORD;
    v_schema TEXT;
    v_table TEXT;
    -- Constantes para exclusiones
    C_PG_CATALOG CONSTANT TEXT := 'pg_catalog';
    C_INFO_SCHEMA CONSTANT TEXT := 'information_schema';
    C_PG_TOAST CONSTANT TEXT := 'pg_toast';
    C_PG_PATTERN CONSTANT TEXT := 'pg_%';
    C_SQL_PATTERN CONSTANT TEXT := 'sql_%';
    C_SPRING_SESSION_PATTERN CONSTANT TEXT := 'spring_session%';
BEGIN
    FOR v_obj IN
        SELECT *
        FROM pg_event_trigger_ddl_commands()
    LOOP
        IF v_obj.object_type = 'table' THEN
            v_schema := v_obj.schema_name;

            -- Extraer nombre de tabla del object_identity
            IF v_obj.object_identity LIKE '%.%' THEN
                v_table := regexp_replace(v_obj.object_identity, '^.*\.', '');
            ELSE
                v_table := v_obj.object_identity;
            END IF;

            -- Limpiar comillas
            v_schema := replace(v_schema, '"', '');
            v_table := replace(v_table, '"', '');

            -- Excluir schemas del sistema y tablas de session
            IF v_schema NOT IN (C_PG_CATALOG, C_INFO_SCHEMA, C_PG_TOAST)
               AND v_table NOT LIKE C_PG_PATTERN
               AND v_table NOT LIKE C_SQL_PATTERN
               AND v_table NOT LIKE C_SPRING_SESSION_PATTERN THEN

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
