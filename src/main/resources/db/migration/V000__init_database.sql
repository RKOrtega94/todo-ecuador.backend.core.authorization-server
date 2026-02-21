-- Create status enum type if not exists
DO
$$
BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'status_enum') THEN
CREATE TYPE status_enum AS ENUM ('ACTIVE', 'INACTIVE', 'DELETED');
END IF;
END
$$;

-- ----------------------------------------------------------------------------
-- STEP1: TIMESTAMPS Y DELETED_AT
-- ----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION trigger_set_timestamps()
    RETURNS TRIGGER
    LANGUAGE plpgsql AS
$$
DECLARE
C_OP_INSERT CONSTANT TEXT := 'INSERT';
    C_OP_UPDATE
CONSTANT TEXT := 'UPDATE';
BEGIN
    IF
TG_OP = C_OP_INSERT THEN
        NEW.created_at := CURRENT_TIMESTAMP;
        NEW.updated_at
:= CURRENT_TIMESTAMP;
    ELSIF
TG_OP = C_OP_UPDATE THEN
        NEW.created_at := OLD.created_at;
        NEW.updated_at
:= CURRENT_TIMESTAMP;
END IF;
RETURN NEW;
END;
$$;

CREATE
OR REPLACE FUNCTION trigger_set_deleted_at()
    RETURNS TRIGGER
    LANGUAGE plpgsql AS
$$
BEGIN
    IF
NEW.status = 'DELETED'::status_enum AND (OLD.status IS NULL OR OLD.status != 'DELETED'::status_enum) THEN
        NEW.deleted_at := CURRENT_TIMESTAMP;
    ELSIF
NEW.status != 'DELETED'::status_enum AND OLD.status = 'DELETED'::status_enum THEN
        NEW.deleted_at := NULL;
END IF;
RETURN NEW;
END;
$$;

-- ----------------------------------------------------------------------------
-- STEP 2: ADD COLUMNS AND TRIGGERS
-- ----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION setup_audit_for_table(
    p_schema_name TEXT,
    p_table_name TEXT
)
    RETURNS VOID
    LANGUAGE plpgsql AS
$$
DECLARE
v_full_table TEXT;
    v_sql
TEXT;
    -- Constants for column names
    C_STATUS
CONSTANT TEXT := 'status';
    C_CREATED_AT
CONSTANT TEXT := 'created_at';
    C_UPDATED_AT
CONSTANT TEXT := 'updated_at';
    C_DELETED_AT
CONSTANT TEXT := 'deleted_at';
    C_CREATED_BY
CONSTANT TEXT := 'created_by';
    C_UPDATED_BY
CONSTANT TEXT := 'updated_by';
BEGIN
    v_full_table
:= quote_ident(p_schema_name) || '.' || quote_ident(p_table_name);

    -- Agregar STATUS si no existe
    IF
NOT EXISTS (SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = p_schema_name
                      AND table_name = p_table_name
                      AND column_name = C_STATUS) THEN
        v_sql := format(
                'ALTER TABLE %s ADD COLUMN %I status_enum DEFAULT %L',
                v_full_table, C_STATUS, 'ACTIVE'
                 );
EXECUTE v_sql;
END IF;

    -- Agregar CREATED_AT si no existe
    IF
NOT EXISTS (SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = p_schema_name
                      AND table_name = p_table_name
                      AND column_name = C_CREATED_AT) THEN
        v_sql := format(
                'ALTER TABLE %s ADD COLUMN %I TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
                v_full_table, C_CREATED_AT
                 );
EXECUTE v_sql;
END IF;

    -- Agregar UPDATED_AT si no existe
    IF
NOT EXISTS (SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = p_schema_name
                      AND table_name = p_table_name
                      AND column_name = C_UPDATED_AT) THEN
        v_sql := format(
                'ALTER TABLE %s ADD COLUMN %I TIMESTAMP DEFAULT NOW()',
                v_full_table, C_UPDATED_AT
                 );
EXECUTE v_sql;
END IF;

    -- Agregar DELETED_AT si no existe
    IF
NOT EXISTS (SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = p_schema_name
                      AND table_name = p_table_name
                      AND column_name = C_DELETED_AT) THEN
        v_sql := format(
                'ALTER TABLE %s ADD COLUMN %I TIMESTAMP',
                v_full_table, C_DELETED_AT
                 );
EXECUTE v_sql;
END IF;

    -- Agregar CREATED_BY si no existe
    IF
NOT EXISTS (SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = p_schema_name
                      AND table_name = p_table_name
                      AND column_name = C_CREATED_BY) THEN
        v_sql := format(
                'ALTER TABLE %s ADD COLUMN %I VARCHAR(100)',
                v_full_table, C_CREATED_BY
                 );
EXECUTE v_sql;
END IF;

    -- Agregar UPDATED_BY si no existe
    IF
NOT EXISTS (SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = p_schema_name
                      AND table_name = p_table_name
                      AND column_name = C_UPDATED_BY) THEN
        v_sql := format(
                'ALTER TABLE %s ADD COLUMN %I VARCHAR(100)',
                v_full_table, C_UPDATED_BY
                 );
EXECUTE v_sql;
END IF;

    -- Crear trigger para timestamps
    v_sql
:= format('DROP TRIGGER IF EXISTS trg_%s_timestamps ON %s', p_table_name, v_full_table);
EXECUTE v_sql;

v_sql
:= format(
            'CREATE TRIGGER trg_%s_timestamps
             BEFORE INSERT OR UPDATE ON %s
             FOR EACH ROW
             EXECUTE FUNCTION trigger_set_timestamps()',
            p_table_name, v_full_table
           );
EXECUTE v_sql;

-- Crear trigger para deleted_at
v_sql
:= format('DROP TRIGGER IF EXISTS trg_%s_deleted_at ON %s', p_table_name, v_full_table);
EXECUTE v_sql;

v_sql
:= format(
            'CREATE TRIGGER trg_%s_deleted_at
             BEFORE UPDATE ON %s
             FOR EACH ROW
             EXECUTE FUNCTION trigger_set_deleted_at()',
            p_table_name, v_full_table
           );
EXECUTE v_sql;
END;
$$;

-- ----------------------------------------------------------------------------
-- PASO 3: EVENT TRIGGER PRINCIPAL
-- ----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION event_trigger_auto_audit()
    RETURNS event_trigger
    LANGUAGE plpgsql AS
$$
DECLARE
v_obj        RECORD;
    v_schema
TEXT;
    v_table
TEXT;
    -- Constants for exclusions
    C_PG_CATALOG
CONSTANT TEXT := 'pg_catalog';
    C_INFO_SCHEMA
CONSTANT TEXT := 'information_schema';
    C_PG_TOAST
CONSTANT TEXT := 'pg_toast';
    C_PG_PATTERN
CONSTANT TEXT := 'pg_%';
    C_SQL_PATTERN
CONSTANT TEXT := 'sql_%';
BEGIN
FOR v_obj IN
SELECT *
FROM pg_event_trigger_ddl_commands()
         LOOP
    IF
                v_obj.object_type = 'table' THEN
                v_schema := v_obj.schema_name;

-- Extraer nombre de tabla del object_identity
-- Formato puede ser: "schema"."table" o solo "table"
IF
v_obj.object_identity LIKE '%.%' THEN
                    v_table := regexp_replace(v_obj.object_identity, '^.*\.', '');
ELSE
                    v_table := v_obj.object_identity;
END IF;

                -- Limpiar comillas
                v_schema
:= replace(v_schema, '"', '');
                v_table
:= replace(v_table, '"', '');

                -- Excluir schemas del sistema
                IF
v_schema NOT IN (C_PG_CATALOG, C_INFO_SCHEMA, C_PG_TOAST)
                        AND v_table NOT LIKE C_PG_PATTERN
                        AND v_table NOT LIKE C_SQL_PATTERN THEN

BEGIN
                        PERFORM
setup_audit_for_table(v_schema, v_table);
EXCEPTION
                        WHEN OTHERS THEN
                            NULL;
END;
END IF;
END IF;
END LOOP;
END;
$$;

-- Eliminar event trigger anterior
DROP
EVENT TRIGGER IF EXISTS auto_audit_on_create_table;

-- Crear event trigger
CREATE
EVENT TRIGGER auto_audit_on_create_table
    ON ddl_command_end
    WHEN TAG IN ('CREATE TABLE')
EXECUTE FUNCTION event_trigger_auto_audit();

-- Habilitar
    ALTER
EVENT TRIGGER auto_audit_on_create_table ENABLE;
