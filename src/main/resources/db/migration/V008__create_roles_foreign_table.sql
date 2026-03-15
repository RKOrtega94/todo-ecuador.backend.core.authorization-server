-- Create foreign roles table
create foreign table if not exists roles(
    id uuid not null,
    company_id uuid,
    name varchar(100) not null,
    status status_enum not null,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    created_by varchar(100),
    updated_by varchar(100)
    ) server ${SECURITY_DB_SERVER_NAME} options (schema_name 'public', table_name 'roles');

-- Create foreign user_roles table
create foreign table if not exists user_roles(
    user_id uuid not null,
    role_id uuid not null
    ) server ${SECURITY_DB_SERVER_NAME} options (schema_name 'public', table_name 'user_roles');