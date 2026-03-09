-- Create users foreign table
create foreign table if not exists users(
    id uuid not null,
    username varchar(100) not null,
    password varchar(255) not null,
    password_expiration timestamp,
    verified boolean default false,
    locked boolean default false,
    enabled boolean default true
    ) server ${SECURITY_DB_SERVER_NAME}
    options (schema_name 'public', table_name 'users');