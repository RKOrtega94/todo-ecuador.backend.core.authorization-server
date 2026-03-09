-- Add the postgres_fdw extension to enable foreign data wrapper functionality
create extension if not exists postgres_fdw;

-- Create server security_db
create server if not exists ${SECURITY_DB_SERVER_NAME}
    foreign data wrapper postgres_fdw
    options (host '${SECURITY_DB_HOST}', port '${SECURITY_DB_PORT}', dbname '${SECURITY_DB_NAME}');

-- Create user mapping for the current user to access the security_db server
create user mapping if not exists for current_user
    server ${SECURITY_DB_SERVER_NAME}
    options (user '${SECURITY_DB_USER}', password '${SECURITY_DB_PASSWORD}');