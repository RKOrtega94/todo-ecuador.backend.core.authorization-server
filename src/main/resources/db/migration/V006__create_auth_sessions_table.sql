-- Auth sessions table: tracks active REST-based authentication sessions per device.
-- Separate from Spring Session (which is used by the OAuth2 Authorization Code flow).
-- Provides: device metadata, refresh token rotation, cross-device session revocation.

CREATE TABLE IF NOT EXISTS auth_sessions
(
    id                  UUID         PRIMARY KEY NOT NULL,
    username            VARCHAR(100)             NOT NULL,
    device_id           VARCHAR(100)             NOT NULL,
    device_name         VARCHAR(255),
    user_agent          VARCHAR(500),
    ip_address          VARCHAR(45),
    access_token_jti    VARCHAR(255)             NOT NULL,
    refresh_token_hash  VARCHAR(255)             NOT NULL,
    created_at          TIMESTAMP                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at        TIMESTAMP                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP                NOT NULL,
    revoked_at          TIMESTAMP                         DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_username          ON auth_sessions (username);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_access_token_jti  ON auth_sessions (access_token_jti);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_refresh_token_hash ON auth_sessions (refresh_token_hash);
-- Composite index to efficiently find active sessions for a user ordered by creation date (for oldest-eviction policy)
CREATE INDEX IF NOT EXISTS idx_auth_sessions_username_revoked_created
    ON auth_sessions (username, revoked_at, created_at);
