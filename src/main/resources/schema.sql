CREATE TABLE spaces (
    space_id INT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(30) NOT NULL,
);

CREATE SEQUENCE space_id_seq;

CREATE TABLE messages (
    msg_id INT PRIMARY KEY,
    space_id INT NOT NULL REFERENCES spaces(space_id),
    author VARCHAR(30) NOT NULL,
    msg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    msg_text VARCHAR(1024) NOT NULL
);
CREATE SEQUENCE msg_id_seq;
CREATE INDEX msg_timestamp_idx ON messages(msg_time);
CREATE UNIQUE INDEX space_name_idx ON spaces(name);
CREATE USER natter_api_user PASSWORD 'password';
GRANT SELECT, INSERT, DELETE ON spaces, messages TO natter_api_user;



CREATE TABLE users (   
    user_id VARCHAR(30) PRIMARY KEY,
    pw_hash VARCHAR(255) NOT NULL
);
GRANT SELECT, INSERT ON users to natter_api_user;


CREATE TABLE audit_logs (
    audit_id INT NULL,
    user_id VARCHAR(30) NULL,
    path VARCHAR(30) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status INT NULL,
    audit_time TIMESTAMP NOT NULL
);
CREATE SEQUENCE audit_id_seq;
GRANT SELECT, INSERT ON audit_logs TO natter_api_user;

CREATE TABLE group_members (
    group_id VARCHAR(30) NOT NULL,
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id)
);
CREATE INDEX group_members_user_id_idx on group_members(user_id);
GRANT SELECT, DELETE ON group_members TO natter_api_user;

CREATE TABLE user_permissions(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    perms VARCHAR(3) NOT NULL,
    PRIMARY KEY (space_id, user_id)
);
GRANT SELECT, INSERT ON user_permissions TO natter_api_user;

CREATE TABLE group_permissions(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    perms VARCHAR(3) NOT NULL,
    PRIMARY KEY (space_id, user_id)
);
GRANT SELECT, INSERT ON group_permissions TO natter_api_user;

CREATE VIEW permissions(space_id, user_or_group_id, perms) AS
    SELECT space_id, user_id, perms from user_permissions
    UNION ALL
    SELECT space_id, user_id, perms from group_permissions;
GRANT SELECT, INSERT ON permissions TO natter_api_user;

CREATE TABLE tokens (
    token_id VARCHAR(100) PRIMARY KEY,
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    expiry TIMESTAMP NOT NULL,
    attributes VARCHAR(4096) NOT NULL,
);
GRANT SELECT, INSERT, DELETE ON tokens TO natter_api_user;

CREATE TABLE role_permissions (
    role_id VARCHAR(30) NOT NULL PRIMARY KEY,
    perms VARCHAR(3) NOT NULL
);

INSERT INTO role_permissions (role_id, perms)
VALUES ('owner', 'rwd'),
       ('moderator', 'rd'),
       ('member', 'rw'),
       ('observer', 'r');
GRANT SELECT, INSERT ON role_permissions TO natter_api_user;

CREATE TABLE user_roles (
    space_id INT NOT NULL REFERENCES spaces(space_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    role_id VARCHAR(30) NOT NULL,
    PRIMARY KEY(space_id, user_id)
);
GRANT SELECT, INSERT ON user_roles TO natter_api_user;