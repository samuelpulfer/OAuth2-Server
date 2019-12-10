CREATE TABLE application
(
    id serial PRIMARY KEY,
    appname character varying(32) NOT NULL,
    redirecturi character varying(1000) NOT NULL
);
CREATE TABLE authcode
(
    authcode character varying(64) PRIMARY KEY,
    fk_nn_users_roles integer NOT NULL,
    expiration timestamp without time zone NOT NULL,
    redeemed timestamp without time zone
);
CREATE TABLE nn_users_roles
(
    id serial PRIMARY KEY,
    fk_users integer NOT NULL,
    fk_roles integer NOT NULL
);
CREATE TABLE roles
(
    id serial PRIMARY KEY,
    rolename character varying(32) NOT NULL,
    fk_application integer NOT NULL
);
CREATE TABLE settings
(
    setting character varying(20) PRIMARY KEY,
    value character varying(2000)
);
CREATE TABLE users
(
    id serial PRIMARY KEY,
    username character varying(20) NOT NULL,
    password character(32)
);
CREATE VIEW v_roles AS (
	SELECT roles.id, roles.rolename, application.appname, users.username, nn_users_roles.id AS userstorolesid
	FROM roles
	LEFT JOIN application ON (application.id = roles.fk_application)
	LEFT JOIN nn_users_roles ON (nn_users_roles.fk_roles = roles.id)
	LEFT JOIN users ON (nn_users_roles.fk_users = users.id)
);
INSERT INTO application (appname,redirecturi) VALUES ('testapp','http://localhost:8080/MyRedirectUri');
INSERT INTO roles (rolename,fk_application) VALUES ('User',1);
INSERT INTO users (username,password) VALUES ('user',MD5('password'));
INSERT INTO nn_users_roles (fk_users,fk_roles) VALUES (1,1);