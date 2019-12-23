/* DROP Tables */

/*
DROP VIEW v_roles;
DROP VIEW v_accesstoken;
DROP VIEW v_refreshtoken;
DROP VIEW v_authcode;
DROP TABLE application;
DROP TABLE authcode;
DROP TABLE accesstoken;
DROP TABLE refreshtoken;
DROP TABLE nn_users_roles;
DROP TABLE roles;
DROP TABLE settings;
DROP TABLE users;
*/


CREATE TABLE application
(
    id serial PRIMARY KEY,
    appname character varying(32) NOT NULL,
    redirecturi character varying(1000) NOT NULL,
    secret character varying(64)
);
CREATE TABLE authcode
(
    authcode character varying(64) PRIMARY KEY,
    fk_nn_users_roles integer NOT NULL,
    expiration timestamp without time zone NOT NULL,
    redeemed timestamp without time zone
);
CREATE TABLE accesstoken
(
    accesstoken character varying(64) PRIMARY KEY,
    fk_authcode character varying(64) NOT NULL,
    expiration timestamp without time zone NOT NULL
);
CREATE TABLE refreshtoken
(
    refreshtoken character varying(64) PRIMARY KEY,
    fk_authcode character varying(64) NOT NULL,
    expiration timestamp without time zone NOT NULL,
    redeemed timestamp without time zone
);
CREATE TABLE nn_users_roles
(
    id serial PRIMARY KEY,
    fk_users integer NOT NULL,
    fk_roles integer NOT NULL,
    deleted timestamp without time zone
);
CREATE TABLE roles
(
    id serial PRIMARY KEY,
    rolename character varying(32) NOT NULL,
    adgroup character varying(200),
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
    password character(32),
    firstname character varying(30),
    surname character varying(30),
    email character varying(100)
);
CREATE VIEW v_roles AS (
	SELECT roles.id, roles.rolename, roles.adgroup, application.appname, application.secret, users.username, nn_users_roles.id AS userstorolesid
	FROM roles
	LEFT JOIN application ON (application.id = roles.fk_application)
	LEFT JOIN nn_users_roles ON (nn_users_roles.fk_roles = roles.id)
	LEFT JOIN users ON (nn_users_roles.fk_users = users.id)
	WHERE nn_users_roles.deleted IS NULL
);
CREATE VIEW v_authcode AS (
	SELECT application.appname, application.secret, roles.rolename, users.username, authcode.authcode, authcode.expiration, authcode.redeemed
	FROM authcode
	LEFT JOIN nn_users_roles ON(authcode.fk_nn_users_roles = nn_users_roles.id)
	LEFT JOIN roles ON(nn_users_roles.fk_roles = roles.id)
	LEFT JOIN users ON(nn_users_roles.fk_users = users.id)
	LEFT JOIN application ON(roles.fk_application = application.id)
);
CREATE VIEW v_refreshtoken AS (
	SELECT v_authcode.appname, v_authcode.secret, v_authcode.rolename, v_authcode.username, v_authcode.authcode, refreshtoken.refreshtoken, refreshtoken.expiration, refreshtoken.redeemed
	FROM refreshtoken
	LEFT JOIN v_authcode ON(refreshtoken.fk_authcode = v_authcode.authcode)
);
CREATE VIEW v_accesstoken AS (
	SELECT v_authcode.appname, v_authcode.secret, v_authcode.rolename, v_authcode.username, v_authcode.authcode, accesstoken.accesstoken, accesstoken.expiration
	FROM accesstoken
	LEFT JOIN v_authcode ON(accesstoken.fk_authcode = v_authcode.authcode)
);
INSERT INTO application (appname,redirecturi,secret) VALUES ('testapp','http://localhost:8080/MyRedirectUri','superStrongSecret');
INSERT INTO roles (rolename,adgroup,fk_application) VALUES ('User','CN=P_testapp_Users,OU=Permission,OU=Groups,OU=ad,DC=deluxxe,DC=ch',1);
INSERT INTO users (username,password) VALUES ('user',MD5('password'));
INSERT INTO nn_users_roles (fk_users,fk_roles) VALUES (1,1);
INSERT INTO settings (setting,value) VALUES ('ActiveDirectory','{"password":"password","baseDN":"ou=ad,dc=deluxxe,dc=ch","user":"user@deluxxe.ch","url":"ldap://adc.deluxxe.ch:389/","authentication":"simple","domain":"deluxxe.ch","tls":true}')