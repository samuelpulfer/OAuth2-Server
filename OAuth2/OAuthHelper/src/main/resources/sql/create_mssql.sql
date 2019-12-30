/* DROP Tables */

/*
DROP VIEW v_userinfo;
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
    id INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
    appname character varying(32) NOT NULL,
    redirecturi character varying(1000) NOT NULL,
    secret character varying(64)
);
CREATE TABLE authcode
(
    authcode character varying(64) PRIMARY KEY,
    fk_nn_users_roles integer NOT NULL,
    expiration datetime NOT NULL,
    redeemed datetime
);
CREATE TABLE accesstoken
(
    accesstoken character varying(64) PRIMARY KEY,
    fk_authcode character varying(64) NOT NULL,
    expiration datetime NOT NULL
);
CREATE TABLE refreshtoken
(
    refreshtoken character varying(64) PRIMARY KEY,
    fk_authcode character varying(64) NOT NULL,
    expiration datetime NOT NULL,
    redeemed datetime
);
CREATE TABLE nn_users_roles
(
    id INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
    fk_users integer NOT NULL,
    fk_roles integer NOT NULL,
    deleted datetime
);
CREATE TABLE roles
(
    id INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
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
    id INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
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
	WHERE nn_users_roles.deleted IS NULL
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
CREATE VIEW v_userinfo AS (
	SELECT accesstoken.accesstoken, roles.rolename, users.username, users.firstname, users.surname, users.email
	FROM accesstoken
	LEFT JOIN authcode ON(accesstoken.fk_authcode = authcode.authcode)
	LEFT JOIN nn_users_roles ON(authcode.fk_nn_users_roles = nn_users_roles.id)
	LEFT JOIN roles ON(nn_users_roles.fk_roles = roles.id)
	LEFT JOIN users ON(nn_users_roles.fk_users = users.id)
	WHERE nn_users_roles.deleted IS NULL
);
INSERT INTO application (appname,redirecturi,secret) VALUES ('testapp','http://localhost:8080/menu/signin','superStrongSecret');
INSERT INTO roles (rolename,adgroup,fk_application) VALUES ('User','CN=P_testapp_Users,OU=Permission,OU=Groups,OU=ad,DC=deluxxe,DC=ch',1);
INSERT INTO users (username,password) VALUES ('user',CONVERT(VARCHAR(32), HashBytes('MD5', 'password'), 2));
INSERT INTO nn_users_roles (fk_users,fk_roles) VALUES (1,1);
INSERT INTO settings (setting,value) VALUES ('ActiveDirectory','{"password":"password","baseDN":"ou=ad,dc=deluxxe,dc=ch","user":"user@deluxxe.ch","url":"ldap://adc.deluxxe.ch:389/","authentication":"simple","domain":"deluxxe.ch","tls":true}')