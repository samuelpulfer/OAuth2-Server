# Vanilla OAuth2-Server
OAuth2 Server written in Java

Installation:

- Install PostgreSQL and create db and user
- Create Postgres tables with script src/main/resources/sql/create_postgres.sql
- Configure DB connection in src/main/webapp/META-INF/context.xml.example and rename it to context.xml
- Install Tomcat 9
- Install latest version of nodejs
- Compile WAR with mvn package -Pproduction
- Deploy WAR to Tomcat

Test it at:
<br>
http://localhost:8080/OAuth2/Login?response_type=code&client_id=testapp&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2FMyRedirectUri&device_id=debug
<br>
User: user
<br>
Password: password
