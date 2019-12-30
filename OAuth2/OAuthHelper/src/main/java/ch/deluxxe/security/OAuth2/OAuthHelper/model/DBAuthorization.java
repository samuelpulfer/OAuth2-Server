package ch.deluxxe.security.OAuth2.OAuthHelper.model;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.Authorization;


public class DBAuthorization implements Authorization {
	
	private DataSource ds;
	
	public DBAuthorization() {
		try {
			Context ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/oauthdb");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	

	@Override
	public boolean authorize(String username, String application, String role) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT id FROM v_roles WHERE username=? AND appname=? AND rolename=?");
			ps.setString(1, username);
			ps.setString(2, application);
			ps.setString(3, role);
			rs = ps.executeQuery();
			if(rs.next()) {
				return true;
			}
			
		} catch (SQLException e) {
			System.out.println("SQL Exception: " + e.getMessage());
		} finally {
			try {
				rs.close();
			} catch (Exception e) {
			}
			try {
				ps.close();
			} catch (Exception e) {
			}
			try {
				conn.close();
			} catch (Exception e) {
			}
		}
		return false;
	}



	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}

}
