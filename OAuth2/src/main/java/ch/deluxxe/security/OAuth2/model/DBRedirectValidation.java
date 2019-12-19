package ch.deluxxe.security.OAuth2.model;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import ch.deluxxe.security.OAuth2.model.iface.RedirectValidation;

public class DBRedirectValidation implements RedirectValidation {
	
private DataSource ds;
	
	public DBRedirectValidation() {
		try {
			Context ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/postgres");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean validate(String application, String redirectUri) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT redirecturi FROM application WHERE appname=?");
			ps.setString(1, application);
			rs = ps.executeQuery();
			if(rs.next()) {
				String[] redirects = rs.getString("redirecturi").split(",");
				//System.out.println(redirectUri);
				//for(String a:redirects) {
				//	System.out.println(a);
				//}
				if(Arrays.asList(redirects).contains(redirectUri)) {
					return true;
				}
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

}
