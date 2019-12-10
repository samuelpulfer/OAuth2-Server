package ch.deluxxe.security.OAuth2.model;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Random;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import ch.deluxxe.security.OAuth2.model.iface.OAuthCodeHelper;

public class OAuthCodeHelperImpl implements OAuthCodeHelper {
	
	final static char[] chars = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
								'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
								'0','1','2','3','4','5','6','7','8','9','-','_'
								};
	
	private DataSource ds;
	
	public OAuthCodeHelperImpl() {
		try {
			Context ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/postgres");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public String getCode(String username, String application, String role) {
		String code = codeGenerator();
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			conn = ds.getConnection();

			ps = conn.prepareStatement("SELECT userstorolesid FROM v_roles WHERE username=? AND appname=? AND rolename=?");
			ps.setString(1, username);
			ps.setString(2, application);
			ps.setString(3, role);
			rs = ps.executeQuery();
			if(rs.next()) {
				int roleId = rs.getInt("userstorolesid");
				ps.close();
				ps = conn.prepareStatement("UPDATE authcode SET expiration = CURRENT_TIMESTAMP WHERE fk_nn_users_roles=? AND redeemed IS NULL AND expiration > CURRENT_TIMESTAMP");
				ps.setInt(1, roleId);
				ps.executeUpdate();
				ps.close();
				ps = conn.prepareStatement("INSERT INTO authcode (authcode,expiration,fk_nn_users_roles) VALUES (?,(CURRENT_TIMESTAMP + (10 * INTERVAL '1 minute')),?)");
				ps.setString(1, code);
				ps.setInt(2, roleId);
				ps.execute();
				return code;
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
		return null;
	}
	
	private String codeGenerator() {
		StringBuilder code = new StringBuilder();
		Random random = new Random();
		for(int i=0;i<64;i++) {
			code.append(chars[random.nextInt(chars.length)]);
		}
		return code.toString();
	}

}
