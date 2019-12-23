package ch.deluxxe.security.OAuth2.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import ch.deluxxe.security.OAuth2.model.iface.Authentication;

public class DBAuthentication implements Authentication {
	
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	
	private DataSource ds;
	
	public DBAuthentication() {
		try {
			Context ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/postgres");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean authenticate(String username, String password) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		String passwordHash = "";
		int id = 0;
		
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			passwordHash = bytesToHex(md.digest(password.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		try {
			System.out.println("User: " + username + " Pw: " + passwordHash);
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT id FROM users WHERE username=? AND password=?");
			ps.setString(1, username);
			ps.setString(2, passwordHash);
			rs = ps.executeQuery();
			if(rs.next()) {
				id = rs.getInt("id");
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

		if(id != 0) {
			return true;
		}
		return false;
	}
	
	private String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars).toLowerCase();
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub
	}

	@Override
	public String getSuffix() {
		return "";
	}
	
	

}
