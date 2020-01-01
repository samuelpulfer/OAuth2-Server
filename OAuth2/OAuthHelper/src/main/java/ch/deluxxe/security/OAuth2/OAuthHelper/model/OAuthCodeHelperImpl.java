package ch.deluxxe.security.OAuth2.OAuthHelper.model;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.iface.OAuthInfo;


/** An implementation of OAuthCodeHelper to generate bearer token.
 * Requires a Database connection defined as "java:comp/env/jdbc/oauthdb"
 * @author Samuel Pulfer
 *
 */
public class OAuthCodeHelperImpl implements OAuthCodeHelper {
	
	/**
	 * A lookup table for all usable characters in token.
	 */
	final static char[] chars = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
								'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
								'0','1','2','3','4','5','6','7','8','9'
								};
	
	/** An implementation of OAuthCodePair
	 * @author Samuel Pulfer
	 *
	 */
	private class OAuthCodePairImpl implements OAuthCodePair {

		private String accessCode = null;
		private String refreshCode = null;
		private String secret = null;
		private String username = null;
		
		public OAuthCodePairImpl() {
			accessCode = codeGenerator();
			refreshCode = codeGenerator();
		}
		/** Sets the secret to sign the token.
		 * @param secret
		 */
		public void setSecret(String secret) {
			this.secret = secret;
		}
		/** Sets the username for the token.
		 * @param username
		 */
		public void setUsername(String username) {
			this.username = username;
		}
		
		@Override
		public String getAccessToken() {
			return accessCode;
		}

		@Override
		public String getRefreshToken() {
			return refreshCode;
		}
		@Override
		public String getJWTAccessToken() {
			JSONObject jo = JWTHelper.payload(18000, username, accessCode);
			try {
				return jwt.getTokenHMAC(jo, secret);
			} catch (InvalidKeyException | NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
		}
		@Override
		public String getJWTRefreshToken() {
			JSONObject jo = JWTHelper.payload(1209600, username, refreshCode);
			try {
				return jwt.getTokenHMAC(jo, secret);
			} catch (InvalidKeyException | NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
		}
		
	}
	
	/** Implements a OAuthInfo
	 * @author Samuel Pulfer
	 *
	 */
	private class OAuthInfoImpl implements OAuthInfo {

		private String application = null;
		private String role = null;
		private String username = null;
		private String accessCode = null;
		
		/** Constructs the OAuthInfoImpl
		 * @param application The application
		 * @param role The role
		 * @param username The username
		 * @param accessCode The access code.
		 */
		public OAuthInfoImpl(String application, String role, String username, String accessCode) {
			this.application = application;
			this.role = role;
			this.username = username;
			this.accessCode = accessCode;
		}
		
		@Override
		public String getApplication() {
			return application;
		}

		@Override
		public String getRole() {
			return role;
		}

		@Override
		public String getAccessCode() {
			return accessCode;
		}

		@Override
		public String getUsername() {
			return username;
		}
		
	}
	
	private DataSource ds;
	private JWTHelper jwt = null;
	
	/**
	 * Initials DataSource
	 */
	public OAuthCodeHelperImpl() {
		try {
			Context ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/oauthdb");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		jwt = new JWTHelper();
	}

	@Override
	public String getAuthCode(String username, String application, String role) {
		username = username.toLowerCase();
		String code = codeGenerator();
		JSONObject jo = JWTHelper.payload(300, username, code);
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			conn = ds.getConnection();

			ps = conn.prepareStatement("SELECT userstorolesid, secret, (SELECT CURRENT_TIMESTAMP) AS tsnow FROM v_roles WHERE username=? AND appname=? AND rolename=?");
			ps.setString(1, username);
			ps.setString(2, application);
			ps.setString(3, role);
			rs = ps.executeQuery();
			if(rs.next()) {
				int roleId = rs.getInt("userstorolesid");
				String secret = rs.getString("secret");
				LocalDateTime later = rs.getTimestamp("tsnow").toLocalDateTime().plusMinutes(5);
				ps.close();
				ps = conn.prepareStatement("UPDATE authcode SET expiration = CURRENT_TIMESTAMP WHERE fk_nn_users_roles=? AND redeemed IS NULL AND expiration > CURRENT_TIMESTAMP");
				ps.setInt(1, roleId);
				ps.executeUpdate();
				ps.close();
				ps = conn.prepareStatement("INSERT INTO authcode (authcode,expiration,fk_nn_users_roles) VALUES (?,?,?)");
				ps.setString(1, code);
				ps.setTimestamp(2, Timestamp.valueOf(later));
				ps.setInt(3, roleId);
				ps.execute();
				return jwt.getTokenHMAC(jo, secret);
			}
			
		} catch (SQLException | InvalidKeyException | NoSuchAlgorithmException e) {
			System.out.println("Exception in getAuthCode(): " + e.getMessage());
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
	


	@Override
	public OAuthCodePair getToken(String code, GrantType grantType) {
		OAuthCodePairImpl newcode = new OAuthCodePairImpl();
		String jti = null;
		try {
		JSONObject jo = new JSONObject(new String(Base64.getUrlDecoder().decode(code.split("\\.")[1])));
		System.out.println(jo);
		jti = jo.getString("jti");
		System.out.println(jti);
		} catch(Exception e) {
			System.out.println("Token not decodable or empty");
			return null;
		}
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			conn = ds.getConnection();
			
			if(grantType.equals(GrantType.authorization_code)) {
				ps = conn.prepareStatement("SELECT authcode, secret, username, (SELECT CURRENT_TIMESTAMP) AS tsnow FROM v_authcode WHERE authcode=? AND expiration > CURRENT_TIMESTAMP AND redeemed IS NULL");
				ps.setString(1, jti);
				rs = ps.executeQuery();
				if(rs.next()) {
					LocalDateTime now = rs.getTimestamp("tsnow").toLocalDateTime();
					newcode.setSecret(rs.getString("secret"));
					newcode.setUsername(rs.getString("username"));
					rs.close();
					ps.close();
					ps = conn.prepareStatement("UPDATE authcode SET redeemed = CURRENT_TIMESTAMP WHERE authcode=?");
					ps.setString(1, jti);
					ps.executeUpdate();
					ps.close();
					ps = conn.prepareStatement("INSERT INTO accesstoken (accesstoken, fk_authcode, expiration) VALUES (?,?,?)");
					ps.setString(1, newcode.getAccessToken());
					ps.setString(2, jti);
					ps.setTimestamp(3, Timestamp.valueOf(now.plusMinutes(300)));
					ps.executeUpdate();
					ps.close();
					ps = conn.prepareStatement("INSERT INTO refreshtoken (refreshtoken, fk_authcode, expiration) VALUES (?,?,?)");
					ps.setString(1, newcode.getRefreshToken());
					ps.setString(2, jti);
					ps.setTimestamp(3, Timestamp.valueOf(now.plusMinutes(20160)));
					ps.executeUpdate();
					return newcode;
				}
				
			} else if(grantType.equals(GrantType.refresh_token)) {
				ps = conn.prepareStatement("SELECT authcode, secret, username, (SELECT CURRENT_TIMESTAMP) AS tsnow FROM v_refreshtoken WHERE refreshtoken=? AND expiration > CURRENT_TIMESTAMP AND redeemed IS NULL");
				ps.setString(1, jti);
				rs = ps.executeQuery();
				if(rs.next()) {
					LocalDateTime now = rs.getTimestamp("tsnow").toLocalDateTime();
					String authcode = rs.getString("authcode");
					newcode.setSecret(rs.getString("secret"));
					newcode.setUsername(rs.getString("username"));
					rs.close();
					ps.close();
					ps = conn.prepareStatement("UPDATE refreshtoken SET redeemed = CURRENT_TIMESTAMP WHERE refreshtoken=?");
					ps.setString(1, jti);
					ps.executeUpdate();
					ps.close();
					ps = conn.prepareStatement("UPDATE accesstoken SET expiration = CURRENT_TIMESTAMP WHERE fk_authcode=? AND expiration > CURRENT_TIMESTAMP");
					ps.setString(1, authcode);
					ps.executeUpdate();
					ps.close();
					ps = conn.prepareStatement("INSERT INTO accesstoken (accesstoken, fk_authcode, expiration) VALUES (?,?,?)");
					ps.setString(1, newcode.getAccessToken());
					ps.setString(2, authcode);
					ps.setTimestamp(3, Timestamp.valueOf(now.plusMinutes(300)));
					ps.executeUpdate();
					ps.close();
					ps = conn.prepareStatement("INSERT INTO refreshtoken (refreshtoken, fk_authcode, expiration) VALUES (?,?,?)");
					ps.setString(1, newcode.getRefreshToken());
					ps.setString(2, authcode);
					ps.setTimestamp(3, Timestamp.valueOf(now.plusMinutes(20160)));
					ps.executeUpdate();
					return newcode;
				}
				
			} else {
				return null;
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
	
	/** Generates a 27 character long random code.
	 * @return The 27 character long random code.
	 */
	private String codeGenerator() {
		StringBuilder code = new StringBuilder();
		code.append(UUID.randomUUID());
		code.append("-");
		Random random = new Random();
		for(int i=0;i<27;i++) {
			code.append(chars[random.nextInt(chars.length)]);
		}
		return code.toString();
	}

	@Override
	public boolean validate(String code) {
		JSONObject userinfo = getUserinfo(code);
		if(userinfo == null) {
			return false;
		}
		return true;
	}

	@Override
	public JSONObject getUserinfo(String code) {
		JSONObject userinfo = null;
		if(code == null) {
			return userinfo;
		}
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT * FROM v_userinfo WHERE accesstoken=?");
			ps.setString(1, code);
			rs = ps.executeQuery();
			if(rs.next()) {
				userinfo = new JSONObject();
				if(rs.getString("firstname") != null && rs.getString("surname") != null) {
					userinfo.put("given_name", rs.getString("firstname"));
					userinfo.put("family_name", rs.getString("surname"));
					userinfo.put("name", rs.getString("firstname") + " " + rs.getString("surname"));
				} else if(rs.getString("surname") != null) {
					userinfo.put("family_name", rs.getString("surname"));
					userinfo.put("name", rs.getString("surname"));
				} else if(rs.getString("firstname") != null) {
					userinfo.put("given_name", rs.getString("firstname"));
					userinfo.put("name", rs.getString("firstname"));
				}
				if(rs.getString("email") != null) {
					userinfo.put("email", rs.getString("email"));
				}
				userinfo.put("sub", rs.getString("username"));
				userinfo.put("preferred_username", rs.getString("username").split("@")[0]);
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
		return userinfo;
	}

	@Override
	public OAuthInfo getOAuthInfo(String code) {
		OAuthInfo info = null;
		String jti = null;
		try {
			JSONObject jo = new JSONObject(new String(Base64.getUrlDecoder().decode(code.split("\\.")[1])));
			jti = jo.getString("jti");
		} catch(Exception e) {
			return info;
		}
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT appname,rolename,username FROM v_accesstoken WHERE accesstoken=? AND expiration > CURRENT_TIMESTAMP");
			ps.setString(1, jti);
			rs = ps.executeQuery();
			if(rs.next()) {
				info = new OAuthInfoImpl(rs.getString("appname"), rs.getString("rolename"), rs.getString("username"), jti);
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
		return info;
	}

}
