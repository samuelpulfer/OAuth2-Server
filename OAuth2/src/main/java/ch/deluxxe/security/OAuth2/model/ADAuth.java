package ch.deluxxe.security.OAuth2.model;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.sql.DataSource;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.model.iface.Authentication;
import ch.deluxxe.security.OAuth2.model.iface.Authorization;

public class ADAuth implements Authentication,Authorization {
	
	private DataSource ds = null;
	private JSONObject settings = null;

	public ADAuth() {
		//System.setProperty("javax.net.ssl.trustStore", "C:\\tmp\\myTrustStore");
		//System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
		
		try {
			Context ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/main");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		settings = getSettings();
	}
	
	private JSONObject getSettings() {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT value FROM settings WHERE setting='ActiveDirectory'");
			rs = ps.executeQuery();
			if(rs.next()) {
				return new JSONObject(rs.getString("value"));
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

	@Override
	public boolean authenticate(String username, String password) {
		StartTlsResponse tls = null;
		try {
			LdapContext ctx = getContext();
			if(ctx != null) {
				if(settings.getBoolean("tls")) {
					tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
					tls.negotiate();
				}
				ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, username + "@" + settings.getString("domain"));
				ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
				
				String searchFilter = "(&(objectClass=user)(sAMAccountName=" + username +"))";
				SearchControls searchControls = new SearchControls();
				searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

				try {
					NamingEnumeration<SearchResult> results = ctx.search(settings.getString("baseDN"), searchFilter, searchControls);
					SearchResult searchResult = null;
					if (results.hasMoreElements()) {
						searchResult = (SearchResult) results.nextElement();
						String firstname = null;
						String surname = null;
						String email = null;
						System.out.println(searchResult.getNameInNamespace());
						if(searchResult.getAttributes().get("givenName") != null) {
							firstname = searchResult.getAttributes().get("givenName").get().toString();
						}
						if(searchResult.getAttributes().get("sn") != null) {
							surname = searchResult.getAttributes().get("sn").get().toString();
						}
						if(searchResult.getAttributes().get("mail") != null) {
							email = searchResult.getAttributes().get("mail").get().toString();
						}
						System.out.println("givenName: " + searchResult.getAttributes().get("givenName").get().toString());
						System.out.println("sn: " + searchResult.getAttributes().get("sn").get().toString());
						System.out.println("mail: " + searchResult.getAttributes().get("mail").get().toString());
						// Store to DB if not exist
						Connection conn = null;
						PreparedStatement ps = null;
						ResultSet rs = null;
						try {
							conn = ds.getConnection();
							ps = conn.prepareStatement("SELECT id FROM users WHERE username=?");
							ps.setString(1, username + "@" + settings.getString("domain"));
							rs = ps.executeQuery();
							if(rs.next()) {
								int id = rs.getInt("id");
								rs.close();
								ps.close();
								ps = conn.prepareStatement("UPDATE users SET firstname=?,surname=?,email=? WHERE id=?");
								if(firstname == null) {
									ps.setNull(1, Types.VARCHAR);
								} else {
									ps.setString(1, firstname);
								}
								if(surname == null) {
									ps.setNull(2, Types.VARCHAR);
								} else {
									ps.setString(2, surname);
								}
								if(email == null) {
									ps.setNull(3, Types.VARCHAR);
								} else {
									ps.setString(3, email);
								}
								ps.setInt(4, id);
								ps.executeUpdate();
							} else {
								rs.close();
								ps.close();
								ps = conn.prepareStatement("INSERT INTO users (firstname,surname,email,username) VALUES (?,?,?,?)");
								if(firstname == null) {
									ps.setNull(1, Types.VARCHAR);
								} else {
									ps.setString(1, firstname);
								}
								if(surname == null) {
									ps.setNull(2, Types.VARCHAR);
								} else {
									ps.setString(2, surname);
								}
								if(email == null) {
									ps.setNull(3, Types.VARCHAR);
								} else {
									ps.setString(3, email);
								}
								ps.setString(4, username + "@" + settings.getString("domain"));
								ps.executeUpdate();
							}
							return true;
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
					}
				} catch (AuthenticationException e) {
					// Not authenticated
					System.out.println("User is not authenticated");
				}
				if(settings.getBoolean("tls")) {
					tls.close();
				}
				ctx.close();
			}
		} catch (IOException | NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	private LdapContext getContext() throws IOException, NamingException {
		Hashtable<String, String> props = new Hashtable<>();
		if(settings == null) {
			return null;
		} else {
			props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			props.put(Context.PROVIDER_URL, settings.getString("url"));
			props.put(Context.SECURITY_AUTHENTICATION, settings.getString("authentication"));
			LdapContext ctx = new InitialLdapContext(props, null);
			return ctx;
		}
	}

	public static void main(String[] args) throws NamingException, IOException {

	}

	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}
	
	private String getAdGroup(String application, String role) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			conn = ds.getConnection();
			ps = conn.prepareStatement("SELECT adgroup FROM v_roles WHERE appname=? AND rolename=?");
			ps.setString(1, application);
			ps.setString(2, role);
			rs = ps.executeQuery();
			if(rs.next()) {
				return rs.getString("adgroup");
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

	@Override
	public boolean authorize(String username, String application, String role) {
		StartTlsResponse tls = null;
		String adGroup = getAdGroup(application, role);
		if(adGroup == null) {
			return false;
		}
		
		try {
			LdapContext ctx = getContext();
			if(ctx != null) {
				if(settings.getBoolean("tls")) {
					tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
					tls.negotiate();
				}
				ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, settings.getString("user"));
				ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, settings.getString("password"));
				
				String searchFilter = "(&(objectClass=user)(sAMAccountName=" + username + ")(memberOf:1.2.840.113556.1.4.1941:=" + adGroup + "))";
				SearchControls searchControls = new SearchControls();
				searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

				try {
					NamingEnumeration<SearchResult> results = ctx.search(settings.getString("baseDN"), searchFilter, searchControls);
					Connection conn = null;
					PreparedStatement ps = null;
					ResultSet rs = null;
					int roleId = 0;
					int userId = 0;
					try {
						
						conn = ds.getConnection();
						ps = conn.prepareStatement("SELECT id FROM v_roles WHERE appname=? AND rolename=?");
						ps.setString(1, application);
						ps.setString(2, role);
						rs = ps.executeQuery();
						if(rs.next()) {
							roleId = rs.getInt("id");
						}
						rs.close();
						ps.close();
						ps = conn.prepareStatement("SELECT id FROM users WHERE username=?");
						ps.setString(1, username + "@" + settings.getString("domain"));
						rs = ps.executeQuery();
						if(rs.next()) {
							userId = rs.getInt("id");
						}
						if(roleId == 0 || userId == 0) {
							return false;
						}
						if (results.hasMoreElements()) {
							rs.close();
							ps.close();
							ps = conn.prepareStatement("SELECT id FROM nn_users_roles WHERE deleted IS NULL AND fk_users=? AND fk_roles=?");
							ps.setInt(1, userId);
							ps.setInt(2, roleId);
							rs = ps.executeQuery();
							if(!rs.next()) {
								rs.close();
								ps.close();
								ps = conn.prepareStatement("INSERT INTO nn_users_roles (fk_users,fk_roles) VALUES (?,?)");
								ps.setInt(1, userId);
								ps.setInt(2, roleId);
								ps.executeUpdate();
							}
							return true;
						} else {
							rs.close();
							ps.close();
							ps = conn.prepareStatement("UPDATE nn_users_roles SET deleted=CURRENT_TIMESTAMP WHERE fk_users=? AND fk_roles=? AND deleted IS NULL");
							ps.setInt(1, userId);
							ps.setInt(2, roleId);
							ps.executeUpdate();
						}
						return false;
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
					
				} catch (AuthenticationException e) {
					// Not authenticated
					System.out.println("User is not authenticated");
				}
				if(settings.getBoolean("tls")) {
					tls.close();
				}
				ctx.close();
			}
		} catch (IOException | NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String getSuffix() {
		return "@" + settings.getString("domain");
	}

}
