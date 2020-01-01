package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

/**
 * Interface to authenticate user.
 * @author Samuel Pulfer
 *
 */
public interface Authentication {
	
	/**
	 * Authenticate a user.
	 * @param username The username
	 * @param password The password
	 * @return true if authenticated else false
	 */
	public boolean authenticate(String username, String password);
	/**
	 * gets the suffix of the Authentication realm. For ActiveDirectory authentication this may be the domain name.
	 * @return The suffix of the Authentication realm.
	 */
	public String getSuffix();
	/**
	 * Closes the authentication (maybe to close DB or ActiveDirectory connections)
	 */
	public void close();

}
