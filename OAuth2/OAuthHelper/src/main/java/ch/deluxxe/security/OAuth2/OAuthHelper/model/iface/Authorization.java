package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

/**
 * Interface to authorize user.
 * @author Samuel Pulfer
 *
 */
public interface Authorization {

	/**
	 * Authorizes user for a specified application and role.
	 * @param username The username.
	 * @param application The application
	 * @param role The role
	 * @return true if authorized else false;
	 */
	public boolean authorize(String username, String application, String role);
	/**
	 * Closes the authorization (maybe to close DB or ActiveDirectory connections)
	 */
	public void close();
}
