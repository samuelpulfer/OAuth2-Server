package ch.deluxxe.security.OAuth2.OAuthHelper.view.iface;

/** Interface to an OAuthInfo object.
 * @author Samuel Pulfer
 *
 */
public interface OAuthInfo {
	
	/** Gets the application.
	 * @return The application.
	 */
	public String getApplication();
	/** Gets the role.
	 * @return The role.
	 */
	public String getRole();
	/** Gets the username.
	 * @return The username.
	 */
	public String getUsername();
	/** Gets the user id.
	 * @return the user id.
	 */
	public int getUserid();
	/** Gets the access code.
	 * @return the access code.
	 */
	public String getAccessCode();

}
