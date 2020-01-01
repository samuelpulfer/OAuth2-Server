package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

/** Validates OAuth2 redirects
 * @author Samuel Pulfer
 *
 */
public interface RedirectValidation {
	
	/** Validates the OAuth2 redirect
	 * @param application The application
	 * @param redirectUri The redirect URI to validate.
	 * @return true if redirect is valid else false
	 */
	public boolean validate(String application, String redirectUri);

}
