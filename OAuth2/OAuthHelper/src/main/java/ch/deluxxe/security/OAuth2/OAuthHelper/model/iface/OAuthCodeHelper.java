package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.GrantType;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.iface.OAuthInfo;



/**
 * Interface to handle OAuth codes and tokens.
 * @author Samuel Pulfer
 *
 */
public interface OAuthCodeHelper {
	/**
	 * Interface to an immutable OAuthCodePair containing access and refresh tokens
	 * @author Samuel Pulfer
	 *
	 */
	interface OAuthCodePair {
		/** Retrieves the access token
		 * @return The access token
		 */
		public String getAccessToken();
		/** Retrieves the access token as JWT
		 * @return The access token as JWT
		 */
		public String getJWTAccessToken();
		/** Retrieves the refresh token
		 * @return The refresh token.
		 */
		public String getRefreshToken();
		/** Retrieves the refresh token as JWT
		 * @return The refresh token as JWT
		 */
		public String getJWTRefreshToken();
	}
	
	/** Gets the AuthCode for specified user, application and role.
	 * @param username The username.
	 * @param application The application.
	 * @param role The role
	 * @return the AuthCode or null if not found, redeemed or expired.
	 */
	public String getAuthCode(String username, String application, String role);
	/** Gets the AuthCodePair for the specified code and GrandType.
	 * @param code The code.
	 * @param grantType The grantRype
	 * @return The AuthCodePair for the specified code and GrandType.
	 */
	public OAuthCodePair getToken(String code, GrantType grantType);
	/**
	 * Validates a access token
	 * @param code The access tokken
	 * @return true if valid else false
	 */
	public boolean validate(String code);
	/** Gets the an OpenId connect user object as JSON
	 * @param code The access token
	 * @return The OpenID connect user object as JSON
	 */
	public JSONObject getUserinfo(String code);
	/** Gets an OAuthInfo object containing informations about the user and role.
	 * @param code The access token
	 * @return The OAuthInfo object containing informations about the user and role.
	 */
	public OAuthInfo getOAuthInfo(String code);

}
