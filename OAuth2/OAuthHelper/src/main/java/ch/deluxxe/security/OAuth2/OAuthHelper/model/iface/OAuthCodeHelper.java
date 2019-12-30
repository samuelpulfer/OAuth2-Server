package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.GrantType;



public interface OAuthCodeHelper {
	interface OAuthCodePair {
		public String getAccessToken();
		public String getJWTAccessToken();
		public String getRefreshToken();
		public String getJWTRefreshToken();
	}
	
	public String getAuthCode(String username, String application, String role);
	public OAuthCodePair getToken(String code, GrantType grantType);
	public boolean validate(String code);
	public JSONObject getUserinfo(String code);

}
