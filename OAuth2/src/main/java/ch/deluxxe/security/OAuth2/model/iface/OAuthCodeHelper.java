package ch.deluxxe.security.OAuth2.model.iface;

public interface OAuthCodeHelper {
	
	public String getCode(String username, String application, String role);

}
