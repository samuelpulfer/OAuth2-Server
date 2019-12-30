package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

public interface RedirectValidation {
	
	public boolean validate(String application, String redirectUri);

}
