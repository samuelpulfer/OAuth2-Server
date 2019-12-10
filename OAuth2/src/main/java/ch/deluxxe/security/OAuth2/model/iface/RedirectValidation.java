package ch.deluxxe.security.OAuth2.model.iface;

public interface RedirectValidation {
	
	public boolean validate(String application, String redirectUri);

}
