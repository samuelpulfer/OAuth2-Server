package ch.deluxxe.security.OAuth2.model.iface;

public interface Authorization {

	public boolean authorize(String username, String application, String role);

}
