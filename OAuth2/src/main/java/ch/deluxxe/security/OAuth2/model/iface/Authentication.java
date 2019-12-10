package ch.deluxxe.security.OAuth2.model.iface;

public interface Authentication {
	
	public boolean authenticate(String username, String password);

}
