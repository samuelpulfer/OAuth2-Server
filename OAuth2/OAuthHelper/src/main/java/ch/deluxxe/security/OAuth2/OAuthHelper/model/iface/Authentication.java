package ch.deluxxe.security.OAuth2.OAuthHelper.model.iface;

public interface Authentication {
	
	public boolean authenticate(String username, String password);
	public String getSuffix();
	public void close();

}
