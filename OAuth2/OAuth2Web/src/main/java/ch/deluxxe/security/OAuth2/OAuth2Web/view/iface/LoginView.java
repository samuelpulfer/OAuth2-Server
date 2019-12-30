package ch.deluxxe.security.OAuth2.OAuth2Web.view.iface;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.ResponseType;

public interface LoginView {
	
	interface LoginListener {
		void login(String username, String password);
		void setLoginRequest(LoginRequest request);
	}
	interface LoginRequest {
		public ResponseType getResponseType();
		public String getClientId();
		public String getRedirectUri();
		public String getDeviceId();
		public String getState();
		public boolean isValid();
	}
	
	public void setMessage(String message);
	public void setApplication(String application);
	public void redirect(String uri);
	
	public void addLoginListener(LoginListener listener);
	public void removeLoginListener(LoginListener listener);

}
