package ch.deluxxe.security.OAuth2.OAuth2Web.presenter;

import ch.deluxxe.security.OAuth2.OAuth2Web.view.iface.LoginView;
import ch.deluxxe.security.OAuth2.OAuth2Web.view.iface.LoginView.LoginListener;
import ch.deluxxe.security.OAuth2.OAuth2Web.view.iface.LoginView.LoginRequest;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.Authentication;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.Authorization;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.RedirectValidation;

public class LoginPresenter implements LoginListener {

	private LoginView view = null;
	private Authentication authentication = null;
	private Authorization authorization = null;
	private RedirectValidation redirectValidation = null;
	private LoginRequest request = null;
	private OAuthCodeHelper codeHelper = null;
	
	public LoginPresenter(LoginView view, Authentication authentication, Authorization authorization, RedirectValidation redirectValidation, OAuthCodeHelper codeHelper) {
		this.view = view;
		this.authentication = authentication;
		this.authorization = authorization;
		this.redirectValidation = redirectValidation;
		this.codeHelper = codeHelper;
		view.addLoginListener(this);
	}
	
	@Override
	public void login(String username, String password) {
		if(username.contentEquals("") || password.equals("")) {
			view.setMessage("Bitte Benutzernamen und Passwort angeben.");
			return;
		}
		if(authentication.authenticate(username.toLowerCase(), password)) {
			if(authorization.authorize(username.toLowerCase(), request.getClientId(), "User")) {
				if(redirectValidation.validate(request.getClientId(),request.getRedirectUri())) {
					view.setMessage("Authenticated, authorized and redirect validated");
					//System.out.println(codeHelper.getCode(username, request.getClientId(), "User"));
					StringBuilder sb = new StringBuilder();
					sb.append(request.getRedirectUri());
					sb.append("?");
					sb.append("code=");
					sb.append(codeHelper.getAuthCode(username + authentication.getSuffix(), request.getClientId(), "User"));
					sb.append("&");
					sb.append("state=");
					sb.append(request.getState());
					view.redirect(sb.toString());
				} else {
					view.setMessage("Ungültige RedirectUri");
				}
			} else {
				view.setMessage("Sie sind für die App " + request.getClientId() + " nicht berechtigt");
			}
		} else {
			view.setMessage("Benutzername oder Passwort falsch.");
		}
	}

	@Override
	public void setLoginRequest(LoginRequest request) {
		this.request = request;
		if(this.request == null || !this.request.isValid()) {
			view.setApplication("Unbekannte Aplikation");
		}  else {
			view.setApplication(this.request.getClientId());
		}
	}
	

}
