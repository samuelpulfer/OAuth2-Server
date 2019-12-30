package ch.deluxxe.security.OAuth2.OAuth2Web.view.route;

import java.util.List;
import java.util.Map;

import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.BeforeEvent;
import com.vaadin.flow.router.HasUrlParameter;
import com.vaadin.flow.router.OptionalParameter;
import com.vaadin.flow.router.Route;


import ch.deluxxe.security.OAuth2.OAuth2Web.view.iface.LoginView.LoginRequest;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.ADAuth;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.DBRedirectValidation;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.OAuthCodeHelperImpl;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.ResponseType;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.Authentication;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.Authorization;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.RedirectValidation;
import ch.deluxxe.security.OAuth2.OAuth2Web.presenter.LoginPresenter;
import ch.deluxxe.security.OAuth2.OAuth2Web.view.LoginViewImpl;
import ch.deluxxe.security.OAuth2.OAuth2Web.view.iface.LoginView.LoginListener;

@Route("Login")
public class Login extends VerticalLayout implements HasUrlParameter<String> {
	
	/**
	 * Generated Serial Version ID
	 */
	private static final long serialVersionUID = 439459123323570176L;
	private LoginRequest loginRequest = null;
	private LoginListener loginListener = null;

	private class LoginRequestImpl implements LoginRequest {
		
		private String responseType = null;
		// App Name
		private String clientId = null;
		private String redirectUri = null;
		private String deviceId = null;
		private String state = null;
		
		public LoginRequestImpl(String responseType, String clientId, String redirectUri, String deviceId, String state) {
			this.responseType = responseType;
			this.clientId = clientId;
			this.redirectUri = redirectUri;
			this.deviceId = deviceId;
		}

		@Override
		public ResponseType getResponseType() {
			return ResponseType.valueOf(responseType);
		}

		@Override
		public String getClientId() {
			return clientId;
		}

		@Override
		public String getRedirectUri() {
			return redirectUri;
		}

		@Override
		public String getDeviceId() {
			return deviceId;
		}

		@Override
		public boolean isValid() {
			if(clientId != null && !clientId.equals("") && responseType != null && !responseType.equals("") && redirectUri != null && !redirectUri.equals("")) {
				return true;
			}
			return false;
		}

		@Override
		public String getState() {
			if(state == null) {
				return "none";
			} else {
				return state;
			}
		}
		
	}
	
	
	public Login() {
		//Authentication authentication = new DBAuthentication();
		//Authorization authorization = new DBAuthorization();
		Authentication authentication = new ADAuth();
		Authorization authorization = new ADAuth();
		RedirectValidation redirectValidation = new DBRedirectValidation();
		OAuthCodeHelper codeHelper = new OAuthCodeHelperImpl();
		LoginViewImpl view = new LoginViewImpl();
		loginListener = new LoginPresenter(view,authentication,authorization,redirectValidation,codeHelper);
		add(view);
	}
	
	@Override
	public void setParameter(BeforeEvent event, @OptionalParameter String parameter) {
		System.out.println(event.getLocation().getQueryParameters().getQueryString());
		Map<String, List<String>> parametersMap = event.getLocation().getQueryParameters().getParameters();
		if(parametersMap.size() > 0) {
			String responseType = null;
			String clientId = null;
			String redirectUrl = null;
			String deviceId = null;
			String state = null;
			if(parametersMap.get("response_type") != null) {
				responseType = parametersMap.get("response_type").get(0);
			}
			if(parametersMap.get("client_id") != null) {
				clientId = parametersMap.get("client_id").get(0);
			}
			if(parametersMap.get("redirect_uri") != null) {
				redirectUrl = parametersMap.get("redirect_uri").get(0);
			}
			if(parametersMap.get("device_id") != null) {
				deviceId = parametersMap.get("device_id").get(0);
			}
			if(parametersMap.get("state") != null) {
				deviceId = parametersMap.get("state").get(0);
			}
			loginRequest = new LoginRequestImpl(responseType,clientId,redirectUrl,deviceId,state);
			loginListener.setLoginRequest(loginRequest);
			
		}
		
	}

}
