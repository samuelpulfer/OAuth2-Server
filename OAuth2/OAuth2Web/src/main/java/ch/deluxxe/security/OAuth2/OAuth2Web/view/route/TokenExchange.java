package ch.deluxxe.security.OAuth2.OAuth2Web.view.route;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.GrantType;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.OAuthCodeHelperImpl;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper.OAuthCodePair;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.OAuthServlet;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.iface.OAuthInfo;



/**
 * Servlet implementation class TokenExchange
 */
@WebServlet("/token")
public class TokenExchange extends OAuthServlet {
	private static final long serialVersionUID = 1L;
	OAuthCodeHelper codeHelper = null;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public TokenExchange() {
        super();
        codeHelper = new OAuthCodeHelperImpl();
    }


	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response, OAuthInfo info) throws ServletException, IOException {
		
		response.sendError(HttpServletResponse.SC_NO_CONTENT);
	}


	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("POST");
		response.addHeader("Access-Control-Allow-Origin", "*");
		GrantType grantType = GrantType.valueOf(request.getParameter("grant_type"));
		System.out.println(grantType.toString());
		String redirectUri = request.getParameter("redirect_uri");
		System.out.println(redirectUri);
		String clientId = request.getParameter("client_id");
		System.out.println(clientId);
		String code = request.getParameter("code");
		System.out.println(code);
		
		OAuthCodePair pair = codeHelper.getToken(code, grantType);
		
		if(pair == null) {
			System.out.println("Pair is null...");
			response.sendError(511);
		} else {
			JSONObject jo = new JSONObject();
			jo.put("state", "none");
			jo.put("access_token", pair.getJWTAccessToken());
			jo.put("token_type", "Bearer");
			jo.put("scope", "*.*");
			jo.put("expires_in", 20160);
			jo.put("refresh_token", pair.getJWTRefreshToken());
			response.setHeader("Content-Type", "application/json");
			response.getWriter().append(jo.toString());
			return;
		}
		
		
	}

}
