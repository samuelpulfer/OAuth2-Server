package ch.deluxxe.security.OAuth2.OAuth2Web.view.route;

import java.io.IOException;
import javax.servlet.ServletConfig;
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



/**
 * Servlet implementation class TokenExchange
 */
@WebServlet("/token")
public class TokenExchange extends HttpServlet {
	private static final long serialVersionUID = 1L;
	OAuthCodeHelper codeHelper = null;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public TokenExchange() {
        super();
        
    }

	/**
	 * @see Servlet#init(ServletConfig)
	 */
	public void init(ServletConfig config) throws ServletException {
		codeHelper = new OAuthCodeHelperImpl();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.addHeader("Access-Control-Allow-Origin", "*");
		boolean valid = false;
		String authHeader = request.getHeader("Authorization");
		if(authHeader != null && authHeader.split(" ").length == 2) {
			 valid = codeHelper.validate(authHeader.split(" ")[1]);
		}
		if(valid) {
			response.setStatus(200);
		} else {
			response.sendError(401, "The Access Token expired");
		}
	}

	@Override
	protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD, POST");
		resp.addHeader("Access-Control-Allow-Headers", "Accept, Authorization");
		resp.setStatus(HttpServletResponse.SC_ACCEPTED);
		return;
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
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
