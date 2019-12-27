package ch.deluxxe.security.OAuth2.view.route;

import java.io.IOException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.model.OAuthCodeHelperImpl;
import ch.deluxxe.security.OAuth2.model.iface.OAuthCodeHelper;

/**
 * Servlet implementation class UserInfo
 */
@WebServlet("/userinfo")
public class UserInfo extends HttpServlet {
	private static final long serialVersionUID = 1L;
	OAuthCodeHelper codeHelper = null;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public UserInfo() {
        super();
        // TODO Auto-generated constructor stub
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
		JSONObject userinfo = null;
		String authHeader = request.getHeader("Authorization");
		if(authHeader != null && authHeader.split(" ").length == 2) {
			 userinfo = codeHelper.getUserinfo(authHeader.split(" ")[1]);
		}
		if(userinfo != null) {
			response.setHeader("Content-Type", "application/json");
			response.getWriter().append(userinfo.toString());
		} else {
			response.sendError(401, "The Access Token expired");
		}
	}

	@Override
	protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD");
		resp.addHeader("Access-Control-Allow-Headers", "Accept, Authorization");
		resp.setStatus(HttpServletResponse.SC_ACCEPTED);
		return;
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}
