package ch.deluxxe.security.OAuth2.OAuth2Web.view.route;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.OAuthCodeHelperImpl;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.OAuthServlet;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.iface.OAuthInfo;


/**
 * Servlet implementation class UserInfo
 */
@WebServlet("/userinfo")
public class UserInfo extends OAuthServlet {
	private static final long serialVersionUID = 1L;
	OAuthCodeHelper codeHelper = null;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public UserInfo() {
        super();
        codeHelper = new OAuthCodeHelperImpl();
    }


    @Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response, OAuthInfo info) throws ServletException, IOException {
    	System.out.println("Application: " + info.getApplication());
    	System.out.println("Role: " + info.getRole());
    	System.out.println("Username: " + info.getUsername());
    	
    	response.setHeader("Content-Type", "application/json");
    	JSONObject jo = codeHelper.getUserinfo(info.getAccessCode());
    	if(jo != null) {
    		response.getWriter().append(jo.toString());
    	} else {
    		response.getWriter().append("{}");
    	}
    	

	}

}
