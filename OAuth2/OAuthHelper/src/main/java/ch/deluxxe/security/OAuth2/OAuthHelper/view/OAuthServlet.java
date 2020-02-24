package ch.deluxxe.security.OAuth2.OAuthHelper.view;

import java.io.IOException;
import java.lang.reflect.Method;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ch.deluxxe.security.OAuth2.OAuthHelper.model.OAuthCodeHelperImpl;
import ch.deluxxe.security.OAuth2.OAuthHelper.model.iface.OAuthCodeHelper;
import ch.deluxxe.security.OAuth2.OAuthHelper.view.iface.OAuthInfo;

/** An abstract class extending the HttpServlet with usefull OAuth helpers.
 * If you like to handle a request method with first checking the Authorization overwrite for example the doGet(HttpServletRequest req, HttpServletResponse resp, OAuthInfo info). If you don't care about authorization override the doGet(HttpServletRequest req, HttpServletResponse resp) method.
 * @author Samuel Pulfer
 *
 */
public abstract class OAuthServlet extends HttpServlet {

	/**
	 * Default Serial Version UID
	 */
	private static final long serialVersionUID = 1L;
	private static final String METHOD_DELETE = "DELETE";
	private static final String METHOD_HEAD = "HEAD";
	private static final String METHOD_GET = "GET";
	private static final String METHOD_OPTIONS = "OPTIONS";
	private static final String METHOD_POST = "POST";
	private static final String METHOD_PUT = "PUT";
	private static final String METHOD_TRACE = "TRACE";
	
	private boolean ALLOW_GET = false;
	private boolean ALLOW_HEAD = false;
	private boolean ALLOW_POST = false;
	private boolean ALLOW_PUT = false;
	private boolean ALLOW_DELETE = false;
	private boolean ALLOW_TRACE = true;
	private boolean ALLOW_OPTIONS = true;

	private String allowedMethods = null;
	
	private OAuthCodeHelper codeHelper = null;

	/**
	 * Constructs the Object with information about the overwritten methods.
	 * If the constructor is overwritten and doesn't call super() this class will not work properly!!!
	 */
	public OAuthServlet() {
		super();
		getAllDeclaredMethods(this.getClass());
		codeHelper = new OAuthCodeHelperImpl();
	}

	/**
	 * Gets all declared Methods of class c.
	 * @param c The class which extends OAuthServlet.
	 */
	private void getAllDeclaredMethods(Class<? extends OAuthServlet> c) {

		Class<?> clazz = c;
		Method[] allMethods = null;

		while (!clazz.equals(OAuthServlet.class)) {
			Method[] thisMethods = clazz.getDeclaredMethods();
			if (allMethods != null && allMethods.length > 0) {
				Method[] subClassMethods = allMethods;
				allMethods = new Method[thisMethods.length + subClassMethods.length];
				System.arraycopy(thisMethods, 0, allMethods, 0, thisMethods.length);
				System.arraycopy(subClassMethods, 0, allMethods, thisMethods.length, subClassMethods.length);
			} else {
				allMethods = thisMethods;
			}

			clazz = clazz.getSuperclass();
		}

		if(allMethods == null) {
			return;
		}
		for (int i = 0; i < allMethods.length; i++) {
			String methodName = allMethods[i].getName();

			if (methodName.equals("doGet")) {
				ALLOW_GET = true;
				ALLOW_HEAD = true;
			} else if (methodName.equals("doPost")) {
				ALLOW_POST = true;
			} else if (methodName.equals("doPut")) {
				ALLOW_PUT = true;
			} else if (methodName.equals("doDelete")) {
				ALLOW_DELETE = true;
			}

		}

		// we know "allow" is not null as ALLOW_OPTIONS = true
		// when this method is invoked
		StringBuilder allow = new StringBuilder();
		if (ALLOW_GET) {
			allow.append(METHOD_GET);
		}
		if (ALLOW_HEAD) {
			if (allow.length() > 0) {
				allow.append(", ");
			}
			allow.append(METHOD_HEAD);
		}
		if (ALLOW_POST) {
			if (allow.length() > 0) {
				allow.append(", ");
			}
			allow.append(METHOD_POST);
		}
		if (ALLOW_PUT) {
			if (allow.length() > 0) {
				allow.append(", ");
			}
			allow.append(METHOD_PUT);
		}
		if (ALLOW_DELETE) {
			if (allow.length() > 0) {
				allow.append(", ");
			}
			allow.append(METHOD_DELETE);
		}
		if (ALLOW_TRACE) {
			if (allow.length() > 0) {
				allow.append(", ");
			}
			allow.append(METHOD_TRACE);
		}
		if (ALLOW_OPTIONS) {
			if (allow.length() > 0) {
				allow.append(", ");
			}
			allow.append(METHOD_OPTIONS);
		}
		this.allowedMethods = allow.toString();
	}
	
	/** Gets the Authorization Header from request and retrieves the corresponding OAuthInfo.
	 * @param req The request.
	 * @return The OAuthInfo for this request.
	 */
	private OAuthInfo getOAuthInfo(HttpServletRequest req) {
		return codeHelper.getOAuthInfo(req.getHeader("Authorization"));
	}

	/** Sets allowed origin for CORS to *.
	 * @param resp
	 */
	protected void setCORS(HttpServletResponse resp) {
		resp.setHeader("Access-Control-Allow-Origin", "*");
	}

	@Override
	protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setHeader("Allow", this.allowedMethods);
		setCORS(resp);
		resp.setHeader("Access-Control-Allow-Methods", this.allowedMethods);
		resp.setHeader("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type");
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		setCORS(resp);
		if(!ALLOW_GET) {
			super.doGet(req, resp);
		}
		OAuthInfo info = getOAuthInfo(req);
		if(info == null) {
			resp.setHeader("WWW-Authenticate", "Bearer");
			resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The Access Token expired or was not present");
			return;
		}
		doGet(req, resp, info);
	}

	/** Will be called after a doGet(HttpServletRequest req, HttpServletResponse resp) ONLY if doDelete(HttpServletRequest req, HttpServletResponse resp) was not overwritten! Override this function to handle GET request.
	 * @param req The request.
	 * @param resp The response.
	 * @param info The OAuthInfo about the request.
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse resp, OAuthInfo info) throws ServletException, IOException {

	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		setCORS(resp);
		if(!ALLOW_POST) {
			super.doPost(req, resp);
		}
		OAuthInfo info = getOAuthInfo(req);
		if(info == null) {
			resp.setHeader("WWW-Authenticate", "Bearer");
			resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The Access Token expired or was not present");
			return;
		}
		doPost(req, resp, info);
	}
	
	/** Will be called after a doPost(HttpServletRequest req, HttpServletResponse resp) ONLY if doDelete(HttpServletRequest req, HttpServletResponse resp) was not overwritten! Override this function to handle POST request.
	 * @param req The request.
	 * @param resp The request.
	 * @param info The OAuthInfo about the request.
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void doPost(HttpServletRequest req, HttpServletResponse resp, OAuthInfo info) throws ServletException, IOException {
		
	}
	
	@Override
	protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		setCORS(resp);
		if(!ALLOW_PUT) {
			super.doPut(req, resp);
		}
		OAuthInfo info = getOAuthInfo(req);
		if(info == null) {
			resp.setHeader("WWW-Authenticate", "Bearer");
			resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The Access Token expired or was not present");
			return;
		}
		doPut(req, resp, info);
	}
	
	/** Will be called after a doPut(HttpServletRequest req, HttpServletResponse resp) ONLY if doDelete(HttpServletRequest req, HttpServletResponse resp) was not overwritten! Override this function to handle PUT request.
	 * @param req The request.
	 * @param resp The request.
	 * @param info The OAuthInfo about the request.
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void doPut(HttpServletRequest req, HttpServletResponse resp, OAuthInfo info) throws ServletException, IOException {
		
	}

	@Override
	protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		setCORS(resp);
		if(!ALLOW_DELETE) {
			super.doPut(req, resp);
		}
		OAuthInfo info = getOAuthInfo(req);
		if(info == null) {
			resp.setHeader("WWW-Authenticate", "Bearer");
			resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The Access Token expired or was not present");
			return;
		}
		doDelete(req, resp, info);
	}
	
	/** Will be called after a doDelete(HttpServletRequest req, HttpServletResponse resp) ONLY if doDelete(HttpServletRequest req, HttpServletResponse resp) was not overwritten! Override this function to handle DELETE request.
	 * @param req The request.
	 * @param resp The request.
	 * @param info The OAuthInfo about the request.
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void doDelete(HttpServletRequest req, HttpServletResponse resp, OAuthInfo info) throws ServletException, IOException {
		
	}
}
