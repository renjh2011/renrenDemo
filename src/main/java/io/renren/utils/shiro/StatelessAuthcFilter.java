package io.renren.utils.shiro;

import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class StatelessAuthcFilter extends AccessControlFilter {
//    public static final String DEFAULT_JWT_PARAM = "access_token";
    public static final String AUTH_CODE_PARAM = "authCode";

    /* protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue){
         return false;
     }*/
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        if (null != getSubject(request, response)
                && getSubject(request, response).isAuthenticated()) {
            return true;
        }
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest req = (HttpServletRequest) request;
        String url = req.getRequestURL().toString();
        Subject subject = getSubject(request, response);
        if (isAccessTokenSubmission(request)) {
            AuthenticationToken token = createOAuth2Token(request, response);
            try {
                subject.login(token);
                return true;
            } catch (AuthenticationException e) {
                WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
            }
        }else{
            String loginUrl = this.getLoginUrl() + "?redirectUrl=" + url;
            //如果用户没有身份验证，且没有auth code，则重定向到服务端授权
            WebUtils.issueRedirect(request, response, loginUrl);
            //                saveRequestAndRedirectToLogin(request, response);
            return false;
        }
        return false;
    }

    /*protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String jwt = request.getParameter(DEFAULT_JWT_PARAM);
        String host = request.getRemoteHost();
        System.out.println("jwt:" + jwt);
        return new JwtToken(jwt, host);
    }*/

    /*protected boolean isJwtSubmission(ServletRequest request) {
        String jwt = request.getParameter(DEFAULT_JWT_PARAM);
        return (request instanceof HttpServletRequest)
                && StringUtils.isNotBlank(jwt);
    }*/

    protected AuthenticationToken createOAuth2Token(ServletRequest request, ServletResponse response) {
        String authCode = request.getParameter(AUTH_CODE_PARAM);
        String host = request.getRemoteHost();
        return new Oauth2Token(authCode, host);
    }

    protected boolean isAccessTokenSubmission(ServletRequest request) {
        String accessToken = request.getParameter(AUTH_CODE_PARAM);
        return (request instanceof HttpServletRequest)
                && StringUtils.isNotBlank(accessToken);
    }

    private void onLoginFail(ServletResponse response) throws IOException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.getWriter().write("login error");
    }
}  