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
  public static final String DEFAULT_JWT_PARAM = "token";

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
    HttpServletRequest req=(HttpServletRequest)request;
    String uri=req.getRequestURI();
    if(isJwtSubmission(request)){
      AuthenticationToken token = createToken(request, response);
      try {
        Subject subject = getSubject(request, response);
        subject.login(token);
        return true;
      } catch (AuthenticationException e) {
        WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED,e.getMessage());
      }
    }
    return false;
  }
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
    String jwt = request.getParameter(DEFAULT_JWT_PARAM);
    String host = request.getRemoteHost();
    System.out.println("jwt:"+jwt);
    return new JwtToken(jwt, host);
  }

  protected boolean isJwtSubmission(ServletRequest request) {
    String jwt = request.getParameter(DEFAULT_JWT_PARAM);
    return (request instanceof HttpServletRequest)
            && StringUtils.isNotBlank(jwt);
  }

  private void onLoginFail(ServletResponse response) throws IOException {
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);  
    httpResponse.getWriter().write("login error");  
  }  
}  