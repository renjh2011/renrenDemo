package io.renren.admin.oauth;

import io.renren.entity.SysUserEntity;
import io.renren.service.SysUserService;
import io.renren.service.oauth.ClientService;
import io.renren.service.oauth.OAuthService;
import io.renren.utils.Constants;
import io.renren.utils.R;
import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Date: 14-2-16
 * <p>Version: 1.0
 */
@Controller
@RequestMapping("/oauth")
@ResponseBody
public class AuthorizeController {

    @Autowired
    private OAuthService oAuthService;
    @Autowired
    private ClientService clientService;
    @Autowired
    private SysUserService sysUserService;

    @RequestMapping("/authorize")
    public Map<String,Object> authorize(
            Model model,
            HttpServletRequest request,
            HttpServletResponse httpResponse)
            throws URISyntaxException, OAuthSystemException {

        try {
            //构建OAuth 授权请求
            OAuthAuthzRequest oauthRequest = new OAuthAuthzRequest(request);

            //检查传入的客户端id是否正确
            if (!oAuthService.checkClientId(oauthRequest.getClientId())) {
                OAuthResponse response =
                        OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                                .setError(OAuthError.TokenResponse.INVALID_CLIENT)
                                .setErrorDescription(Constants.INVALID_CLIENT_DESCRIPTION)
                                .buildJSONMessage();
//                return new ResponseEntity(response.getBody(), HttpStatus.valueOf(response.getResponseStatus()));

                return R.error(response.getResponseStatus(),response.getBody());
            }


            Subject subject = SecurityUtils.getSubject();
            //如果用户没有登录，跳转到登陆页面
            SysUserEntity sysUserEntity = null;
            if(!subject.isAuthenticated()) {
                if((sysUserEntity=login(subject, request))==null) {//登录失败时跳转到登陆页面
                   /* model.addAttribute("client", clientService.findByClientId(oauthRequest.getClientId()));
                    return "oauth2login";*/
                   Map<String,Object> map=new HashMap<>();
                   map.put("client_id",clientService.findByClientId(oauthRequest.getClientId()).getClientId());
                   httpResponse.sendRedirect("http://192.168.0.182/login.html");
                   return R.ok(map);
                }
            }

            //生成授权码
            String authorizationCode = null;
            //responseType目前仅支持CODE，另外还有TOKEN
            String responseType = oauthRequest.getParam(OAuth.OAUTH_RESPONSE_TYPE);
            if (responseType.equals(ResponseType.CODE.toString())) {
                OAuthIssuerImpl oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
                authorizationCode = oauthIssuerImpl.authorizationCode();
                oAuthService.addAuthCode(authorizationCode, sysUserEntity.getUsername());
            }

            //进行OAuth响应构建
            OAuthASResponse.OAuthAuthorizationResponseBuilder builder =
                    OAuthASResponse.authorizationResponse(request, HttpServletResponse.SC_FOUND);
            //设置授权码
            builder.setCode(authorizationCode);
            //得到到客户端重定向地址
            String redirectURI = oauthRequest.getParam(OAuth.OAUTH_REDIRECT_URI);

            //构建响应
            final OAuthResponse response = builder.location(redirectURI).buildQueryMessage();

            //根据OAuthResponse返回ResponseEntity响应
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(new URI(response.getLocationUri()));
            Map<String,Object> map=new HashMap<>();
            map.put("URI",response.getLocationUri());
            map.put("code",response.getResponseStatus());
            map.put("headers",headers);

//            return new ResponseEntity(headers, HttpStatus.valueOf(response.getResponseStatus()));
            return R.ok(map);
        } catch (OAuthProblemException e) {

            //出错处理
            String redirectUri = e.getRedirectUri();
            if (OAuthUtils.isEmpty(redirectUri)) {
                //告诉客户端没有传入redirectUri直接报错
//                return new ResponseEntity("OAuth callback url needs to be provided by client!!!", HttpStatus.NOT_FOUND);
                return R.error(HttpStatus.NOT_FOUND.value(),"OAuth callback url needs to be provided by client!!!");
            }

            //返回错误消息（如?error=）
            final OAuthResponse response =
                    OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
                            .error(e).location(redirectUri).buildQueryMessage();
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(new URI(response.getLocationUri()));
//            return new ResponseEntity(headers, HttpStatus.valueOf(response.getResponseStatus()));
            return R.error(response.getResponseStatus(),headers.toString());
        } catch (IOException e) {
            e.printStackTrace();
            return R.error("1203");
        }
    }

    private SysUserEntity login(Subject subject, HttpServletRequest request) {
        String username=request.getParameter("username");
        String password=request.getParameter("password");
        try{
            SysUserEntity user = sysUserService.queryByUserName(username);
            if(user!=null) {
                Map<String,Object> m = new HashMap<String,Object>();
                m.put("username", user.getUsername());
                m.put("userId", user.getUserId());
                m.put("phone", user.getMobile());
                //todo
                //验证密码是否正确
                return user;
            }else {
                throw new AuthenticationException();
            }
        }catch (UnknownAccountException e) {
            e.printStackTrace();
        }catch (IncorrectCredentialsException e) {
            e.printStackTrace();
        }catch (LockedAccountException e) {
            e.printStackTrace();
        }catch (AuthenticationException e) {
            e.printStackTrace();
        }
        return null;
    }
}