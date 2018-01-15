package io.renren.utils.shiro;

import org.apache.shiro.authc.AuthenticationToken;

public class Oauth2Token implements AuthenticationToken {

    private static final long serialVersionUID = -790191688300000066L;

    private String authCode;// json web token
    private String host;// 客户端IP

    public Oauth2Token(String authCode, String host){
        this.authCode = authCode;
        this.host = host;
    }

    @Override
    public Object getPrincipal() {
        return this.authCode;
    }

    @Override
    public Object getCredentials() {
        return Boolean.TRUE;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }
}