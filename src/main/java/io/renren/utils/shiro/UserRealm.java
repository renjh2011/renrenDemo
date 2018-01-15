package io.renren.utils.shiro;

import com.alibaba.fastjson.JSONObject;
import com.qiniu.util.Json;
import io.jsonwebtoken.*;
import io.renren.entity.SysUserEntity;
import io.renren.entity.UserEntity;
import io.renren.service.SysMenuService;
import io.renren.service.SysUserService;
import io.renren.utils.Constants;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 认证
 * 
 * @author chenshun
 * @email sunlightcs@gmail.com
 * @date 2016年11月10日 上午11:55:49
 */
@Component
public class UserRealm extends AuthorizingRealm {
    @Autowired
    private SysUserService sysUserService;
    @Autowired
    private SysMenuService sysMenuService;
    @Autowired
	private RedisTemplate redisTemplate;

//    @Value("oauth2.client_id")
	private String clientId="c1ebe466-1cdc-4bd3-ab69-77c3561b9dee";
//	@Value("oauth2.client_secret")
	private String clientSecret="d8346ea2-6017-43ed-ad68-19c0f971738b";
//	@Value("oauth2.access_token_url")
	private String accessTokenUrl="http://192.168.0.182/access/accessToken";
//	@Value("oauth2.user_info_url")
	private String userInfoUrl="http://192.168.0.182/userInfo";
//	@Value("oauth2.redirect_url")
	private String redirectUrl="http://192.168.0.182:8089";

	public Class<?> getAuthenticationTokenClass() {
		return Oauth2Token.class;//此Realm只支持JwtToken
	}
    /**
     * 授权(验证权限时调用)
     */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		SysUserEntity user = (SysUserEntity)principals.getPrimaryPrincipal();
		Long userId = user.getUserId();

		//用户权限列表
		Set<String> permsSet = sysMenuService.getUserPermissions(userId);

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.setStringPermissions(permsSet);
		return info;
	}

	/**
	 * 认证(登录时调用)
	 */
	/*@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		JwtToken jwtToken = (JwtToken) token;
		String jwt = (String) jwtToken.getPrincipal();
		SysUserEntity userEntity;
		try {
			Claims claims = Jwts.parser()
					.setSigningKey(DatatypeConverter.parseBase64Binary(Constants.SECRETKEY))
					.parseClaimsJws(jwt)
					.getBody();
			userEntity = new SysUserEntity();
			userEntity.setUserId(claims.get("userId", Long.class));
			userEntity.setUsername(claims.get("username", String.class));// 用户名
//			userEntity.setRoleIdList(claims.get("roles", List.class));// 签发者
			userEntity.setMobile(claims.get("phone", String.class));// 签发者
		} catch (ExpiredJwtException e) {
			throw new AuthenticationException("JWT 令牌过期:" + e.getMessage());
		} catch (UnsupportedJwtException e) {
			throw new AuthenticationException("JWT 令牌无效:" + e.getMessage());
		} catch (MalformedJwtException e) {
			throw new AuthenticationException("JWT 令牌格式错误:" + e.getMessage());
		} catch (SignatureException e) {
			throw new AuthenticationException("JWT 令牌签名无效:" + e.getMessage());
		} catch (IllegalArgumentException e) {
			throw new AuthenticationException("JWT 令牌参数异常:" + e.getMessage());
		} catch (Exception e) {
			throw new AuthenticationException("JWT 令牌错误:" + e.getMessage());
		}
		// 如果要使token只能使用一次，此处可以过滤并缓存jwtPlayload.getId()
		// 可以做签发方验证
		// 可以做接收方验证
		return new SimpleAuthenticationInfo(userEntity, Boolean.TRUE, getName());
	}*/
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		Oauth2Token oauth2Token = (Oauth2Token) token;
		String accessToken = (String) oauth2Token.getPrincipal();
		String code = oauth2Token.getAuthCode(); //获取 auth code
		String username = extractUsername(code); // 提取用户名
		SimpleAuthenticationInfo authenticationInfo =
				new SimpleAuthenticationInfo(username, code, getName());
		return authenticationInfo;
	}

	private String extractUsername(String code) {
		try {
			OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
			OAuthClientRequest accessTokenRequest = OAuthClientRequest
					.tokenLocation(accessTokenUrl)
					.setGrantType(GrantType.AUTHORIZATION_CODE)
					.setClientId(clientId).setClientSecret(clientSecret)
					.setCode(code).setRedirectURI(redirectUrl)
					.buildQueryMessage();
			//获取access token
			OAuthAccessTokenResponse oAuthResponse =
					oAuthClient.accessToken(accessTokenRequest, OAuth.HttpMethod.POST);
			String accessToken = oAuthResponse.getAccessToken();
			Long expiresIn = oAuthResponse.getExpiresIn();
			//获取user info
			OAuthClientRequest userInfoRequest =
					new OAuthBearerClientRequest(userInfoUrl)
							.setAccessToken(accessToken).buildQueryMessage();
			OAuthResourceResponse resourceResponse = oAuthClient.resource(
					userInfoRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
			String body = resourceResponse.getBody();
			Map map= JSONObject.parseObject(body,Map.class);
			return (String) map.get("username");
		} catch (Exception e) {
			throw new AuthenticationException(e);
		}
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getAccessTokenUrl() {
		return accessTokenUrl;
	}

	public void setAccessTokenUrl(String accessTokenUrl) {
		this.accessTokenUrl = accessTokenUrl;
	}

	public String getUserInfoUrl() {
		return userInfoUrl;
	}

	public void setUserInfoUrl(String userInfoUrl) {
		this.userInfoUrl = userInfoUrl;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}
}
