package io.renren.utils.shiro;

import io.jsonwebtoken.*;
import io.renren.entity.SysUserEntity;
import io.renren.entity.UserEntity;
import io.renren.service.SysMenuService;
import io.renren.service.SysUserService;
import io.renren.utils.Constants;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.util.List;
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

	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;//此Realm只支持JwtToken
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
	@Override
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
	}

}
