package io.renren.admin;

import com.google.code.kaptcha.Constants;
import com.google.code.kaptcha.Producer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.renren.entity.SysUserEntity;
import io.renren.service.SysUserService;
import io.renren.utils.R;
import io.renren.utils.RedisUtils;
import io.renren.utils.ShiroUtils;
import io.renren.utils.shiro.JwtToken;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

/**
 * 登录相关
 * 
 * @author chenshun
 * @email sunlightcs@gmail.com
 * @date 2016年11月10日 下午1:15:31
 */
@Controller
public class SysLoginController {
	@Autowired
	private Producer producer;
	@Autowired
	private RedisTemplate redisTemplate;
	@Autowired
	private SysUserService sysUserService;
	
	@RequestMapping("captcha.jpg")
	public void captcha(HttpServletResponse response)throws ServletException, IOException {
        response.setHeader("Cache-Control", "no-store, no-cache");
        response.setContentType("image/jpeg");

        //生成文字验证码
        String text = producer.createText();
        //生成图片验证码
        BufferedImage image = producer.createImage(text);
        //保存到shiro session
//        ShiroUtils.setSessionAttribute(Constants.KAPTCHA_SESSION_KEY, text);
		RedisUtils.set(text,text,60l);
        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(image, "jpg", out);
		out.flush();
	}

	private static Key getKeyInstance() {
		//We will sign our JavaWebToken with our ApiKey secret
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(io.renren.utils.Constants.SECRETKEY);
		Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
		return signingKey;
	}

	public static String createJavaWebToken(Map<String, Object> claims) {
		return Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, getKeyInstance()).compact();
	}
	/**
	 * 登录
	 */
	@ResponseBody
	@RequestMapping(value = "/sys/login", method = RequestMethod.POST)
	public R login(HttpServletRequest request,String username, String password, String captcha)throws IOException {
		String jwt = request.getParameter("jwt");
		String host = request.getRemoteHost();
//		String kaptcha = ShiroUtils.getKaptcha(Constants.KAPTCHA_SESSION_KEY);
		String kaptcha = (String) RedisUtils.get(captcha);
		/*if(!captcha.equalsIgnoreCase(kaptcha)){
			return R.error("验证码不正确");
		}*/
		
		try{
			Subject subject = ShiroUtils.getSubject();
			SysUserEntity user = sysUserService.queryByUserName(username);
			if(user!=null) {
				Map<String,Object> m = new HashMap<String,Object>();
				m.put("username", user.getUsername());
				m.put("userId", user.getUserId());
				m.put("phone", user.getMobile());
				jwt=createJavaWebToken(m);
				AuthenticationToken token = new JwtToken(jwt, host);
				subject.login(token);
			}else {
				throw new AuthenticationException();
			}
		}catch (UnknownAccountException e) {
			return R.error(e.getMessage());
		}catch (IncorrectCredentialsException e) {
			return R.error(e.getMessage());
		}catch (LockedAccountException e) {
			return R.error(e.getMessage());
		}catch (AuthenticationException e) {
			e.printStackTrace();
			return R.error("账户验证失败");
		}
		Map<String, Object> map =new HashMap<>();
		map.put("token",jwt);
		return R.ok(map);
	}
	
	/**
	 * 退出
	 */
	@RequestMapping(value = "logout", method = RequestMethod.GET)
	public String logout() {
		ShiroUtils.logout();
		return "redirect:login.html";
	}
	
}
