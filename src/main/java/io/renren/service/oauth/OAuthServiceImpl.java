package io.renren.service.oauth;

import io.renren.utils.RedisUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

/**
 * <p>Date: 14-2-17
 * <p>Version: 1.0
 */
@Service("OAuthService")
public class OAuthServiceImpl implements OAuthService {

    @Autowired
    private ClientService clientService;

    @Override
    public void addAuthCode(String authCode, String username) {
        RedisUtils.set(authCode,username);
    }

    @Override
    public void addAccessToken(String accessToken, String username) {
        RedisUtils.set(accessToken,username);
    }

    @Override
    public String getUsernameByAuthCode(String authCode) {
        return (String) RedisUtils.get(authCode);
    }

    @Override
    public String getUsernameByAccessToken(String accessToken) {
        return null;
    }

    @Override
    public boolean checkAuthCode(String authCode) {
        return RedisUtils.get(authCode)!=null;
    }

    @Override
    public boolean checkAccessToken(String accessToken) {
        return RedisUtils.get(accessToken)!=null;
    }

    @Override
    public boolean checkClientId(String clientId) {
        return clientService.findByClientId(clientId) != null;
    }

    @Override
    public boolean checkClientSecret(String clientSecret) {
        return clientService.findByClientSecret(clientSecret) != null;
    }

    @Override
    public long getExpireIn() {
        return 3600L;
    }
}
