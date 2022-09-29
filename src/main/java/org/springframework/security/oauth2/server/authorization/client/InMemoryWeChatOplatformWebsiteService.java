package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.WeChatOplatformWebsiteAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatOplatformParameterNames;
import org.springframework.security.oauth2.server.authorization.exception.RedirectWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOplatformWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2WeChatOplatformWebsiteEndpointUtils;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 微信开放平台 网站应用 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryWeChatOplatformWebsiteService implements WeChatOplatformWebsiteService {

	private final List<WeChatOplatformWebsiteProperties.WeChatOplatformWebsite> weChatOplatformWebsiteList;

	/**
	 * 默认 微信开放平台 网站应用 的权限
	 * <p>
	 * 若要自定义用户的权限，请开发者自己实现 {@link WeChatOplatformWebsiteService}
	 */
	private final String defaultRole;

	public InMemoryWeChatOplatformWebsiteService(
			List<WeChatOplatformWebsiteProperties.WeChatOplatformWebsite> weChatOplatformWebsiteList,
			String defaultRole) {
		this.weChatOplatformWebsiteList = weChatOplatformWebsiteList;
		this.defaultRole = defaultRole;
	}

	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(defaultRole);
		authorities.add(authority);
		User user = new User(openid, accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		WeChatOplatformWebsiteAuthenticationToken authenticationToken = new WeChatOplatformWebsiteAuthenticationToken(
				authorities, clientPrincipal, principal, user, additionalParameters, details, appid, code, openid);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionid(unionid);

		return authenticationToken;
	}

	@Override
	public WeChatOplatformWebsiteTokenResponse getAccessTokenResponse(String appid, String code,
			String accessTokenUrl) {
		Map<String, String> uriVariables = new HashMap<>(8);
		uriVariables.put(OAuth2WeChatOplatformParameterNames.APPID, appid);

		String secret = getSecretByAppid(appid);

		uriVariables.put(OAuth2WeChatOplatformParameterNames.SECRET, secret);
		uriVariables.put(OAuth2WeChatOplatformParameterNames.CODE, code);

		RestTemplate restTemplate = new RestTemplate();

		String forObject = restTemplate.getForObject(accessTokenUrl, String.class, uriVariables);

		WeChatOplatformWebsiteTokenResponse weChatOplatformWebsiteTokenResponse;
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			weChatOplatformWebsiteTokenResponse = objectMapper.readValue(forObject,
					WeChatOplatformWebsiteTokenResponse.class);
		}
		catch (JsonProcessingException e) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatOplatformWebsiteEndpointUtils.ERROR_CODE,
					"使用 微信开放平台 网站应用 授权code：" + code + " 获取Token异常",
					OAuth2WeChatOplatformWebsiteEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		String openid = weChatOplatformWebsiteTokenResponse.getOpenid();
		if (openid == null) {
			OAuth2Error error = new OAuth2Error(weChatOplatformWebsiteTokenResponse.getErrcode(),
					weChatOplatformWebsiteTokenResponse.getErrmsg(),
					OAuth2WeChatOplatformWebsiteEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		return weChatOplatformWebsiteTokenResponse;
	}

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param weChatOplatformWebsite 微信开放平台 网站应用 配置
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse,
			WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite) {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(weChatOplatformWebsite.getSuccessUrl() + "?"
					+ weChatOplatformWebsite.getParameterName() + "=" + accessToken.getTokenValue());
		}
		catch (IOException e) {
			throw new RedirectWeChatOplatformException("微信开放平台 网站应用重定向异常", e);
		}

	}

	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		for (WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite : weChatOplatformWebsiteList) {
			if (appid.equals(weChatOplatformWebsite.getAppid())) {
				return weChatOplatformWebsite.getSecret();
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2WeChatOplatformWebsiteEndpointUtils.INVALID_ERROR_CODE, "未找到 secret",
				OAuth2WeChatOplatformWebsiteEndpointUtils.AUTH_CODE2SESSION_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
