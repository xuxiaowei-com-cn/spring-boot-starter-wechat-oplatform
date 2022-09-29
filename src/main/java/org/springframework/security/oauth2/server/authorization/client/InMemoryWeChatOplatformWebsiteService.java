package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOplatformWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2WeChatOplatformWebsiteEndpointUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

	private final WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties;

	public InMemoryWeChatOplatformWebsiteService(WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties) {
		this.weChatOplatformWebsiteProperties = weChatOplatformWebsiteProperties;
	}

	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(
				weChatOplatformWebsiteProperties.getDefaultRole());
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

	/**
	 * 根据 appid 获取 微信开放平台 网站应用属性配置
	 * @param appid 公众号ID
	 * @return 返回 微信开放平台 网站应用属性配置
	 */
	@Override
	public WeChatOplatformWebsiteProperties.WeChatOplatformWebsite getWeChatOplatformWebsiteByAppid(String appid) {
		List<WeChatOplatformWebsiteProperties.WeChatOplatformWebsite> list = weChatOplatformWebsiteProperties.getList();
		if (list == null) {
			throw new AppidWeChatOplatformException("appid 未配置");
		}

		for (WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite : list) {
			if (appid.equals(weChatOplatformWebsite.getAppid())) {
				return weChatOplatformWebsite;
			}
		}

		throw new AppidWeChatOplatformException("未匹配到 appid");
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 开放平台 网站应用 ID
	 * @return 返回重定向的地址
	 */
	@Override
	public String getRedirectUriByAppid(String appid) {
		WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite = getWeChatOplatformWebsiteByAppid(
				appid);
		String redirectUriPrefix = weChatOplatformWebsite.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
		}
		else {
			throw new RedirectUriWeChatOplatformException("重定向地址前缀不能为空");
		}
	}

	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite = getWeChatOplatformWebsiteByAppid(
				appid);
		return weChatOplatformWebsite.getSecret();
	}

}
