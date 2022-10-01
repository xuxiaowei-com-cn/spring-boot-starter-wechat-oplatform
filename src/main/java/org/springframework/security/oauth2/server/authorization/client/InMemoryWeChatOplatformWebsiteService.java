package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.WeChatOplatformWebsiteAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatOplatformParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOplatformWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2WeChatOplatformWebsiteEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

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

	/**
	 * 构建 微信开放平台 网站应用 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID
	 * @param code 授权码
	 * @param openid 用户唯一标识
	 * @param credentials 证书
	 * @param unionid 多账户用户唯一标识
	 * @param accessToken 授权凭证
	 * @param refreshToken 刷新凭证
	 * @param expiresIn 过期时间
	 * @param scope 授权范围
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope) throws OAuth2AuthenticationException {
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

	/**
	 * 根据 AppID、code、accessTokenUrl 获取Token
	 * @param appid AppID
	 * @param code 授权码
	 * @param accessTokenUrl 通过 code 换取网页授权 access_token 的 URL
	 * @param remoteAddress 用户IP
	 * @param sessionId SessionID
	 * @return 返回 微信授权结果
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public WeChatOplatformWebsiteTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl,
			String remoteAddress, String sessionId) throws OAuth2AuthenticationException {
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
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse,
			WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite)
			throws OAuth2AuthenticationException {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(weChatOplatformWebsite.getSuccessUrl() + "?"
					+ weChatOplatformWebsite.getParameterName() + "=" + accessToken.getTokenValue());
		}
		catch (IOException e) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatOplatformWebsiteEndpointUtils.ERROR_CODE,
					"微信开放平台 网站应用重定向异常", null);
			throw new RedirectWeChatOplatformException(error, e);
		}

	}

	/**
	 * 根据 appid 获取 微信开放平台 网站应用属性配置
	 * @param appid 公众号ID
	 * @return 返回 微信开放平台 网站应用属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public WeChatOplatformWebsiteProperties.WeChatOplatformWebsite getWeChatOplatformWebsiteByAppid(String appid)
			throws OAuth2AuthenticationException {
		List<WeChatOplatformWebsiteProperties.WeChatOplatformWebsite> list = weChatOplatformWebsiteProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatOplatformWebsiteEndpointUtils.ERROR_CODE, "appid 未配置",
					null);
			throw new AppidWeChatOplatformException(error);
		}

		for (WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite : list) {
			if (appid.equals(weChatOplatformWebsite.getAppid())) {
				return weChatOplatformWebsite;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2WeChatOplatformWebsiteEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidWeChatOplatformException(error);
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 开放平台 网站应用 ID
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public String getRedirectUriByAppid(String appid) throws OAuth2AuthenticationException {
		WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite = getWeChatOplatformWebsiteByAppid(
				appid);
		String redirectUriPrefix = weChatOplatformWebsite.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
		}
		else {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatOplatformWebsiteEndpointUtils.ERROR_CODE, "重定向地址前缀不能为空",
					null);
			throw new RedirectUriWeChatOplatformException(error);
		}
	}

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param tokenUrlPrefix 获取 Token URL 前缀
	 * @param tokenUrl Token URL
	 * @param uriVariables 参数
	 * @return 返回 OAuth 2.1 授权 Token
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request,
			HttpServletResponse response, String tokenUrlPrefix, String tokenUrl, Map<String, String> uriVariables)
			throws OAuth2AuthenticationException {

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

		RestTemplate restTemplate = new RestTemplate();

		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

		return restTemplate.postForObject(tokenUrlPrefix + tokenUrl, httpEntity, OAuth2AccessTokenResponse.class,
				uriVariables);
	}

	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite = getWeChatOplatformWebsiteByAppid(
				appid);
		return weChatOplatformWebsite.getSecret();
	}

}
