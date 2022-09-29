package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.client.WeChatOplatformWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOplatformWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.RestTemplate;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2WeChatOplatformWebsiteAuthenticationToken.WECHAT_OPLATFORM_WEBSITE;

/**
 * 微信开放平台 网站应用 授权码接收服务
 *
 * @see <a href=
 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AccessTokenResponse
 * @see DefaultOAuth2AccessTokenResponseMapConverter
 * @see DefaultMapOAuth2AccessTokenResponseConverter
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class WeChatOplatformWebsiteCodeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/wechat-oplatform/website/code";

	public static final String TOKEN_URL = "/oauth2/token?grant_type={grant_type}&appid={appid}&code={code}&state={state}&client_id={client_id}&client_secret={client_secret}&remote_address={remote_address}&session_id={session_id}";

	private WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties;

	private WeChatOplatformWebsiteService weChatOplatformWebsiteService;

	/**
	 * 微信开放平台 网站应用 使用code获取授权凭证URL前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setWeChatOplatformWebsiteProperties(WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties) {
		this.weChatOplatformWebsiteProperties = weChatOplatformWebsiteProperties;
	}

	@Autowired
	public void setWeChatOplatformWebsiteService(WeChatOplatformWebsiteService weChatOplatformWebsiteService) {
		this.weChatOplatformWebsiteService = weChatOplatformWebsiteService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");
			String code = request.getParameter(OAuth2ParameterNames.CODE);
			String state = request.getParameter(OAuth2ParameterNames.STATE);
			String grantType = WECHAT_OPLATFORM_WEBSITE.getValue();

			WeChatOplatformWebsiteProperties.WeChatOplatformWebsite oplatformWebsite = weChatOplatformWebsiteService
					.getWeChatOplatformWebsiteByAppid(appid);

			String clientId = oplatformWebsite.getClientId();
			String clientSecret = oplatformWebsite.getClientSecret();
			String tokenUrlPrefix = oplatformWebsite.getTokenUrlPrefix();
			String scope = oplatformWebsite.getScope();

			String remoteHost = request.getRemoteHost();
			HttpSession session = request.getSession(false);

			RestTemplate restTemplate = new RestTemplate();
			Map<String, String> uriVariables = new HashMap<>(8);
			uriVariables.put(OAuth2ParameterNames.GRANT_TYPE, grantType);
			uriVariables.put(OAuth2WeChatOplatformParameterNames.APPID, appid);
			uriVariables.put(OAuth2ParameterNames.CODE, code);
			uriVariables.put(OAuth2ParameterNames.STATE, state);
			uriVariables.put(OAuth2ParameterNames.SCOPE, scope);
			uriVariables.put(OAuth2ParameterNames.CLIENT_ID, clientId);
			uriVariables.put(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);
			uriVariables.put(OAuth2WeChatOplatformParameterNames.REMOTE_ADDRESS, remoteHost);
			uriVariables.put(OAuth2WeChatOplatformParameterNames.SESSION_ID, session == null ? "" : session.getId());

			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

			List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
			messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

			OAuth2AccessTokenResponse oauth2AccessTokenResponse = restTemplate.postForObject(tokenUrlPrefix + TOKEN_URL,
					httpEntity, OAuth2AccessTokenResponse.class, uriVariables);

			assert oauth2AccessTokenResponse != null;

			weChatOplatformWebsiteService.sendRedirect(request, response, uriVariables, oauth2AccessTokenResponse,
					oplatformWebsite);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
