package org.springframework.security.oauth2.server.authorization.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatOplatformParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2WeChatOplatformWebsiteAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 微信 OAuth2 用于验证授权授予的 {@link OAuth2WeChatOplatformWebsiteAuthenticationToken}。
 *
 * @author xuxiaowei
 * @since Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationConverter 尝试从 {@link HttpServletRequest} 提取
 * OAuth 2.0 授权代码授权的访问令牌请求，然后将其转换为用于验证授权授权的
 * {@link OAuth2AuthorizationCodeAuthenticationToken} 。
 * @see OAuth2RefreshTokenAuthenticationConverter 用于 OAuth 2.0 授权代码授予的Authentication实现。
 * @see OAuth2ClientCredentialsAuthenticationConverter 尝试从 {@link HttpServletRequest} 提取
 * OAuth 2.0 客户端凭据授予的访问令牌请求，然后将其转换为用于验证授权授予的
 * {@link OAuth2ClientCredentialsAuthenticationToken} 。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2WeChatOplatformWebsiteAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {

		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!OAuth2WeChatOplatformWebsiteAuthenticationToken.WECHAT_OPLATFORM_WEBSITE.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// code (REQUIRED)
		String code = parameters.getFirst(OAuth2ParameterNames.CODE);
		if (!StringUtils.hasText(code) || parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CODE,
					OAuth2WeChatOplatformWebsiteEndpointUtils.AUTH_CODE2SESSION_URI);
		}

		// appid (REQUIRED)
		String appid = parameters.getFirst(OAuth2WeChatOplatformParameterNames.APPID);

		if (!StringUtils.hasText(appid) || parameters.get(OAuth2WeChatOplatformParameterNames.APPID).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2WeChatOplatformParameterNames.APPID,
					OAuth2WeChatOplatformWebsiteEndpointUtils.AUTH_CODE2SESSION_URI);
		}

		// scope
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);

		Map<String, Object> additionalParameters = new HashMap<>(4);
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.CLIENT_ID)
					&& !key.equals(OAuth2ParameterNames.CODE) && !key.equals(OAuth2ParameterNames.REDIRECT_URI)
					&& !key.equals(OAuth2ParameterNames.CLIENT_SECRET)
					&& !key.equals(OAuth2WeChatOplatformParameterNames.APPID) && !key.equals(OAuth2ParameterNames.SCOPE)
					&& !OAuth2WeChatOplatformParameterNames.REMOTE_ADDRESS.equals(key)
					&& !OAuth2WeChatOplatformParameterNames.SESSION_ID.equals(key)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		String remoteAddress = request.getParameter(OAuth2WeChatOplatformParameterNames.REMOTE_ADDRESS);
		String sessionId = request.getParameter(OAuth2WeChatOplatformParameterNames.SESSION_ID);

		return new OAuth2WeChatOplatformWebsiteAuthenticationToken(clientPrincipal, additionalParameters, appid, code,
				scope, remoteAddress, sessionId);
	}

}
