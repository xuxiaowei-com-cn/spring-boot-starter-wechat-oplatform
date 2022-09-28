package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriWeChatOplatformException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOplatformWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

/**
 * 微信开放平台 网站应用 跳转到微信授权页面
 *
 * @see <a href=
 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class WeChatOplatformWebsiteAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/wechat-oplatform/website/authorize";

	public static final String AUTHORIZE_URL = "https://open.weixin.qq.com/connect/qrconnect?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect";

	public static final String SNSAPI_LOGIN = "snsapi_login";

	private WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties;

	/**
	 * 微信开放平台 网站应用 授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setWeChatOplatformWebsiteProperties(WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties) {
		this.weChatOplatformWebsiteProperties = weChatOplatformWebsiteProperties;
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

			List<WeChatOplatformWebsiteProperties.WeChatOplatformWebsite> list = weChatOplatformWebsiteProperties
					.getList();
			if (list == null) {
				throw new AppidWeChatOplatformException("appid 未配置");
			}

			String redirectUri = null;
			boolean include = false;
			for (WeChatOplatformWebsiteProperties.WeChatOplatformWebsite weChatOplatformWebsite : list) {
				if (appid.equals(weChatOplatformWebsite.getAppid())) {
					include = true;
					String redirectUriPrefix = weChatOplatformWebsite.getRedirectUriPrefix();
					if (StringUtils.hasText(redirectUriPrefix)) {
						redirectUri = UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
					}
					else {
						throw new RedirectUriWeChatOplatformException("重定向地址前缀不能为空");
					}
				}
			}

			if (!include) {
				throw new AppidWeChatOplatformException("未匹配到 appid");
			}

			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			if (!SNSAPI_LOGIN.equals(scope)) {
				scope = SNSAPI_LOGIN;
			}

			String state = UUID.randomUUID().toString();
			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scope, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
