package org.springframework.security.oauth2.server.authorization.web.authentication;

/**
 * 微信开放平台 网站应用 OAuth 2.0 协议端点的实用方法
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2WeChatOplatformWebsiteEndpointUtils {

	/**
	 * 微信开放平台 网站应用
	 */
	public static final String AUTH_CODE2SESSION_URI = "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html";

	/**
	 * 错误代码
	 */
	public static final String ERROR_CODE = "C10000";

	/**
	 * 无效错误代码
	 */
	public static final String INVALID_ERROR_CODE = "C20000";

}
