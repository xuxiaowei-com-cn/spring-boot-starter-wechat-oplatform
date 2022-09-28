package org.springframework.security.oauth2.core.endpoint;

/**
 * 微信开放平台 网站应用 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
public interface OAuth2WeChatOplatformParameterNames {

	/**
	 * AppID(公众号ID)
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String APPID = "appid";

	/**
	 * AppSecret(公众号密钥)
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String SECRET = "secret";

	/**
	 * @see OAuth2ParameterNames#CODE
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String CODE = "code";

	/**
	 * 用户唯一标识
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String OPENID = "openid";

	/**
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String UNIONID = "unionid";

	/**
	 * 远程地址
	 */
	String REMOTE_ADDRESS = "remote_address";

	/**
	 * Session ID
	 */
	String SESSION_ID = "session_id";

}
