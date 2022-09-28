package org.springframework.security.oauth2.server.authorization.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 微信开放平台 网站应用 属性配置类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
@Component
@ConfigurationProperties("wechat.oplatform.website")
public class WeChatOplatformWebsiteProperties {

	/**
	 * 微信开放平台 网站应用 属性配置列表
	 */
	private List<WeChatOplatformWebsite> list;

	/**
	 * 默认微信开放平台 网站应用 的权限
	 */
	private String defaultRole;

	/**
	 * 微信开放平台 网站应用 属性配置类
	 *
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	@Data
	public static class WeChatOplatformWebsite {

		/**
		 * AppID
		 */
		private String appid;

		/**
		 * AppSecret
		 */
		private String secret;

		/**
		 * 重定向的网址前缀（程序使用时，会在后面拼接 /{@link #appid}）
		 */
		private String redirectUriPrefix;

		/**
		 * OAuth2 客户ID
		 */
		private String clientId;

		/**
		 * OAuth2 客户秘钥
		 */
		private String clientSecret;

		/**
		 * 获取 Token URL 前缀
		 */
		private String tokenUrlPrefix;

		/**
		 * 授权范围
		 */
		private String scope;

		/**
		 * 登录成功后重定向的URL
		 */
		private String successUrl;

		/**
		 * 登录成功后重定向的URL OAuth2.1 授权 Token Name
		 */
		private String parameterName = "access_token";

	}

}
