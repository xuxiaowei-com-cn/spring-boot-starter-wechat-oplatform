package org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.InMemoryWeChatOplatformWebsiteService;
import org.springframework.security.oauth2.server.authorization.client.WeChatOplatformWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOplatformWebsiteProperties;

/**
 * 微信开放平台 网站应用 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2WeChatOplatformWebsiteConfiguration {

	private WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties;

	@Autowired
	public void setWeChatOplatformWebsiteProperties(WeChatOplatformWebsiteProperties weChatOplatformWebsiteProperties) {
		this.weChatOplatformWebsiteProperties = weChatOplatformWebsiteProperties;
	}

	@Bean
	@ConditionalOnMissingBean
	public WeChatOplatformWebsiteService weChatOplatformWebsiteService() {
		return new InMemoryWeChatOplatformWebsiteService(weChatOplatformWebsiteProperties);
	}

}
