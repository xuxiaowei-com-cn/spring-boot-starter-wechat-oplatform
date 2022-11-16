package org.springframework.security.oauth2.server.authorization.authentication;

/*-
 * #%L
 * spring-boot-starter-wechat-oplatform
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * 微信开放平台 网站应用 OAuth2 身份验证令牌
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken 用于 OAuth 2.0 授权代码授予的
 * {@link Authentication} 实现。
 * @see OAuth2RefreshTokenAuthenticationToken 用于 OAuth 2.0 刷新令牌授予的 {@link Authentication}
 * 实现。
 * @see OAuth2ClientCredentialsAuthenticationToken 用于 OAuth 2.0
 * 客户端凭据授予的{@link Authentication} 实现。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2WeChatOplatformWebsiteAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	/**
	 * 授权类型：微信开放平台 网站应用
	 */
	public static final AuthorizationGrantType WECHAT_OPLATFORM_WEBSITE = new AuthorizationGrantType(
			"wechat_oplatform_website");

	/**
	 * AppID
	 */
	@Getter
	private final String appid;

	/**
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	@Getter
	private final String code;

	/**
	 * @see OAuth2ParameterNames#SCOPE
	 */
	@Getter
	private final String scope;

	@Getter
	private final String remoteAddress;

	@Getter
	private final String sessionId;

	@Getter
	private final String state;

	@Getter
	private final String binding;

	/**
	 * 子类构造函数。
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param appid AppID
	 * @param code 授权码，<a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 * @param scope {@link OAuth2ParameterNames#SCOPE}，授权范围，<a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 * @param remoteAddress 用户IP
	 * @param sessionId SessionID
	 * @param binding 是否绑定，需要使用者自己去拓展
	 */
	public OAuth2WeChatOplatformWebsiteAuthenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, String appid, String code, String scope, String remoteAddress,
			String sessionId, String state, String binding) {
		super(OAuth2WeChatOplatformWebsiteAuthenticationToken.WECHAT_OPLATFORM_WEBSITE, clientPrincipal,
				additionalParameters);
		Assert.hasText(code, "appid 不能为空");
		Assert.hasText(code, "code 不能为空");
		this.appid = appid;
		this.code = code;
		this.scope = scope;
		this.remoteAddress = remoteAddress;
		this.sessionId = sessionId;
		this.state = state;
		this.binding = binding;
	}

}
