package org.springframework.security.oauth2.core.endpoint;

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

/**
 * 微信开放平台 网站应用 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public interface OAuth2WeChatOplatformWebsiteParameterNames {

	/**
	 * AppID
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String APPID = "appid";

	/**
	 * AppSecret
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
	 */
	String SECRET = "secret";

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

	/**
	 * 是否绑定，需要使用者自己去拓展
	 */
	String BINDING = "binding";

}
