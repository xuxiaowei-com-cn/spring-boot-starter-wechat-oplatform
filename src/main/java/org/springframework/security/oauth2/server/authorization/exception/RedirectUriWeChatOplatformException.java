package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 微信开放平台 redirectUri 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectUriWeChatOplatformException extends WeChatOplatformException {

	public RedirectUriWeChatOplatformException(String message) {
		super(message);
	}

	public RedirectUriWeChatOplatformException(OAuth2Error error) {
		super(error);
	}

	public RedirectUriWeChatOplatformException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectUriWeChatOplatformException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectUriWeChatOplatformException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
