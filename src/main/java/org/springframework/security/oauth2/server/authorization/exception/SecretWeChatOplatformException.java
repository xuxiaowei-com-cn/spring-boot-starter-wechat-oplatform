package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 微信开放平台 Secret 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class SecretWeChatOplatformException extends WeChatOplatformException {

	public SecretWeChatOplatformException(String errorCode) {
		super(errorCode);
	}

	public SecretWeChatOplatformException(OAuth2Error error) {
		super(error);
	}

	public SecretWeChatOplatformException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public SecretWeChatOplatformException(OAuth2Error error, String message) {
		super(error, message);
	}

	public SecretWeChatOplatformException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
