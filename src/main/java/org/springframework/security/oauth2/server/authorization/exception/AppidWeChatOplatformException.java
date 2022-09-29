package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 微信开放平台 AppID 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class AppidWeChatOplatformException extends WeChatOplatformException {

	public AppidWeChatOplatformException(String errorCode) {
		super(errorCode);
	}

	public AppidWeChatOplatformException(OAuth2Error error) {
		super(error);
	}

	public AppidWeChatOplatformException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public AppidWeChatOplatformException(OAuth2Error error, String message) {
		super(error, message);
	}

	public AppidWeChatOplatformException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
