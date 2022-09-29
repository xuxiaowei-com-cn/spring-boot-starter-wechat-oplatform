package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 重定向 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectWeChatOplatformException extends WeChatOplatformException {

	public RedirectWeChatOplatformException(String errorCode) {
		super(errorCode);
	}

	public RedirectWeChatOplatformException(OAuth2Error error) {
		super(error);
	}

	public RedirectWeChatOplatformException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectWeChatOplatformException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectWeChatOplatformException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
