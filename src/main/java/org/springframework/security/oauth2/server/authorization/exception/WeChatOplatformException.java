package org.springframework.security.oauth2.server.authorization.exception;

/**
 * 微信开放平台父异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class WeChatOplatformException extends RuntimeException {

	public WeChatOplatformException(String message) {
		super(message);
	}

	public WeChatOplatformException(String message, Throwable cause) {
		super(message, cause);
	}

}
