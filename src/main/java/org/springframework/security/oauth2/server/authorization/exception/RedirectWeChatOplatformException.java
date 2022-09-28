package org.springframework.security.oauth2.server.authorization.exception;

/**
 * 重定向 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectWeChatOplatformException extends WeChatOplatformException {

	public RedirectWeChatOplatformException(String message) {
		super(message);
	}

	public RedirectWeChatOplatformException(String message, Throwable cause) {
		super(message, cause);
	}

}
