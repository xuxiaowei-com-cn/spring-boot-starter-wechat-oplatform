package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * 通过 code 换取网页授权 access_token 返回值
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see <a href=
 * "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">微信登录功能/网站应用微信登录开发指南</a>
 */
@Data
public class WeChatOplatformWebsiteTokenResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
	 */
	@JsonProperty("access_token")
	private String accessToken;

	/**
	 * access_token接口调用凭证超时时间，单位（秒）
	 */
	@JsonProperty("expires_in")
	private Integer expiresIn;

	/**
	 * 用户刷新access_token
	 */
	@JsonProperty("refresh_token")
	private String refreshToken;

	/**
	 * 授权范围
	 */
	private String scope;

	/**
	 * 用户唯一标识
	 */
	private String openid;

	/**
	 * 用户在开放平台的唯一标识符
	 */
	private String unionid;

	/**
	 * 普通用户昵称
	 */
	private String nickname;

	/**
	 * 普通用户性别，1为男性，2为女性
	 */
	private String sex;

	/**
	 * 国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语，默认为en
	 */
	private String language;

	/**
	 * 普通用户个人资料填写的省份
	 */
	private String province;

	/**
	 * 普通用户个人资料填写的城市
	 */
	private String city;

	/**
	 * 国家，如中国为CN
	 */
	private String country;

	/**
	 * 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空
	 */
	private String headimgurl;

	/**
	 * 用户特权信息，json数组，如微信沃卡用户为（chinaunicom）
	 */
	private String[] privilege;

	/**
	 * 错误码
	 */
	private String errcode;

	/**
	 * 错误信息
	 */
	private String errmsg;

}
