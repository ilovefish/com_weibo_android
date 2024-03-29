/*
 * Copyright 2011 Sina.
 *
 * Licensed under the Apache License and Weibo License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.open.weibo.com
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.weibo.net;

import java.io.IOException;
import java.net.MalformedURLException;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.CookieSyncManager;

//import com.sina.sso.RemoteSSO;

/**
 * Encapsulation main Weibo APIs, Include: 1. getRquestToken , 2.
 * getAccessToken, 3. url request. Used as a single instance class. Implements a
 * weibo api as a synchronized way.
 * 
 * @author (luopeng@staff.sina.com.cn zhangjie2@staff.sina.com.cn 官方微博：WBSDK  http://weibo.com/u/2791136085)
 */
public class Weibo {

	// public static String SERVER = "http://api.t.sina.com.cn/";
	public static String SERVER = "https://api.weibo.com/2/";
	public static String URL_OAUTH_TOKEN = "http://api.t.sina.com.cn/oauth/request_token";
	public static String URL_AUTHORIZE = "http://api.t.sina.com.cn/oauth/authorize";
	public static String URL_ACCESS_TOKEN = "http://api.t.sina.com.cn/oauth/access_token";
	public static String URL_AUTHENTICATION = "http://api.t.sina.com.cn/oauth/authenticate";

	public static String URL_OAUTH2_ACCESS_TOKEN = "https://api.weibo.com/oauth2/access_token";

	// public static String URL_OAUTH2_ACCESS_AUTHORIZE =
	// "http://t.weibo.com:8093/oauth2/authorize";
	public static String URL_OAUTH2_ACCESS_AUTHORIZE = "https://api.weibo.com/oauth2/authorize";

	private static String APP_KEY = "";
	private static String APP_SECRET = "";

	//private static String ssoPackageName = "";// "com.sina.weibo";
	//private static String ssoActivityName = "";// "com.sina.weibo.MainTabActivity";

	private static Weibo mWeiboInstance = null;
	private Token mAccessToken = null;
	private RequestToken mRequestToken = null;
//	private ServiceConnection conn = null;

	private WeiboDialogListener mAuthDialogListener;

	private static final int DEFAULT_AUTH_ACTIVITY_CODE = 32973;

	public static final String TOKEN = "access_token";
	public static final String EXPIRES = "expires_in";
	public static final String REFRESHTOKEN = "refresh_token";
	public static final String UID = "uid";
	public static final String DEFAULT_REDIRECT_URI = "wbconnect://success";//
	public static final String DEFAULT_CANCEL_URI = "wbconnect://cancel";//

//	public static final String WEIBO_SIGNATURE = "30820295308201fea00302010202044b4ef1bf300d"
//			+ "06092a864886f70d010105050030818d310b300906035504061302434e3110300e0603550408130"
//			+ "74265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e"
//			+ "612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a0603550"
//			+ "40b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c746430"
//			+ "20170d3130303131343130323831355a180f32303630303130323130323831355a30818d310b300"
//			+ "906035504061302434e3110300e060355040813074265694a696e673110300e0603550407130742"
//			+ "65694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f67792028436"
//			+ "8696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c"
//			+ "6f677920284368696e612920436f2e204c746430819f300d06092a864886f70d010101050003818"
//			+ "d00308189028181009d367115bc206c86c237bb56c8e9033111889b5691f051b28d1aa8e42b66b7"
//			+ "413657635b44786ea7e85d451a12a82a331fced99c48717922170b7fc9bc1040753c0d38b4cf2b2"
//			+ "2094b1df7c55705b0989441e75913a1a8bd2bc591aa729a1013c277c01c98cbec7da5ad7778b2fa"
//			+ "d62b85ac29ca28ced588638c98d6b7df5a130203010001300d06092a864886f70d0101050500038"
//			+ "181000ad4b4c4dec800bd8fd2991adfd70676fce8ba9692ae50475f60ec468d1b758a665e961a3a"
//			+ "edbece9fd4d7ce9295cd83f5f19dc441a065689d9820faedbb7c4a4c4635f5ba1293f6da4b72ed3"
//			+ "2fb8795f736a20c95cda776402099054fccefb4a1a558664ab8d637288feceba9508aa907fc1fe2"
//			+ "b1ae5a0dec954ed831c0bea4";

	private Activity mAuthActivity;
	private String[] mAuthPermissions;
	private int mAuthActivityCode;
	private String mRedirectUrl;

	private Weibo() {
		Utility.setRequestHeader("Accept-Encoding", "gzip");
		Utility.setTokenObject(this.mRequestToken);
		mRedirectUrl = DEFAULT_REDIRECT_URI;
//		conn = new ServiceConnection() {
//			
//			public void onServiceDisconnected(ComponentName name) {
//			}
//
//			
//			public void onServiceConnected(ComponentName name, IBinder service) {
//				RemoteSSO remoteSSOservice = RemoteSSO.Stub
//						.asInterface(service);
//				try {
//					ssoPackageName = remoteSSOservice.getPackageName();
//					ssoActivityName = remoteSSOservice.getActivityName();
//					boolean singleSignOnStarted = startSingleSignOn(
//							mAuthActivity, APP_KEY, mAuthPermissions,
//							mAuthActivityCode);
//					if (!singleSignOnStarted) {
//						startDialogAuth(mAuthActivity, mAuthPermissions);
//					}
//				} catch (RemoteException e) {
//					e.printStackTrace();
//				}
//			}
//		};
	}

	public synchronized static Weibo getInstance() {
		if (mWeiboInstance == null) {
			mWeiboInstance = new Weibo();
		}
		return mWeiboInstance;
	}

	//
	public void setAccessToken(AccessToken token) {
		mAccessToken = token;
	}

	public Token getAccessToken() {
		return this.mAccessToken;
	}

	public void setupConsumerConfig(String consumer_key, String consumer_secret) {
		Weibo.APP_KEY = consumer_key;
		Weibo.APP_SECRET = consumer_secret;
	}

	public static String getAppKey() {
		return Weibo.APP_KEY;
	}

	public static String getAppSecret() {
		return Weibo.APP_SECRET;
	}

	public void setRequestToken(RequestToken token) {
		this.mRequestToken = token;
	}

	public static String getSERVER() {
		return SERVER;
	}

	public static void setSERVER(String sERVER) {
		SERVER = sERVER;
	}

	//
	public void addOauthverifier(String verifier) {
		mRequestToken.setVerifier(verifier);
	}

	public String getRedirectUrl() {
		return mRedirectUrl;
	}

	public void setRedirectUrl(String mRedirectUrl) {
		this.mRedirectUrl = mRedirectUrl;
	}

	/**
	 * Requst sina weibo open api by get or post
	 * 
	 * @param url
	 *            Openapi request URL.
	 * @param params
	 *            http get or post parameters . e.g.
	 *            gettimeling?max=max_id&min=min_id max and max_id is a pair of
	 *            key and value for params, also the min and min_id
	 * @param httpMethod
	 *            http verb: e.g. "GET", "POST", "DELETE"
	 * @throws IOException
	 * @throws MalformedURLException
	 * @throws WeiboException
	 */
	public String request(Context context, String url, WeiboParameters params,
			String httpMethod, Token token) throws WeiboException {
		String rlt = Utility.openUrl(context, url, httpMethod, params,
				this.mAccessToken);
		return rlt;
	}
//
//	/**/
//	public RequestToken getRequestToken(Context context, String key,
//			String secret, String callback_url) throws WeiboException {
//		Utility.setAuthorization(new RequestTokenHeader());
//		WeiboParameters postParams = new WeiboParameters();
//		postParams.add("oauth_callback", callback_url);
//		String rlt;
//		rlt = Utility.openUrl(context, Weibo.URL_OAUTH_TOKEN, "POST",
//				postParams, null);
//		RequestToken request = new RequestToken(rlt);
//		this.mRequestToken = request;
//		return request;
//	}
////generateAccessToken
//	public AccessToken generateAccessToken(Context context,
//			RequestToken requestToken) throws WeiboException {
//		Utility.setAuthorization(new AccessTokenHeader());
//		WeiboParameters authParam = new WeiboParameters();
//		authParam
//				.add("oauth_verifier", this.mRequestToken.getVerifier()/* "605835" */);
//		authParam.add("source", APP_KEY);
//		String rlt = Utility.openUrl(context, Weibo.URL_ACCESS_TOKEN, "POST",
//				authParam, this.mRequestToken);
//		AccessToken accessToken = new AccessToken(rlt);
//		this.mAccessToken = accessToken;
//		Log.d("CNM", "NO USING!!!!!!!!");
//		return accessToken;
//	}
//
//	public AccessToken getXauthAccessToken(Context context, String app_key,
//			String app_secret, String usrname, String password)
//			throws WeiboException {
//		Utility.setAuthorization(new XAuthHeader());
//		WeiboParameters postParams = new WeiboParameters();
//		postParams.add("x_auth_username", usrname);
//		postParams.add("x_auth_password", password);
//		postParams.add("oauth_consumer_key", APP_KEY);
//		String rlt = Utility.openUrl(context, Weibo.URL_ACCESS_TOKEN, "POST",
//				postParams, null);
//		AccessToken accessToken = new AccessToken(rlt);
//		this.mAccessToken = accessToken;
//		return accessToken;
//	}
//
//	/**
//	 * 
//	 * 
//	 * https://api.weibo.com/oauth2/access_token?client_id=YOUR_CLIENT_ID&
//	 * client_secret=YOUR_CLIENT_SECRET&grant_type=password&redirect_uri=
//	 * YOUR_REGISTERED_REDIRECT_URI&username=USER_NAME&pasword=PASSWORD
//	 * 
//	 * @param context
//	 * @param app_key
//	 * @param app_secret
//	 * @param usrname
//	 * @param password
//	 * @return
//	 * @throws WeiboException
//	 */
//	public Oauth2AccessToken getOauth2AccessToken(Context context,
//			String app_key, String app_secret, String usrname, String password)
//			throws WeiboException {
//		Utility.setAuthorization(new Oauth2AccessTokenHeader());
//		WeiboParameters postParams = new WeiboParameters();
//		postParams.add("username", usrname);
//		postParams.add("password", password);
//		postParams.add("client_id", app_key);
//		postParams.add("client_secret", app_secret);
//		postParams.add("grant_type", "password");
//		String rlt = Utility.openUrl(context, Weibo.URL_OAUTH2_ACCESS_TOKEN,
//				"POST", postParams, null);
//		Oauth2AccessToken accessToken = new Oauth2AccessToken(rlt);
//		this.mAccessToken = accessToken;
//		return accessToken;
//	}

	/**
	 * Share text content or image to weibo .
	 * 
	 */
	public boolean share2weibo(Activity activity, String accessToken,
			String tokenSecret, String content, String picPath)
			throws WeiboException {
		if (TextUtils.isEmpty(accessToken)) {
			throw new WeiboException("token can not be null!");
		}
		// else if (TextUtils.isEmpty(tokenSecret)) {
		// throw new WeiboException("secret can not be null!");
		// }

		if (TextUtils.isEmpty(content) && TextUtils.isEmpty(picPath)) {
			throw new WeiboException("weibo content can not be null!");
		}
		Intent i = new Intent(activity, ShareActivity.class);
		i.putExtra(ShareActivity.EXTRA_ACCESS_TOKEN, accessToken);
		i.putExtra(ShareActivity.EXTRA_TOKEN_SECRET, tokenSecret);
		i.putExtra(ShareActivity.EXTRA_WEIBO_CONTENT, content);
		i.putExtra(ShareActivity.EXTRA_PIC_URI, picPath);
		activity.startActivity(i);

		return true;
	}

	private void startDialogAuth(Activity activity, String[] permissions) {
		WeiboParameters params = new WeiboParameters();
		if (permissions.length > 0) {
			params.add("scope", TextUtils.join(",", permissions));
		}
		CookieSyncManager.createInstance(activity);
		dialog(activity, params, new WeiboDialogListener() {

			public void onComplete(Bundle values) {
				// ensure any cookies set by the dialog are saved
				CookieSyncManager.getInstance().sync();
				if (null == mAccessToken) {
					mAccessToken = new Token();
				}
				String access_token = values.getString(TOKEN);
				String ExpiresTime = values.getString(EXPIRES);
				String RefreshToken = values.getString(REFRESHTOKEN);
				
				Log.d("onComplete",access_token+" "+ExpiresTime+" "+RefreshToken);
				/*http://weibo.com/#access_token=2.00yxqmcC_fVR4E5dec09b531oPUyPB&remind_in=103131&expires_in=103131&uid=2405409782*/
				mAccessToken.setToken(access_token);
				mAccessToken.setExpiresTime(ExpiresTime);
				
				
				
				if (isSessionValid()) {
					Log.d("Weibo-authorize", "Login Success! access_token="
							+ mAccessToken.getToken() + " expires="
							+ mAccessToken.getExpiresTime() + "refresh_token="
							+ mAccessToken.getRefreshToken());
					mAuthDialogListener.onComplete(values);
				} else {
					Log.d("Weibo-authorize", "Failed to receive access token");
					mAuthDialogListener.onWeiboException(new WeiboException(
							"Failed to receive access token."));
				}
			}

			public void onError(DialogError error) {
				Log.d("Weibo-authorize", "Login failed: " + error);
				mAuthDialogListener.onError(error);
			}

			public void onWeiboException(WeiboException error) {
				Log.d("Weibo-authorize", "Login failed: " + error);
				mAuthDialogListener.onWeiboException(error);
			}

			public void onCancel() {
				Log.d("Weibo-authorize", "Login canceled");
				mAuthDialogListener.onCancel();
			}
		});
	}

	/**
	 * User-Agent Flow
	 * 
	 * @param activity
	 * 
	 * @param listener
	 */
	public void authorize(Activity activity, final WeiboDialogListener listener) {
		authorize(activity, new String[] {}, DEFAULT_AUTH_ACTIVITY_CODE,
				listener);
	}

//	private void authorize(Activity activity, String[] permissions,
//			final WeiboDialogListener listener) {
//		authorize(activity, permissions, DEFAULT_AUTH_ACTIVITY_CODE, listener);
//	}

	private void authorize(Activity activity, String[] permissions,
			int activityCode, final WeiboDialogListener listener) {
		mAuthActivity = activity;
		mAuthPermissions = permissions;
		mAuthActivityCode = activityCode;

		Utility.setAuthorization(new Oauth2AccessTokenHeader());

		boolean bindSucced = false;
		mAuthDialogListener = listener;

		// Prefer single sign-on, where available.
		// 单点登入技术：http://www.ibm.com/developerworks/cn/security/se-sso/
		// 此处没有调用
//		bindSucced = bindRemoteSSOService(activity);
//		Log.v("Weibo","This RemoteSSOService is "+ bindSucced);
		// Otherwise fall back to traditional dialog.
		if (!bindSucced) {
			Log.d("authorize", "startDialogAuth");
			startDialogAuth(activity, permissions);
		}

	}

//	private boolean bindRemoteSSOService(Activity activity) {
//		Context context = activity.getApplicationContext();
//		Intent intent = new Intent("com.sina.weibo.remotessoservice");
//		return context.bindService(intent, conn, Context.BIND_AUTO_CREATE);
//	}

//	private boolean startSingleSignOn(Activity activity, String applicationId,
//			String[] permissions, int activityCode) {
//		boolean didSucceed = true;
//		Intent intent = new Intent();
//		intent.setClassName(ssoPackageName, ssoActivityName);
//		intent.putExtra("appKey", applicationId);// applicationId //"2745207810"
//		intent.putExtra("redirectUri", mRedirectUrl);
//
//		if (permissions.length > 0) {
//			intent.putExtra("scope", TextUtils.join(",", permissions));
//		}
//
//		// validate Signature
//		if (!validateAppSignatureForIntent(activity, intent)) {
//			return false;
//		}
//
//		try {
//			activity.startActivityForResult(intent, activityCode);
//		} catch (ActivityNotFoundException e) {
//			didSucceed = false;
//		}
//
//		activity.getApplication().unbindService(conn);
//		return didSucceed;
//	}

//	private boolean validateAppSignatureForIntent(Activity activity,
//			Intent intent) {
//		ResolveInfo resolveInfo = activity.getPackageManager().resolveActivity(
//				intent, 0);
//		if (resolveInfo == null) {
//			return false;
//		}
//
//		String packageName = resolveInfo.activityInfo.packageName;
//		try {
//			PackageInfo packageInfo = activity.getPackageManager()
//					.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
//			for (Signature signature : packageInfo.signatures) {
//				if (WEIBO_SIGNATURE.equals(signature.toCharsString())) {
//					return true;
//				}
//			}
//		} catch (NameNotFoundException e) {
//			return false;
//		}
//
//		return false;
//	}

	/**
	 * IMPORTANT: This method must be invoked at the top of the calling
	 * activity's onActivityResult() function or Weibo authentication will not
	 * function properly!
	 * 
	 * If your calling activity does not currently implement onActivityResult(),
	 * you must implement it and include a call to this method if you intend to
	 * use the authorize() method in this SDK.
	 * 
	 * For more information, see
	 * http://developer.android.com/reference/android/app/
	 * Activity.html#onActivityResult(int, int, android.content.Intent)
	 */
	public void authorizeCallBack(int requestCode, int resultCode, Intent data) {
		if (requestCode == mAuthActivityCode) {

			// Successfully redirected.
			if (resultCode == Activity.RESULT_OK) {

				// Check OAuth 2.0/2.10 error code.
				String error = data.getStringExtra("error");
				if (error == null) {
					error = data.getStringExtra("error_type");
				}

				// error occurred.
				if (error != null) {
					if (error.equals("access_denied")
							|| error.equals("OAuthAccessDeniedException")) {
						Log.d("Weibo-authorize", "Login canceled by user.");
						mAuthDialogListener.onCancel();
					} else {
						String description = data
								.getStringExtra("error_description");
						if (description != null) {
							error = error + ":" + description;
						}
						Log.d("Weibo-authorize", "Login failed: " + error);
						mAuthDialogListener.onError(new DialogError(error,
								resultCode, description));
					}

					// No errors.
				} else {
					if (null == mAccessToken) {
						mAccessToken = new Token();
					}
					mAccessToken.setToken(data.getStringExtra(TOKEN));
					mAccessToken.setExpiresTime(data.getStringExtra(EXPIRES));
					mAccessToken.setRefreshToken(data
							.getStringExtra(REFRESHTOKEN));
					if (isSessionValid()) {
						Log.d("Weibo-authorize",
								"Login Success! access_token="
										+ mAccessToken.getToken() + " expires="
										+ mAccessToken.getExpiresTime()
										+ "refresh_token="
										+ mAccessToken.getRefreshToken());
						mAuthDialogListener.onComplete(data.getExtras());
					} else {
						Log.d("Weibo-authorize",
								"Failed to receive access token by SSO");
						startDialogAuth(mAuthActivity, mAuthPermissions);
					}
				}

				// An error occurred before we could be redirected.
			} else if (resultCode == Activity.RESULT_CANCELED) {

				// An Android error occured.
				if (data != null) {
					Log.d("Weibo-authorize",
							"Login failed: " + data.getStringExtra("error"));
					mAuthDialogListener.onError(new DialogError(data
							.getStringExtra("error"), data.getIntExtra(
							"error_code", -1), data
							.getStringExtra("failing_url")));

					// User pressed the 'back' button.
				} else {
					Log.d("Weibo-authorize", "Login canceled by user.");
					mAuthDialogListener.onCancel();
				}
			}
		}
	}

	public void dialog(Context context, WeiboParameters parameters,
			final WeiboDialogListener listener) {
		parameters.add("client_id", APP_KEY);//AppKey
		parameters.add("response_type", "token");//设置返回类型为token
		parameters.add("redirect_uri", mRedirectUrl);//设置回调url
		parameters.add("forcelogin","true");
		parameters.add("display", "mobile");//授权页面的终端类型:mobile 移动终端的授权页面，适用于支持html5的手机。 

		if (isSessionValid()) {
			parameters.add(TOKEN, mAccessToken.getToken());//用来调用其它接口的授权过的accesstoken
		}
		String url = URL_OAUTH2_ACCESS_AUTHORIZE + "?"
				+ Utility.encodeUrl(parameters);
		Log.d("TAG", "WeiboDialog: " + url);
		if (context.checkCallingOrSelfPermission(Manifest.permission.INTERNET) != PackageManager.PERMISSION_GRANTED) {
			Utility.showAlert(context, "Error",
					"Application requires permission to access the Internet");
		} else {
			Log.d("TAG", "WeiboDialog!!!!!!!!!");
			mWeiboDialog = new WeiboDialog(this, context, url, listener);
			mWeiboDialog.show();
		}
	}
	
	private WeiboDialog mWeiboDialog;
	public boolean isSessionValid() {
		if (mAccessToken != null) {
			long ExpiresTime = mAccessToken.getExpiresTime();
			long currentTime = System.currentTimeMillis();
			boolean empty = TextUtils.isEmpty(mAccessToken.getToken());
			Log.d("isSessionValid",
					"mAccessToken:"+ empty+
							",System.currentTimeMillis():"+currentTime+
							",mAccessToken:"+ExpiresTime);
			return (!TextUtils.isEmpty(mAccessToken.getToken()) && (mAccessToken
					.getExpiresTime() == 0 || (System.currentTimeMillis() < mAccessToken
					.getExpiresTime())));
		}
		return false;
	}
}
