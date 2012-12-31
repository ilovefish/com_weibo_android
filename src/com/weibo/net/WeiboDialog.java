package com.weibo.net;

import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.http.SslError;
import android.os.Bundle;
import android.text.style.BackgroundColorSpan;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings.LayoutAlgorithm;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;

import com.weibo.android.R;

public class WeiboDialog extends Dialog {

	static final FrameLayout.LayoutParams FILL = new FrameLayout.LayoutParams(
			ViewGroup.LayoutParams.FILL_PARENT,
			ViewGroup.LayoutParams.FILL_PARENT);
	static final int MARGIN = 4;
	static final int PADDING = 2;

	private final Weibo mWeibo;
	private String mUrl;
	private WeiboDialogListener mListener;
	private ProgressDialog mSpinner;
	private ImageView mBtnClose;
	private WebView mWebView;
	private RelativeLayout webViewContainer;
	private RelativeLayout mContent;

	private final static String TAG = "Weibo-WebView";

	public WeiboDialog(final Weibo weibo, Context context, String url,
			WeiboDialogListener listener) {
		super(context,R.style.weibosdk_ContentOverlay);
		Log.d("WeiboDialog", "WeiboDialog");
		mWeibo = weibo;
		mUrl = url;
		mListener = listener;
		
	}
/**初始化对话框，例如调用setContentView(View)等*/
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		Log.d("WeiboDialog", "onCreate");
		mSpinner = new ProgressDialog(getContext());
		mSpinner.requestWindowFeature(Window.FEATURE_NO_TITLE);
		//mSpinner.setTitle("SpinnerDialog");
		//calling getWindow().requestFeature(),窗口扩展功能，这里的flag为没有标题栏
		mSpinner.setMessage("Loading...");
		mSpinner.setOnKeyListener(new OnKeyListener() {

			
			public boolean onKey(DialogInterface dialog, int keyCode,
					KeyEvent event) {
				Log.v("mSpinner", "is onKey!");
				switch (keyCode) {
				case KeyEvent.KEYCODE_BACK:
					Log.d(TAG,"KEYCODE_BACK");
					onBack();
					break;
				case KeyEvent.KEYCODE_HOME:
					Log.d(TAG,"KEYCODE_HOME");
					onBack();
					break;
				default:
					break;
				}
				return false;
			}

		});
		//setTitle("WebView");
		requestWindowFeature(Window.FEATURE_NO_TITLE);
		mContent = new RelativeLayout(getContext());
		
		
		setUpWebView();
		setUpCloseBtn();

		addContentView(mContent, new LayoutParams(LayoutParams.FILL_PARENT,
				LayoutParams.FILL_PARENT));
	}

	protected void onBack() {
		try {
			/*mSpinner的销毁*/
			mSpinner.dismiss();
			if (null != mWebView) {
				/*mWebView的销毁*/
				mWebView.stopLoading();
				mWebView.destroy();
			}
		} catch (Exception e) {
		}
		dismiss();
	}

	@Override
	public void onAttachedToWindow() {
		// TODO Auto-generated method stub
		this.getWindow().setType(WindowManager.LayoutParams.TYPE_KEYGUARD_DIALOG);
		super.onAttachedToWindow();
	}

	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		// TODO Auto-generated method stub
		switch (keyCode) {
		case KeyEvent.KEYCODE_BACK:
			Log.d(TAG,"KEYCODE_BACK");
			onBack();
			break;
		case KeyEvent.KEYCODE_HOME:
			Log.d(TAG,"KEYCODE_HOME");
			onBack();
		
			break;
		default:
			break;
		}
		return super.onKeyDown(keyCode, event);
	}

	private void setUpWebView() {
		webViewContainer = new RelativeLayout(getContext());

		mWebView = new WebView(getContext());
		mWebView.setVerticalScrollBarEnabled(false);
		mWebView.setHorizontalScrollBarEnabled(false);
		mWebView.getSettings().setJavaScriptEnabled(true);
		mWebView.getSettings().setLayoutAlgorithm(LayoutAlgorithm.SINGLE_COLUMN);
		mWebView.setWebViewClient(new WeiboDialog.WeiboWebViewClient());
		mWebView.loadUrl(mUrl);
		mWebView.setLayoutParams(FILL);
		mWebView.setVisibility(View.INVISIBLE);

		webViewContainer.addView(mWebView);

		RelativeLayout.LayoutParams lp = new RelativeLayout.LayoutParams(
				LayoutParams.FILL_PARENT, LayoutParams.FILL_PARENT);
		Resources resources = getContext().getResources();
		//设置边缘像素
		lp.leftMargin = resources
				.getDimensionPixelSize(R.dimen.weibosdk_dialog_left_margin);
		lp.topMargin = resources
				.getDimensionPixelSize(R.dimen.weibosdk_dialog_top_margin);
		lp.rightMargin = resources
				.getDimensionPixelSize(R.dimen.weibosdk_dialog_right_margin);
		lp.bottomMargin = resources
				.getDimensionPixelSize(R.dimen.weibosdk_dialog_bottom_margin);
		mContent.addView(webViewContainer, lp);
	}

	private void setUpCloseBtn() {
		/*mBtnClose
		 *设置了一个ImageView的功能
		 */
		mBtnClose = new ImageView(getContext());
		mBtnClose.setClickable(false);
		mBtnClose.setOnClickListener(new View.OnClickListener() {
			
			public void onClick(View v) {
				mListener.onCancel();
				WeiboDialog.this.dismiss();
			}
		});
		mBtnClose.setImageResource(R.drawable.weibosdk_close_selector);
		mBtnClose.setVisibility(View.INVISIBLE);

		RelativeLayout.LayoutParams closeBtnRL = new RelativeLayout.LayoutParams(
				LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
		closeBtnRL.addRule(RelativeLayout.ALIGN_PARENT_RIGHT);
		closeBtnRL.addRule(RelativeLayout.ALIGN_PARENT_TOP);
		closeBtnRL.topMargin = getContext().getResources()
				.getDimensionPixelSize(
						R.dimen.weibosdk_dialog_btn_close_right_margin);
		closeBtnRL.rightMargin = getContext().getResources()
				.getDimensionPixelSize(
						R.dimen.weibosdk_dialog_btn_close_top_margin);

		webViewContainer.addView(mBtnClose, closeBtnRL);
	}

	private class WeiboWebViewClient extends WebViewClient {

		//处理怎么加载url
		public boolean shouldOverrideUrlLoading(WebView view, String url) {
			Log.d(TAG, "Redirect URL: " + url);
			return super.shouldOverrideUrlLoading(view, url);
		}

		
		//Report an error to the host application
		//当点击一个url之后接受的错误
		public void onReceivedError(WebView view/*回调此函数的view*/, int errorCode/*错误的值*/,
				String description/*A String describing the error*/, String failingUrl/*加载错误的url*/) {
			super.onReceivedError(view, errorCode, description, failingUrl);
			mListener.onError(new DialogError(description, errorCode,
					failingUrl));
			WeiboDialog.this.dismiss();
		}

		//通过一个url加载page时调用一次，内容改变时不调用
		public void onPageStarted(WebView view, String url, Bitmap favicon/*网站地址边上的小图标*/) {
			Log.d(TAG, "onPageStarted URL: " + url);
			if (url.startsWith(mWeibo.getRedirectUrl())) {//处理回调url
				Log.d(TAG, "RedirectUrl: " + url);
				handleRedirectUrl(view, url);
				view.stopLoading();
				WeiboDialog.this.dismiss();
				return;
			}
			mSpinner.getWindow().setType(0);
			mSpinner.show();
			mSpinner.getWindow().setType(WindowManager.LayoutParams.TYPE_KEYGUARD_DIALOG);
			super.onPageStarted(view, url, favicon);
			
			
		}

		//Notify the host application that a page has finished loading
		public void onPageFinished(WebView view, String url) {
			Log.d(TAG, "onPageFinished URL: " + url);
			super.onPageFinished(view, url);
			if (mSpinner.isShowing()) {
				mSpinner.dismiss();
				mBtnClose.setVisibility(View.VISIBLE);
				mBtnClose.setClickable(true);
			}

			mContent.setBackgroundColor(Color.TRANSPARENT);
			webViewContainer
					.setBackgroundResource(R.drawable.weibosdk_dialog_bg);
			// mBtnClose.setVisibility(View.VISIBLE);
			mWebView.setVisibility(View.VISIBLE);
		}

		//SSL(Secure Sockets Layer 安全套接层),传输层安全（Transport Layer Security，TLS）
		//SSL协议位于TCP/IP协议与各种应用层协议之间，为数据通讯提供安全支持
		//主线程定义WebViewClient SslErrorHandler，传入webclient，等待回调 -->回调WebViewClient.onReceivedSslError 传入 SslErrorHandler 选择所回调的方法
		public void onReceivedSslError(WebView view, SslErrorHandler handler,
				SslError error) {
			handler.proceed();//进行证书
		}

	}

	private void handleRedirectUrl(WebView view, String url) {
		Bundle values = Utility.parseUrl(url);
		Log.d("TAG", "WeiboDialog: " + url);
		String error = values.getString("error");
		String error_code = values.getString("error_code");

		if (error == null && error_code == null) {
			mListener.onComplete(values);
			Log.d("TAG", "WeiboDialog: " + "!!!!!!!!!!!!!!!!");
		} else if (error.equals("access_denied")) {
			// 用户或授权服务器拒绝授予数据访问权限
			mListener.onCancel();
		} else {
			mListener.onWeiboException(new WeiboException(error, Integer
					.parseInt(error_code)));
		}
	}
}
