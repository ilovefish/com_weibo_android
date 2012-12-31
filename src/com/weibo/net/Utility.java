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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRouteParams;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.AlertDialog.Builder;
import android.content.Context;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;

/**
 * Utility class for Weibo object.
 * 
 * @author (luopeng@staff.sina.com.cn zhangjie2@staff.sina.com.cn 官方微博：WBSDK  http://weibo.com/u/2791136085)
 * 
 * 
 */

public class Utility {

    private static WeiboParameters mRequestHeader = new WeiboParameters();//key value map object
    
    /**@used ”Authorization” headerader
     * */
    private static HttpHeaderFactory mAuth;//used Authorization header
    private static Token mToken = null;//used Authorization" header

    /**@used ”Content-Type” header
     * */
    public static final String BOUNDARY = "7cd4a6d158c";
    public static final String MP_BOUNDARY = "--" + BOUNDARY;
    public static final String END_MP_BOUNDARY = "--" + BOUNDARY + "--";
    public static final String MULTIPART_FORM_DATA = "multipart/form-data";

    
    public static final String HTTPMETHOD_POST = "POST";
    public static final String HTTPMETHOD_GET = "GET";
    public static final String HTTPMETHOD_DELETE = "DELETE";

    private static final int SET_CONNECTION_TIMEOUT = 50000;
    private static final int SET_SOCKET_TIMEOUT = 200000;

    /*成员变量相关方法*/
    /**
     * @function isBundleEmpty
     * 
     * @think 避免直接操作mRequestHeader
     * 		
     * */
    public static boolean isBundleEmpty(WeiboParameters bundle) {
        if (bundle == null || bundle.size() == 0) {
            return true;
        }
        return false;
    }
    
    /**
     * @function set mRequestHeader by key&value
     * 
     * @think 避免直接操作mRequestHeader
     * 		
     * */
    public static void setRequestHeader(String key, String value) {
        // mRequestHeader.clear();
        mRequestHeader.add(key, value);
    }
    
    /**
     * @function set mRequestHeader by WeiboParameters
     * 
     * @think 避免直接操作mRequestHeader
     * 		
     * */
    public static void setRequestHeader(WeiboParameters params) {
        mRequestHeader.addAll(params);
    }
    
    /**
     * 
     * @function clear mRequestHeader
     * 
     * @think 避免直接操作mRequestHeader
     * 		
     * */
    public static void clearRequestHeader() {
        mRequestHeader.clear();

    }
    
    /**
     * @function set Token
     * */
    public static void setTokenObject(Token token) {
        mToken = token;
    }
    
    /**
     * @function set HttpHeaderFactory for Authorization header
     * */
    public static void setAuthorization(HttpHeaderFactory auth) {
        mAuth = auth;
    }  
    /*成员变量相关方法*/
    
    /**
     * @function set the same header No matter request method type
     * 
     * @param httpMethod
     * 
     * @param request
     * 
     * @param authParam about "Authorization"
     * 
     * @param url for "Authorization"
     * 
     * @param token for "Authorization"
     * 
     * @think 
     * 		1. mRequestHeader set public header
     * 		   as:"Accept-Encoding"="gzip"
     *      2. set "Authorization" header
     *      3. set "User-Agent" header
     * */
    public static void setHeader(String httpMethod, HttpUriRequest request,
            WeiboParameters authParam, String url, Token token) throws WeiboException {
        if (!isBundleEmpty(mRequestHeader)) {//
            for (int loc = 0; loc < mRequestHeader.size(); loc++) {
                String key = mRequestHeader.getKey(loc);
                request.setHeader(key, mRequestHeader.getValue(key));
                /*Utility.setRequestHeader("Accept-Encoding", "gzip");*/
            }
        }
        if (!isBundleEmpty(authParam) && mAuth != null) {
            String authHeader = mAuth.getWeiboAuthHeader(httpMethod, url, authParam,
                    Weibo.getAppKey(), Weibo.getAppSecret(), token);
            Log.d("authHeader","is "+ authHeader);
            if (authHeader != null) {
                request.setHeader("Authorization", authHeader);//主要生成"Authorization"header
            }
        }
        request.setHeader("User-Agent", System.getProperties().getProperty("http.agent")
                + " WeiboAndroidSDK");//设置用户代理，用来告知服务器类型
       
    }
    
    /** 
     * @function realize toString for <input type="text" name="name1"/><br/>
     * 			                      <input type="text" name="name2"/><br/>
     * @param parameters
     * @param boundary
     *            
     * @return form parameters String
     * 
     * @law 上传参数部分的格式规律:
     * 		1.“Content-Disposition: form-data;”
	 *		2.“name=”name1″”+“\r\n”
	 *	      “\r\n”
	 *		3.“value=”value1″”+“\r\n”
	 *		4.“—————————–7d92221b604bc”+“\r\n”   
	 *
     */
    public static String encodePostBody(Bundle parameters, String boundary) {
        if (parameters == null)
            return "";
        StringBuilder sb = new StringBuilder();

        for (String key : parameters.keySet()) {
            if (parameters.getByteArray(key) != null) {
                continue;
            }
            
            sb.append("Content-Disposition: form-data; name=\"" + key + "\"\r\n\r\n"/*换两行行*/
                    + parameters.getString(key));
            sb.append("\r\n" + "--" + boundary + "\r\n");
        }

        return sb.toString();
    }
    
    /** 
     * @function realize toString for WeiboParameters to "&rsv_spt=1&issp=1&rsv_bp=0&ie=utf-8&tn=baiduhome_pg&inputT=1324"
     * 
     * @param parameters
     *            
     * @return url parameters String
     * 
     * @law url参数格式规律:
     * 		&key=calue 
     */
    public static String encodeUrl(WeiboParameters parameters) {
        if (parameters == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (int loc = 0; loc < parameters.size(); loc++) {
            if (first)
                first = false;
            else
                sb.append("&");
            sb.append(URLEncoder.encode(parameters.getKey(loc)) + "="
                    + URLEncoder.encode(parameters.getValue(loc)));
        }
        return sb.toString();
    }
    
    /** 
     * @function realize toBundle for "&rsv_spt=1" to key=rsv_spt,vaule=1
     * 
     * @param String s
     *            
     * @return Bundle
     * 
     * @law url参数格式规律:
     * 		&key=calue 
     */
    public static Bundle decodeUrl(String s) {
    	if(s==null)Log.d("decodeUrl","null");
        Bundle params = new Bundle();
        if (s != null) {
            String array[] = s.split("&");
            for (String parameter : array) {
                String v[] = parameter.split("=");
                params.putString(URLDecoder.decode(v[0]), URLDecoder.decode(v[1]));
            }
        }
        return params;
    }
    
    /**
     * @function Parse a URL query and fragment parameters into a key-value bundle.
     * 			 for "&rsv_spt=1" to key=rsv_spt,vaule=1 and "&rsv_spt=1#222" to 222
     * @param url
     *            the URL to parse
     * @return a dictionary bundle of keys and values
     * 
     * @law url参数格式规律:
     * 		&key=calue#222 
     */
    public static final String TOKEN = "access_token";
	public static final String EXPIRES = "expires_in";
	public static final String REFRESHTOKEN = "refresh_token";
    public static Bundle parseUrl(String url) {
        // hack to prevent MalformedURLException
    	Log.d("parseUrl",url);
        url = url.replace("http", "http");
        try {
            URL u = new URL(url);
            Log.d("parseUrl",u.toString());
            Bundle b = decodeUrl(u.getQuery());
            b.putAll(decodeUrl(u.getRef()));
            String access_token = b.getString(TOKEN);
			String ExpiresTime = b.getString(EXPIRES);
			String RefreshToken = b.getString(REFRESHTOKEN);
			Log.d("parseUrl",access_token+" "+ExpiresTime+" "+RefreshToken);
            return b;
        } catch (MalformedURLException e) {
            return new Bundle();
        }
    }
    
    /**
     * @function Construct a url encoded entity by parameters for Bundle to UrlEncodedFormEntity
     * 
     * @param bundle
     *            :parameters key pairs
     * @return UrlEncodedFormEntity: encoed entity
     * 
     * @law 
     * 
     * @think Bundle->NameValuePair->UrlEncodedFormEntity
     */
    public static UrlEncodedFormEntity getPostParamters(Bundle bundle) throws WeiboException {
        if (bundle == null || bundle.isEmpty()) {
            return null;
        }
        try {
            List<NameValuePair> form = new ArrayList<NameValuePair>();
            for (String key : bundle.keySet()) {
                form.add(new BasicNameValuePair(key, bundle.getString(key)));
            }
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(form, "UTF-8");
            return entity;
        } catch (UnsupportedEncodingException e) {
            throw new WeiboException(e);
        }
    }
    
    /**
     * @function Implement a weibo http request and return results .
     * 			 for discriminate flie Whether or not null then openUrl
     * @param context
     *            : context of activity
     * @param url
     *            : request url of open api
     * @param method
     *            : HTTP METHOD.GET, POST, DELETE
     * @param params
     *            : Http params , query or postparameters
     * @param Token
     *            : oauth token or accesstoken
     * @return UrlEncodedFormEntity: encoed entity
     * 
     * @law
     * 
     * @think
     */
    public static String openUrl(Context context, String url, String method,
            WeiboParameters params, Token token) throws WeiboException {
        String rlt = "";
        String file = "";
        for (int loc = 0; loc < params.size(); loc++) {
            String key = params.getKey(loc);
            if (key.equals("pic")) {
                file = params.getValue(key);
                params.remove(key);
            }
        }
        if (TextUtils.isEmpty(file)) {
            rlt = openUrl(context, url, method, params, null, token);
        } else {
            rlt = openUrl(context, url, method, params, file, token);
        }
        return rlt;
    }
    
    /**
     * @function Implement a weibo http request and return results .
     * 			 
     * @param context
     *            : context of activity
     * @param url
     *            : request url of open api
     * @param method
     *            : HTTP METHOD.GET, POST, DELETE
     * @param params
     *            : Http params , query or postparameters
     * @param file
     * 			  : file 
     * @param Token
     *            : oauth token or accesstoken
     * @return UrlEncodedFormEntity: encoed entity
     * 
     * @law Content-Type header format and assign boundary
     * 		”Content-Type”, MULTIPART_FORM_DATA + “; boundary=” + BOUNDARY
     * 
     * @think
     * 1.get HttpClient
     * 
     * 2.request:
     * 	 different:
     * 	 method:GET
     * 		get url = url + ? + params like "http://www.baidu.com/s?wd=1"
     * 		get HttpGet
     *   method:POST
     *   	get url = url
     *   	get HttpPost
     *   	set header "application/x-www-form-urlencoded" or "multipart/form-data"
     *   	set content "application/x-www-form-urlencoded" content or "multipart/form-data" content
     *   	set entity ByteArrayOutputStream-> ByteArrayEntity
     *   method:DELETE
     *   	get url = url
     *      get HttpDelete
     *   same:
     *   	set Header:
     *   	1. mRequestHeader set public header
     * 		   as:"Accept-Encoding"="gzip"
     *      2. set "Authorization" header
     *      3. set "User-Agent" header
     *     
     *   Response:  
     *   	1.get statusCode:
     *   	  no 200:parse JSON
     *   	  200:parse JSON
     */
    public static String openUrl(Context context, String url, String method,
            WeiboParameters params, String file, Token token) throws WeiboException {
        String result = "";
        try {
            HttpClient client = getNewHttpClient(context);
            HttpUriRequest request = null;
            ByteArrayOutputStream bos = null;
            if (method.equals("GET")) {
                url = url + "?" + encodeUrl(params);
                HttpGet get = new HttpGet(url);
                request = get;
            } else if (method.equals("POST")) {
                HttpPost post = new HttpPost(url);
                byte[] data = null;
                bos = new ByteArrayOutputStream(1024 * 50);
                if (!TextUtils.isEmpty(file)) {
                    Utility.paramToUpload(bos, params);
                    post.setHeader("Content-Type", MULTIPART_FORM_DATA + "; boundary=" + BOUNDARY);
                    Bitmap bf = BitmapFactory.decodeFile(file);

                    Utility.imageContentToUpload(bos, bf);

                } else {
                    post.setHeader("Content-Type", "application/x-www-form-urlencoded"/*称/值对编码*/);
                    String postParam = encodeParameters(params);
                    data = postParam.getBytes("UTF-8");
                    bos.write(data);
                }
                data = bos.toByteArray();
                bos.close();
                // UrlEncodedFormEntity entity = getPostParamters(params);
                ByteArrayEntity formEntity = new ByteArrayEntity(data);
                post.setEntity(formEntity);
                request = post;//post:Content-Type  header and entity
            } else if (method.equals("DELETE")) {
                request = new HttpDelete(url);
            }
            setHeader(method, request, params, url, token);
            HttpResponse response = client.execute(request);
            StatusLine status = response.getStatusLine();
            int statusCode = status.getStatusCode();

            if (statusCode != 200) {
                result = read(response);
                String err = null;
                int errCode = 0;
				try {
					JSONObject json = new JSONObject(result);
					err = json.getString("error");
					errCode = json.getInt("error_code");
					Log.d("eer","eer is "+err+" rreCode is"+errCode);
				} catch (JSONException e) {
					e.printStackTrace();
				}
				throw new WeiboException(String.format(err), errCode);
            }
            // parse content stream from response
            result = read(response);
            return result;
        } catch (IOException e) {
            throw new WeiboException(e);
        }
    }
    
    /**
     * @function getNewHttpClient
     * 
     * @think
     *  1.set Socket:SSL TLS X509 KeyStore and HOSTNAME_VERIFIER
     *  2.set ThreadSafeClientConnManager:HttpVersion ContentCharset SchemeRegistry
     *  3.set HttpClient:ConnectionTimeout SoTimeout ThreadSafeClientConnManager
     *  4.set HttpHost:by APN
     * */
    public static HttpClient getNewHttpClient(Context context) {
        try {
        	Log.d("Utility", "getNewHttpClient");
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());//数字认证模式
            trustStore.load(null, null);//网络认证库

            SSLSocketFactory sf = new MySSLSocketFactory(trustStore);
            sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);//指定主机名校验器

            HttpParams params = new BasicHttpParams();

            HttpConnectionParams.setConnectionTimeout(params, 10000);
            HttpConnectionParams.setSoTimeout(params, 10000);

            HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
            HttpProtocolParams.setContentCharset(params, HTTP.UTF_8);

            SchemeRegistry registry = new SchemeRegistry();
            registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
            registry.register(new Scheme("https", sf, 443));

            ClientConnectionManager ccm = new ThreadSafeClientConnManager(params, registry);

            // Set the default socket timeout (SO_TIMEOUT) // in
            // milliseconds which is the timeout for waiting for data.
            HttpConnectionParams.setConnectionTimeout(params, Utility.SET_CONNECTION_TIMEOUT);
            HttpConnectionParams.setSoTimeout(params, Utility.SET_SOCKET_TIMEOUT);
            HttpClient client = new DefaultHttpClient(ccm, params);
            
            WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            WifiInfo info = wifiManager.getConnectionInfo();
            if (!wifiManager.isWifiEnabled() || -1 == info.getNetworkId()) {
                // 获取当前正在使用的APN接入点
                Uri uri = Uri.parse("content://telephony/carriers/preferapn");
                Cursor mCursor = context.getContentResolver().query(uri, null, null, null, null);
                if (mCursor != null && mCursor.moveToFirst()) {
                    // 游标移至第一条记录，当然也只有一条
                    String proxyStr = mCursor.getString(mCursor.getColumnIndex("proxy"));
                    if (proxyStr != null && proxyStr.trim().length() > 0) {
                        HttpHost proxy = new HttpHost(proxyStr, 80);
                        client.getParams().setParameter(ConnRouteParams.DEFAULT_PROXY, proxy);
                    }
                    mCursor.close();
                }
            }
            Log.d("Utility", "getNewHttpClient+newDefaultHttpClient");
            return client;
        } catch (Exception e) {
        	Log.d("Utility", "getNewHttpClient+DefaultHttpClient");
            return new DefaultHttpClient();
        }
    }
    
    /**
     * @function assign X509 the format of the digital certificate
     * */
    public static class MySSLSocketFactory extends SSLSocketFactory {
        SSLContext sslContext = SSLContext.getInstance("TLS");//SSL实例指定协议TLS

        public MySSLSocketFactory(KeyStore truststore) throws NoSuchAlgorithmException,
                KeyManagementException, KeyStoreException, UnrecoverableKeyException {
            super(truststore);

            TrustManager tm = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };

            sslContext.init(null, new TrustManager[] { tm }, null);//指定数字证书格式
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
                throws IOException, UnknownHostException {
            return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
        }

        @Override
        public Socket createSocket() throws IOException {
            return sslContext.getSocketFactory().createSocket();
        }
    }
    
    /**
     * @function Get a HttpClient object which is setting correctly(NO set Socket and ThreadSafeClientConnManager) .
     * 
     * @param context
     *            : context of activity
     * @return HttpClient: HttpClient object
     */
    public static HttpClient getHttpClient(Context context) {
        BasicHttpParams httpParameters = new BasicHttpParams();
        // Set the default socket timeout (SO_TIMEOUT) // in
        // milliseconds which is the timeout for waiting for data.
        HttpConnectionParams.setConnectionTimeout(httpParameters, Utility.SET_CONNECTION_TIMEOUT);
        HttpConnectionParams.setSoTimeout(httpParameters, Utility.SET_SOCKET_TIMEOUT);
        HttpClient client = new DefaultHttpClient(httpParameters);
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        WifiInfo info = wifiManager.getConnectionInfo();
        if (!wifiManager.isWifiEnabled() || -1 == info.getNetworkId()) {
            // 获取当前正在使用的APN接入点
            Uri uri = Uri.parse("content://telephony/carriers/preferapn");
            Cursor mCursor = context.getContentResolver().query(uri, null, null, null, null);
            if (mCursor != null && mCursor.moveToFirst()) {
                // 游标移至第一条记录，当然也只有一条
                String proxyStr = mCursor.getString(mCursor.getColumnIndex("proxy"));
                if (proxyStr != null && proxyStr.trim().length() > 0) {
                    HttpHost proxy = new HttpHost(proxyStr, 80);
                    client.getParams().setParameter(ConnRouteParams.DEFAULT_PROXY, proxy);
                }
                mCursor.close();
            }
        }
        return client;
    }
    
    /**
     * @function Upload image into output stream for like <input type="file" name="file1"/><br/>
     * 
     * @param out
     *            : output stream for uploading weibo
     * @param imgpath
     *            : bitmap for uploading
     * @return void
     * 
     * @law
     * for:
     * “—————————–7d92221b604bc”+“\r\n”
	 *	“Content-Disposition: form-data;”+“name=”file2″;”+“filename=”C:\2.txt””+“\r\n”
	 *	“Content-Type: text/plain”+“\r\n\r\n”
	 *	二进制数+”\r\n”
	 *	end:
	 *	"\r\n"+“—————————–7d92221b604bc–”
     */
    private static void imageContentToUpload(OutputStream out, Bitmap imgpath)
            throws WeiboException {
        StringBuilder temp = new StringBuilder();

        temp.append(MP_BOUNDARY).append("\r\n");
        temp.append("Content-Disposition: form-data; name=\"pic\"; filename=\"")
                .append("news_image").append("\"\r\n");
        String filetype = "image/png";
        temp.append("Content-Type: ").append(filetype).append("\r\n\r\n");
        byte[] res = temp.toString().getBytes();
        BufferedInputStream bis = null;
        try {
            out.write(res);
            imgpath.compress(CompressFormat.PNG, 75, out);
            out.write("\r\n".getBytes());
            out.write(("\r\n" + END_MP_BOUNDARY).getBytes());
        } catch (IOException e) {
            throw new WeiboException(e);
        } finally {
            if (null != bis) {
                try {
                    bis.close();
                } catch (IOException e) {
                    throw new WeiboException(e);
                }
            }
        }
    }
    
    /**
     * @function Upload weibo contents into output stream .
     * 
     * @param baos
     *            : output stream for uploading weibo
     * @param params
     *            : post parameters for uploading
     * @return void
     * 
     * @law 上传参数部分的格式规律:
     * 		for:
	 *		“—————————–7d92221b604bc”“\r\n”
     * 		“Content-Disposition: form-data;”
	 *		“name=”name1″”+“\r\n”
	 *	    “\r\n”
	 *		“value1”+“\r\n” 
     *
	 * @think params->StringBuilder->OutputStream
     */
    private static void paramToUpload(OutputStream baos, WeiboParameters params)
            throws WeiboException {
        String key = "";
        for (int loc = 0; loc < params.size(); loc++) {
            key = params.getKey(loc);
            StringBuilder temp = new StringBuilder(10);
            temp.setLength(0);
            temp.append(MP_BOUNDARY).append("\r\n");
            temp.append("content-disposition: form-data; name=\"").append(key).append("\"\r\n\r\n");
            temp.append(params.getValue(key)).append("\r\n");
            byte[] res = temp.toString().getBytes();
            try {
                baos.write(res);
            } catch (IOException e) {
                throw new WeiboException(e);
            }
        }
    }
    
    /**
     * @function Read http requests result from response .
     * 
     * @param response
     *            : http response by executing httpclient
     * 
     * @return String : http response content
     * 
     * @think entity -> GZIPInputStream -> ByteArrayOutputStream -> String
     */
    private static String read(HttpResponse response) throws WeiboException {
        String result = "";
        HttpEntity entity = response.getEntity();
        InputStream inputStream;
        try {
            inputStream = entity.getContent();
            ByteArrayOutputStream content = new ByteArrayOutputStream();

            Header header = response.getFirstHeader("Content-Encoding");
            if (header != null && header.getValue().toLowerCase().indexOf("gzip") > -1) {
                inputStream = new GZIPInputStream(inputStream);
            }

            // Read response into a buffered stream
            int readBytes = 0;
            byte[] sBuffer = new byte[512];
            while ((readBytes = inputStream.read(sBuffer)) != -1) {
                content.write(sBuffer, 0, readBytes);
            }
            // Return result from buffered stream
            result = new String(content.toByteArray());
            return result;
        } catch (IllegalStateException e) {
            throw new WeiboException(e);
        } catch (IOException e) {
            throw new WeiboException(e);
        }
    }
    
    /**
     * @function Read http requests result from inputstream .
     * 
     * @param inputstream
     *            : http inputstream from HttpConnection
     * 
     * @return String : http response content
     * 
     * @think BufferedReader -> StringBuilder -> String
     */
    private static String read(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(in), 1000);
        for (String line = r.readLine(); line != null; line = r.readLine()) {
            sb.append(line);
        }
        in.close();
        return sb.toString();
    }
    
    /**
     * @function Clear current context cookies .
     * 
     * @param context
     *            : current activity context.
     * 
     * @return void
     */
    public static void clearCookies(Context context) {
        @SuppressWarnings("unused")
        CookieSyncManager cookieSyncMngr = CookieSyncManager.createInstance(context);
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.removeAllCookie();
    }
    
    /**
     * @function Display a simple alert dialog with the given text and title.
     * 
     * @param context
     *            Android context in which the dialog should be displayed
     * @param title
     *            Alert dialog title
     * @param text
     *            Alert dialog message
     */
    public static void showAlert(Context context, String title, String text) {
        Builder alertBuilder = new Builder(context);
        alertBuilder.setTitle(title);
        alertBuilder.setMessage(text);
        alertBuilder.create().show();
    }
    
    /**
     * @function realize toString for "rsv_spt=1&issp=1&rsv_bp=0" and
     * 			 use URLDecoder,URLEncoder 用于application/x-www-form-rulencoded MIME字符串之间的转换
     * */
    public static String encodeParameters(WeiboParameters httpParams) {
        if (null == httpParams || Utility.isBundleEmpty(httpParams)) {
            return "";
        }
        StringBuilder buf = new StringBuilder();
        int j = 0;
        for (int loc = 0; loc < httpParams.size(); loc++) {
            String key = httpParams.getKey(loc);
            if (j != 0) {
                buf.append("&");
            }
            try {
                buf.append(URLEncoder.encode(key, "UTF-8")).append("=")
                        .append(URLEncoder.encode(httpParams.getValue(key), "UTF-8"));
            } catch (java.io.UnsupportedEncodingException neverHappen) {
            }
            j++;
        }
        return buf.toString();

        
    }
    
    /**
     * @function Base64 encode mehtod for weibo request.Refer to weibo development
     * document.
     * 8Bit字节代码的编码方式,RFC2045～RFC2049
     */
    public static char[] base64Encode(byte[] data) {
        final char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                .toCharArray();
        char[] out = new char[((data.length + 2) / 3) * 4];
        for (int i = 0, index = 0; i < data.length; i += 3, index += 4) {
            boolean quad = false;
            boolean trip = false;
            int val = (0xFF & (int) data[i]);
            val <<= 8;
            if ((i + 1) < data.length) {
                val |= (0xFF & (int) data[i + 1]);
                trip = true;
            }
            val <<= 8;
            if ((i + 2) < data.length) {
                val |= (0xFF & (int) data[i + 2]);
                quad = true;
            }
            out[index + 3] = alphabet[(quad ? (val & 0x3F) : 64)];
            val >>= 6;
            out[index + 2] = alphabet[(trip ? (val & 0x3F) : 64)];
            val >>= 6;
            out[index + 1] = alphabet[val & 0x3F];
            val >>= 6;
            out[index + 0] = alphabet[val & 0x3F];
        }
        return out;
    }
        
    /**
     * @function digest MD5 encode mehtod
     * 确保信息传输完整一致,RFC 1321
     * */
    public static String digestMD5(String string) {
		String s = null;
		char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(string.getBytes());
			byte tmp[] = md.digest();
			char str[] = new char[16 * 2];
			int k = 0;
			for (int i = 0; i < 16; i++) {
				byte byte0 = tmp[i];
				str[k++] = hexDigits[byte0 >>> 4 & 0xf];
				str[k++] = hexDigits[byte0 & 0xf];
			}
			s = new String(str);
		}
		catch (Exception e) {
		}
		return s;
	}

}
