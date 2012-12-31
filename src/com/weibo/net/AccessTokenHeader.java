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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encapsulation a http accessToken headers. the order of weiboParameters will
 * not be changed. Otherwise the signature should not be calculated right.
 * 
 * @author (luopeng@staff.sina.com.cn zhangjie2@staff.sina.com.cn 官方微博：WBSDK  http://weibo.com/u/2791136085)
 */

/*http://api.t.sina.com.cn/oauth/access_token
 *使用oauth_token和oauth_token_secret获取access token
 * 
 * */
public class AccessTokenHeader extends HttpHeaderFactory {

	
	/**
     *  oauth_consumer_key - GDdmIQH6jhtmLUypg82g
	    oauth_nonce - 9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8
	    oauth_signature_method - HMAC-SHA1
	    oauth_token - 8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc
	    oauth_timestamp - 1272323047
	    oauth_verifier - pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY
	    oauth_version - 1.0
	    oauth_token_secret - x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA

     * */
    @Override
    public WeiboParameters generateSignatureList(WeiboParameters bundle) {
        if (bundle == null || (bundle.size() == 0)) {
            return null;
        }
        WeiboParameters pp = new WeiboParameters();
        String key = "oauth_consumer_key";
        pp.add(key, bundle.getValue(key));
        key = "oauth_nonce";
        pp.add(key, bundle.getValue(key));
        key = "oauth_signature_method";
        pp.add(key, bundle.getValue(key));
        key = "oauth_timestamp";
        pp.add(key, bundle.getValue(key));
        key = "oauth_token";
        pp.add(key, bundle.getValue(key));
        key = "oauth_verifier";
        pp.add(key, bundle.getValue(key));
        key = "oauth_version";
        pp.add(key, bundle.getValue(key));
        key = "source";
        pp.add(key, bundle.getValue(key));
        return pp;
    }

    //密钥
    @Override
    public String generateSignature(String data, Token token) throws WeiboException {
        byte[] byteHMAC = null;
        try {
            Mac mac = Mac.getInstance(HttpHeaderFactory.CONST_HMAC_SHA1);
            SecretKeySpec spec = null;
            if (null == token.getSecretKeySpec()) {
                String oauthSignature = encode(Weibo.getAppSecret()) + "&"
                        + encode(token.getSecret());
                spec = new SecretKeySpec(oauthSignature.getBytes(),
                        HttpHeaderFactory.CONST_HMAC_SHA1);
                token.setSecretKeySpec(spec);
            }
            spec = token.getSecretKeySpec();
            mac.init(spec);
            byteHMAC = mac.doFinal(data.getBytes());
        } catch (InvalidKeyException e) {
            throw new WeiboException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new WeiboException(e);
        }
        return String.valueOf(Utility.base64Encode(byteHMAC));
    }

    @Override
    public void addAdditionalParams(WeiboParameters des, WeiboParameters src) {
        // TODO Auto-generated method stub

    }

}
