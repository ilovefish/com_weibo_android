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

import javax.crypto.spec.SecretKeySpec;

/**
 * A token base class contais token and secret.Whether accessToken or
 * requestToken should be as child of it.
 * 
 * @author (luopeng@staff.sina.com.cn zhangjie2@staff.sina.com.cn 官方微博：WBSDK  http://weibo.com/u/2791136085)
 */

public class Token {

    // mToken 可能是access token， 可能是oauth_token
    private String mToken = "";
    private String mRefreshToken = "";
    private long mExpiresTime = 0;
    private long mUid = 0;

    private String mOauth_verifier = "";
    protected String mOauth_Token_Secret = "";
    protected String[] responseStr = null;
    protected SecretKeySpec mSecretKeySpec;

    public Token() {

    }

    public String getToken() {
        return this.mToken;
    }

    public String getRefreshToken() {
        return mRefreshToken;
    }

    public void setRefreshToken(String mRefreshToken) {
        this.mRefreshToken = mRefreshToken;
    }

    public long getExpiresTime() {
        return this.mExpiresTime;
    }

    /**
     * 
     * @param expiresIn 过期时间长度值，仅当从服务器获取到数据时使用此方法
     */
    public void setExpiresTime(String expiresIn) {
        if (expiresIn != null && !expiresIn.equals("0")) {
            setExpiresTime(System.currentTimeMillis() + Long.parseLong(expiresIn) * 1000);
        }
    }
    
    /**
     * 
     * @param mExpiresTime 过期时刻点 时间值
     */
    public void setExpiresTime(long mExpiresTime) {
        this.mExpiresTime = mExpiresTime;
    }

    

    public void setToken(String mToken) {
        this.mToken = mToken;
    }

    public void setVerifier(String verifier) {
        mOauth_verifier = verifier;
    }

    public String getVerifier() {
        return mOauth_verifier;
    }

    public String getSecret() {
        return mOauth_Token_Secret;
    }

    public Token(String rltString) {
        responseStr = rltString.split("&");
        mOauth_Token_Secret = getParameter("oauth_token_secret");
        mToken = getParameter("oauth_token");
    }

    public Token(String token, String secret) {
        mToken = token;
        mOauth_Token_Secret = secret;
    }

    public String getParameter(String parameter) {
        String value = null;
        for (String str : responseStr) {
            if (str.startsWith(parameter + '=')) {
                value = str.split("=")[1].trim();
                break;
            }
        }
        return value;
    }

    protected void setSecretKeySpec(SecretKeySpec secretKeySpec) {
        this.mSecretKeySpec = secretKeySpec;
    }

    protected SecretKeySpec getSecretKeySpec() {
        return mSecretKeySpec;
    }

	public long getUid() {
		return mUid;
	}

	public void setUid(long mUid) {
		this.mUid = mUid;
	}

}
