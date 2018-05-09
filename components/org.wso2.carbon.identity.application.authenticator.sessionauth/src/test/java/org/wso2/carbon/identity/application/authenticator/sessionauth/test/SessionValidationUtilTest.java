/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.application.authenticator.sessionauth.test;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.http.Header;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.sessionauth.util.SessionValidationUtil;

/**
 * TODO:Class level comment
 */

public class SessionValidationUtilTest {
    @Test
    public void testGetQuery(){
        String actual ="tenantDomain:carbon.super AND username:user AND userstoreDomain:PRIMARY";
        String tenantDomain = "carbon.super";
        String username = "user";
        String userStoreDomain = "PRIMARY";
        Assert.assertEquals(actual, SessionValidationUtil.getQuery(tenantDomain,username,userStoreDomain));

    }

    @Test
    public void testSetAuthorizationHeader(){

        HttpPost httpPost = new HttpPost();
        String username = "admin";
        String password = "admin";
        httpPost = SessionValidationUtil.setAuthorizationHeader(httpPost,username,password);
        Header header = httpPost.getFirstHeader(HTTPConstants.HEADER_AUTHORIZATION);
        Assert.assertEquals("Basic YWRtaW46YWRtaW4=",header.getValue());


    }



}
