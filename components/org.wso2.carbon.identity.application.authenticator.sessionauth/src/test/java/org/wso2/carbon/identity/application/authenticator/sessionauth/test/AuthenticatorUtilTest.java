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
import org.json.JSONArray;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.sessionauth.SessionCountAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.sessionauth.exception.SessionValidationException;
import org.wso2.carbon.identity.application.authenticator.sessionauth.util.AuthenticatorUtil;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

/**
 * TODO:Class level comment
 */

public class AuthenticatorUtilTest {

    @Mock
    AuthenticatedUser authenticatedUserMock;



    @BeforeClass
    public void setup() {
        initMocks(this);
        when(authenticatedUserMock.getUserName()).thenReturn(
                TestUtils.getRandomString(10, true, false));
        when(authenticatedUserMock.getTenantDomain()).thenReturn(
                TestUtils.getRandomString(10, true, false));
        when(authenticatedUserMock.getUserStoreDomain()).thenReturn(
                TestUtils.getRandomString(10, true, false));

    }

    @Test
    public void testGetQuery() {

        String tenantDomain = TestUtils.getRandomString(5, true, false);
        String username = TestUtils.getRandomString(5, true, false);
        String userStoreDomain = TestUtils.getRandomString(5, true, false);
        String actual = "tenantDomain:" + tenantDomain + " AND username:" + username + " AND userstoreDomain:" + userStoreDomain;
        Assert.assertEquals(actual, AuthenticatorUtil.getQuery(tenantDomain, username, userStoreDomain));

    }

    @Test
    public void testSetAuthorizationHeader() {

        HttpPost httpPost = new HttpPost();
        String username = TestUtils.getRandomString(10, true, false);
        String password = TestUtils.getRandomString(20, true, true);
        String toEncode = username + SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR + password;
        byte[] encoding = org.apache.commons.codec.binary.Base64.encodeBase64(
                toEncode.getBytes(Charset.forName(StandardCharsets.UTF_8.name())));
        String authHeader = new String(encoding, Charset.defaultCharset());

        httpPost = AuthenticatorUtil.setAuthorizationHeader(httpPost, username, password);
        Header header = httpPost.getFirstHeader(HTTPConstants.HEADER_AUTHORIZATION);

        Assert.assertEquals("Basic " + authHeader, header.getValue());

    }
    //Test for JSON response is []
    @Test (expectedExceptions = {SessionValidationException.class,NullPointerException.class})
    public void testGetSessionDetails() throws IOException, SessionValidationException {
        JSONArray respond = AuthenticatorUtil.getSessionDetails(authenticatedUserMock);
        Assert.assertEquals(respond.toString().charAt(0), '[');
        Assert.assertEquals(respond.toString().charAt(respond.toString().length() - 1), ']');
    }





    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}
