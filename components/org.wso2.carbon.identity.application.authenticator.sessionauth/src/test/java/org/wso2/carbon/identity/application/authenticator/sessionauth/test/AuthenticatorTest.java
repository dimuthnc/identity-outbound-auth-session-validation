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

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.sessionauth.SessionCountAuthenticator;
import org.wso2.carbon.identity.application.authenticator.sessionauth.SessionCountAuthenticatorConstants;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * Class for testing Authenticator
 */
public class AuthenticatorTest {

    SessionCountAuthenticator sessionCountAuthenticator = new SessionCountAuthenticator();
    @Mock
    HttpServletRequest request;
    @Mock
    HttpServletResponse response;
    @Mock
    SequenceConfig sequenceConfig;
    Map<Integer, StepConfig> stepMap;
    @Mock
    StepConfig stepConfig;
    @Mock
    AuthenticatedUser authenticatedUser;
    @Mock
    LocalApplicationAuthenticator localApplicationAuthenticator;
    @Mock
    AuthenticatorConfig authenticatorConfig;

    AuthenticationContext context = new AuthenticationContext();

    //method for setting up tests and mock objects
    @BeforeClass
    public void setup() {

        initMocks(this);

    }

    //method to test getName function
    @Test
    public void testGetName() {

        Assert.assertEquals(sessionCountAuthenticator.getName(), SessionCountAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    //method to test getFriendlyName function
    @Test
    public void testGetFriendlyName() {

        Assert.assertEquals(sessionCountAuthenticator.getFriendlyName(),
                SessionCountAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    //Testing for logout requests
    @Test
    public void testProcessLogout() throws AuthenticationFailedException {

        context.setLogoutRequest(true);
        Assert.assertEquals(sessionCountAuthenticator.process(request, response, context), AuthenticatorFlowStatus
                .SUCCESS_COMPLETED);
    }

    //testing when initial request is called and authenticated user is null. AuthenticationFailed exception is expected
    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessInitialRequest() throws AuthenticationFailedException {

        context.setLogoutRequest(false);
        AuthenticatedUser authenticatedUserNull = null;
        stepMap = new HashMap<>();
        stepMap.put(0, stepConfig);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(1);
        when(sequenceConfig.getStepMap()).thenReturn(stepMap);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUserNull);
        sessionCountAuthenticator.process(request, response, context);

    }

    //testing when initial request is called and authenticated user is not null. Null pointer exception is expected
    // as it cannot retrieve data from ConfigurationFacade
    @Test(expectedExceptions = NullPointerException.class)
    public void testProcessInitialRequestWithValidUser() throws AuthenticationFailedException {

        SessionCountAuthenticator sessionCountAuthenticator = spy(SessionCountAuthenticator.class);
        context.setLogoutRequest(false);
        stepMap = new HashMap<>();
        stepMap.put(0, stepConfig);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(1);
        when(sequenceConfig.getStepMap()).thenReturn(stepMap);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(localApplicationAuthenticator);
        sessionCountAuthenticator.process(request, response, context);

    }

}
