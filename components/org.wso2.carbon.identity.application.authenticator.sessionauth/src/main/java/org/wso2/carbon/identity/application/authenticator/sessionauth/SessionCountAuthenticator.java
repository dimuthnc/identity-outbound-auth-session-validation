/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.sessionauth;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.ssl.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Username Password based Authenticator
 */
public class SessionCountAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 1819664539416029245L;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final Log log = LogFactory.getLog(SessionCountAuthenticator.class);
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    private static JSONArray sessionMetaData = new JSONArray();

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return true;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        if (StringUtils.isNotEmpty(request.getParameter("sessionTerminationDataInput"))) {
            try {

                processAuthenticationResponse(request, response, context);
            } catch (Exception e) {
                log.info("Exception occurred");
                log.info(e.getMessage());
                context.setRetrying(true);
                context.setCurrentAuthenticator(getName());
                return initiateAuthRequest(response, context, e.getMessage());
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            return initiateAuthRequest(response, context, null);
        }
    }

    /**
     * This will prompt user to change the credentials only if the last password
     * changed time has gone beyond the pre-configured value.
     *
     * @param response the response
     * @param context  the authentication context
     */
    private AuthenticatorFlowStatus initiateAuthRequest(HttpServletResponse response, AuthenticationContext context,
                                                        String errorMessage)
            throws AuthenticationFailedException {

        log.info("INITIATE AUTHENTICATION REQUEST STARTED");
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);

        AuthenticatedUser authenticatedUser = stepConfig.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Authentication failed!. Failed to identify the user");
        }

        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {

            String data = "{" +
                    SessionCountAuthenticatorConstants.TABLE_NAME_TAG +
                    SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                    SessionCountAuthenticatorConstants.ACTIVE_SESSION_TABLE_NAME + "," +
                    SessionCountAuthenticatorConstants.QUERY_TAG +
                    SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                    getQuery(authenticatedUser.getTenantDomain(), authenticatedUser.getUserName(), authenticatedUser
                            .getUserStoreDomain())
                    + "," +
                    SessionCountAuthenticatorConstants.START_TAG +
                    SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                    SessionCountAuthenticatorConstants.START_INDEX + "," +
                    SessionCountAuthenticatorConstants.COUNT_TAG +
                    SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                    5 +
                    "}";

            HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
            StringEntity entity = new StringEntity(data, ContentType.APPLICATION_JSON);
            HttpClient httpClient = httpClientBuilder.build();

            String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SessionCountAuthenticatorConstants.LOGIN_STANDARD_PAGE,
                            SessionCountAuthenticatorConstants.PASSWORD_RESET_ENFORCER_PAGE);

            try {
                HttpPost httpRequest = new HttpPost(SessionCountAuthenticatorConstants.TABLE_SEARCH_URL);

                String toEncode = SessionCountAuthenticatorConstants.USERNAME_CONFIG
                        + SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR
                        + SessionCountAuthenticatorConstants.PASSWORD_CONFIG;
                byte[] encoding = Base64.encodeBase64(toEncode.getBytes());
                String authHeader = new String(encoding, Charset.defaultCharset());
                httpRequest.addHeader(HTTPConstants.HEADER_AUTHORIZATION, SessionCountAuthenticatorConstants.AUTH_TYPE_KEY +
                        authHeader);
                httpRequest.addHeader(SessionCountAuthenticatorConstants.CONTENT_TYPE_TAG, "application/json");
                httpRequest.setEntity(entity);
                HttpResponse httpResponse = httpClient.execute(httpRequest);
                if (httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(httpResponse.getEntity()
                            .getContent(),
                            SessionCountAuthenticatorConstants.UTF_8_TAG));
                    StringBuilder responseResult = new StringBuilder();
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        responseResult.append(line);
                    }
                    sessionMetaData = new JSONArray(responseResult.toString());
                    log.info(responseResult.toString());
                    byte[] encodedBytes = Base64.encodeBase64(responseResult.toString().getBytes());
                    String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                            context.getCallerSessionKey(), context.getContextIdentifier());

                    String retryParam = "";
                    if (context.isRetrying()) {
                        retryParam = "&authFailure=true&authFailureMsg=" + errorMessage;
                    }
                    String encodedUrl = loginPage + ("?" + queryParams + "&sessionData=" + new String(encodedBytes))
                            + "&authenticators=" + getName() + ":" + SessionCountAuthenticatorConstants.AUTHENTICATOR_TYPE
                            + retryParam;
                    response.sendRedirect(encodedUrl);

                } else {
                    log.error("Failed to retrieve data from endpoint. Error code :" +
                            httpResponse.getStatusLine().getStatusCode());
                }
                context.setCurrentAuthenticator(getName());
                return AuthenticatorFlowStatus.INCOMPLETE;

            } catch (IOException e) {
                log.error("Problem occurred in IO operations");
            }
        }
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        ArrayList<String> terminationSessionIdList = new ArrayList<>();
        for (int index = 0; index < sessionMetaData.length(); index++) {
            JSONObject session = new JSONObject(sessionMetaData.get(index).toString());
            if (StringUtils.isNotEmpty(request.getParameter(String.valueOf(session.get("id"))))) {
                terminationSessionIdList.add(request.getParameter(String.valueOf(session.get("id"))));
                log.info("Terminate the session with ID " + session.get("id"));
            }
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getFriendlyName() {

        return SessionCountAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return SessionCountAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    private String getQuery(String tenantDomain, String username, String userStore) {

        return SessionCountAuthenticatorConstants.QUOTE +
                SessionCountAuthenticatorConstants.TENANT_DOMAIN_TAG +
                SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                tenantDomain +
                SessionCountAuthenticatorConstants.AND_TAG +
                SessionCountAuthenticatorConstants.USERNAME_TAG +
                SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                username +
                SessionCountAuthenticatorConstants.AND_TAG +
                SessionCountAuthenticatorConstants.USERSTORE_TAG +
                SessionCountAuthenticatorConstants.ATTRIBUTE_SEPARATOR +
                userStore +
                SessionCountAuthenticatorConstants.QUOTE;
    }
}
