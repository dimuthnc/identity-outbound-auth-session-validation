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
package org.wso2.carbon.identity.application.authenticator.sessionauth.javascript.function;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.javascript.flow.IsValidFunction;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import org.wso2.carbon.identity.application.authenticator.sessionauth.util.SessionValidationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.lang.Integer.parseInt;

/**
 * Function to check if the given user has valid number of sessions.
 * The purpose is to perform dynamic authentication selection based on the active session count.
 */
public class IsWithinSessionLimitFunction implements IsValidFunction {

    private static final Log log = LogFactory.getLog(org.wso2.carbon.identity.application.authentication.framework.javascript.flow.IsWithinSessionLimitFunction.class);
    private static final String USERNAME_CONFIG_NAME = "AnalyticsCredentials.Username";
    private static final String PASSWORD_CONFIG_NAME = "AnalyticsCredentials.Password";

    /**
     * Method to validate user session a given the authentication context and set of required attributes
     *
     * @param context Authentication context
     * @param map     Hash map of attributes required for validation
     * @return boolean value indicating the validation success/failure
     * @throws AuthenticationFailedException when exception occurred in session retrieving method
     */
    @Override
    public Boolean validate(JsAuthenticationContext context, Map<String, String> map)
            throws AuthenticationFailedException {

        boolean state = false;
        int sessionLimit = getSessionLimitFromMap(map);
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Unable to find the Authenticated user from previous step");
        }
        try {
            int sessionCount = getActiveSessionCount(authenticatedUser);
            if (sessionCount < sessionLimit) {
                state = true;
            }
        } catch (FrameworkException e) {
            throw new AuthenticationFailedException("Problem occurred in session data retrieving", e);
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException("Failed to retrieve session count from response", e);
        }
        return state;
    }

    /**
     * Method used for adding authentication header for httpMethod.
     *
     * @param httpMethod httpMethod that needs auth header to be added
     * @param username   username of user
     * @param password   password of the user
     */
    private void setAuthorizationHeader(HttpRequestBase httpMethod, String username, String password) {

        String toEncode = username + SessionValidationConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR + password;
        byte[] encoding = Base64.encodeBase64(toEncode.getBytes(Charset.forName(StandardCharsets.UTF_8.name())));
        String authHeader = new String(encoding, Charset.defaultCharset());
        httpMethod.addHeader(HTTPConstants.HEADER_AUTHORIZATION,
                SessionValidationConstants.JSSessionCountValidation.AUTH_TYPE_KEY + authHeader);
    }

    /**
     * Method for generating the table query for retrieving session information.
     *
     * @param tenantDomain Tenant Domain User belong to
     * @param username     Username of the user
     * @param userStore    Userstore of the user
     * @return Query String
     */
    private String getQuery(String tenantDomain, String username, String userStore) {

        return SessionValidationConstants.JSSessionCountValidation.TENANT_DOMAIN_TAG +
                SessionValidationConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                tenantDomain +
                SessionValidationConstants.JSSessionCountValidation.AND_TAG +
                SessionValidationConstants.JSSessionCountValidation.USERNAME_TAG +
                SessionValidationConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                username +
                SessionValidationConstants.JSSessionCountValidation.AND_TAG +
                SessionValidationConstants.JSSessionCountValidation.USER_STORE_TAG +
                SessionValidationConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                userStore;
    }

    /**
     * Method for retrieving user defined maximum session limit from parameter map
     *
     * @param map parameter map passed from JS
     * @return inter indicating the maximum session Limit
     */
    private int getSessionLimitFromMap(Map<String, String> map) {

        return parseInt(map.get(SessionValidationConstants.JSSessionCountValidation.SESSION_LIMIT_TAG));
    }

    /**
     * Method to retrieve active session count for the given authenticated user
     *
     * @param authenticatedUser Authenticated user object
     * @return current active session count
     * @throws FrameworkException When the REST response is not in 200 state or failed to read REST response
     */
    private int getActiveSessionCount(AuthenticatedUser authenticatedUser) throws FrameworkException {

        int sessionCount;
        JSONObject paramMap = new JSONObject();

        paramMap.put(SessionValidationConstants.JSSessionCountValidation.TABLE_NAME_TAG,
                SessionValidationConstants.JSSessionCountValidation.ACTIVE_SESSION_TABLE_NAME);
        paramMap.put(SessionValidationConstants.JSSessionCountValidation.QUERY_TAG,
                getQuery(authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserName(),
                        authenticatedUser.getUserStoreDomain()));

        String data = paramMap.toString();
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        StringEntity entity = new StringEntity(data, ContentType.APPLICATION_JSON);
        HttpClient httpClient = httpClientBuilder.build();
        HttpPost request = new HttpPost(SessionValidationConstants.JSSessionCountValidation.TABLE_SEARCH_COUNT_URL);

        setAuthorizationHeader(request,
                IdentityUtil.getProperty(USERNAME_CONFIG_NAME),
                IdentityUtil.getProperty(PASSWORD_CONFIG_NAME));
        request.addHeader(SessionValidationConstants.JSSessionCountValidation.CONTENT_TYPE_TAG, "application/json");
        request.setEntity(entity);
        try {
            HttpResponse response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                        response.getEntity().getContent(),
                        SessionValidationConstants.JSSessionCountValidation.UTF_8_TAG))) {
                    StringBuilder responseResult = new StringBuilder();
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        responseResult.append(line);
                    }
                    sessionCount = parseInt(responseResult.toString());
                    return sessionCount;
                } catch (IOException e) {
                    throw new FrameworkException("Problem occurred while processing the HTTP Response ");
                }
            } else {
                throw new FrameworkException("Failed to retrieve data from endpoint.Response status code :" +
                        response.getStatusLine().getStatusCode());
            }

        } catch (IOException e) {
            throw new FrameworkException("Failed to execute the HTTP Post request");
        }

    }

}
