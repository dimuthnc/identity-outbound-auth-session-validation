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

/**
 * Constants used by the SessionCountAuthenticator
 */
public abstract class SessionCountAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "SessionCountAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "sessionCount";
    public static final String USERNAME_TAG = "username";
    public static final String SESSION_LIMIT_TAG = "sessionLimit";
    public static final String USER_STORE_TAG = "userstoreDomain";
    public static final String CONTENT_TYPE_TAG = "Content-type";
    public static final String AUTH_TYPE_KEY = "Basic ";

    public static final String QUOTE = "\"";
    public static final String ATTRIBUTE_SEPARATOR = ":";

    public static final String ACTIVE_SESSION_TABLE_NAME = "ORG_WSO2_IS_ANALYTICS_STREAM_ACTIVESESSIONS";
    public static final String TABLE_NAME_TAG = "tableName";
    public static final String QUERY_TAG = "query";
    public static final String COUNT_TAG = "count";
    public static final String START_TAG = "start";

    public static final String TENANT_DOMAIN_TAG = "tenantDomain";
    public static final String AND_TAG = " AND ";
    public static final String SESSION_TERMINATION_SERVLET_INPUT = "sessionTerminationDataInput";

    public static final String TABLE_SEARCH_URL = "https://localhost:9444/analytics/search";

    public static final int START_INDEX = 0;
    public static final int SESSION_COUNT_MAX = 100;

    public static final String LOGIN_STANDARD_PAGE = "authenticationendpoint/login.do";
    public static final String SESSION_TERMINATION_ENFORCER_PAGE = "sessioncountauthenticationendpoint/Session.jsp";
    public static final String AUTHENTICATOR_TYPE = "LOCAL";

}
