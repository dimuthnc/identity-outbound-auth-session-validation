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
package org.wso2.carbon.identity.application.authenticator.sessionauth.util;

/**
 * TODO:Class level comment
 */
public class SessionValidationConstants {
    public static class JSSessionCountValidation{
        public static final String USERNAME_TAG = "username";
        public static final String USER_STORE_TAG = "userstoreDomain";
        public static final String CONTENT_TYPE_TAG = "Content-type";
        public static final String UTF_8_TAG = "UTF-8";
        public static final String AUTH_TYPE_KEY = "Basic ";
        public static final String ATTRIBUTE_SEPARATOR = ":";
        public static final String ACTIVE_SESSION_TABLE_NAME = "ORG_WSO2_IS_ANALYTICS_STREAM_ACTIVESESSIONS";
        public static final String TABLE_NAME_TAG = "tableName";
        public static final String QUERY_TAG = "query";
        public static final String TENANT_DOMAIN_TAG = "tenantDomain";
        public static final String AND_TAG = " AND ";
        public static final String TABLE_SEARCH_COUNT_URL = "https://localhost:9444/analytics/search_count";
        public static final String SESSION_LIMIT_TAG = "sessionLimit";

    }

}
