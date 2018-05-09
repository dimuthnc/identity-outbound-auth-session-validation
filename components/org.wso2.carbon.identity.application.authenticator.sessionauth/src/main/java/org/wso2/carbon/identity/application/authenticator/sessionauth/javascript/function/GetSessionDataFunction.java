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

import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.sessionauth.exception.SessionValidationException;
import org.wso2.carbon.identity.application.authenticator.sessionauth.model.Session;

import java.io.IOException;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.sessionauth.util.SessionValidationUtil.getSessionDetails;

/**
 * TODO:Class level comment
 */
public class GetSessionDataFunction implements GetDataFunction {

    @Override
    public JSONObject getData(JsAuthenticationContext context, Map<String, String> map) {

        JSONObject jsonObject = new JSONObject();
        JSONArray jsonArray = new JSONArray();
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            return jsonObject;
        }

        try {
            JSONArray sessionMetaData = getSessionDetails(authenticatedUser);
            for (int sessionIndex = 0; sessionIndex < sessionMetaData.length(); sessionIndex++) {
                JSONObject sessionJsonObject = sessionMetaData.getJSONObject(sessionIndex);
                JSONObject sessionValues = sessionJsonObject.getJSONObject("values");
                String sessionId = sessionValues.getString("sessionId");
                String timestamp = sessionJsonObject.get("timestamp").toString();
                String userAgent = sessionValues.get("userAgent").toString();
                String ipAddress = sessionValues.getString("remoteIp");
                String serviceProvider = sessionValues.getString("serviceProvider");
                Session session = new Session(sessionId, timestamp, userAgent, ipAddress, serviceProvider);
                jsonArray.put(session.getJSONObject());
            }
            jsonObject.put("sessions", jsonArray);
        } catch (IOException e) {
            //TODO
        } catch (SessionValidationException e) {
            //TODO
        }
        return jsonObject;
    }
}
