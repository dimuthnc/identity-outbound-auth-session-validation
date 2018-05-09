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
package org.wso2.carbon.identity.application.authenticator.sessionauth.model;

import com.google.gson.JsonObject;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;

/**
 * TODO:Class level comment
 */
public class Session {
    String sessionId;
    String timeStamp;
    String userAgent;
    String ipAddress;
    String serviceProvider;

    public Session(String sessionId, String startTimeStamp, String userAgent, String ipAddress,String serviceProvider) {

        this.sessionId = sessionId;
        this.timeStamp = startTimeStamp;
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
        this.serviceProvider = serviceProvider;
    }


    public JSONObject getJSONObject(){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("sessionID",sessionId);
        jsonObject.put("timestamp", timeStamp);
        jsonObject.put("userAgent",userAgent);
        jsonObject.put("ipAddress",ipAddress);
        jsonObject.put("serviceProvider",serviceProvider);
        return jsonObject;
    }
}
