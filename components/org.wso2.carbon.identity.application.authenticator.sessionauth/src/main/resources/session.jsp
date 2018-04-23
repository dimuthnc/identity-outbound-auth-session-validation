<%--
  ~ Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@page import="org.apache.commons.ssl.Base64" %>
<%@page import="org.json.JSONArray" %>
<%@page import="org.json.JSONObject" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Date" %>
<%@ page import="java.text.DateFormat" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="org.joda.time.DateTime" %>
<%@ page import="java.sql.Timestamp" %>
<%@page import="java.util.ArrayList" %>
<%@page import="java.util.Arrays" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.TenantDataManager" %>


<%
    request.getSession().invalidate();
    String queryString = request.getQueryString();
    Map<String, String> idpAuthenticatorMapping = null;
    
    String errorMessage = "Authentication Failed! Please Retry";
    String authenticationFailed = "false";
    
    byte[] sessionDataEncoded = request.getParameter("sessionData").getBytes("UTF-8");
    String sessionData = new String(Base64.decodeBase64(sessionDataEncoded));
    JSONArray sessionDataArray = new JSONArray(sessionData);
    
    
    
    if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
        idpAuthenticatorMapping = (Map<String, String>) request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
    }
    if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
        authenticationFailed = "true";
        if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
            errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);
            if (errorMessage.equalsIgnoreCase("authentication.fail.message")) {
                errorMessage = "Authentication Failed! Please Retry";
            }
        }
    }


%>

<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSO2 Identity Server</title>
    
    <link rel="icon" href="images/favicon.png" type="image/x-icon"/>
    <link href="libs/bootstrap_3.3.5/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/Roboto.css" rel="stylesheet">
    <link href="css/custom-common.css" rel="stylesheet">
    
    
    
    
    
    <script src="https://code.getmdl.io/1.3.0/material.min.js"></script>
    <link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.indigo-pink.min.css">
    <!-- Material Design icon font -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    
    <script src="js/scripts.js"></script>
    <script src="assets/js/jquery-1.7.1.min.js"></script>
    <!--[if lt IE 9]>
    <script src="js/html5shiv.min.js"></script>
    <script src="js/respond.min.js"></script>
    <![endif]-->



</head>

<body onload="getLoginDiv()" onLoad="insertRow()">

<!-- header -->
<header class="header header-default">
    <div class="container-fluid"><br></div>
    <div class="container-fluid">
        <div class="pull-left brand float-remove-xs text-center-xs">
            <a href="#">
                <img src="images/logo-inverse.svg" alt="wso2" title="wso2" class="logo">
                
                <h1><em>Identity Server</em></h1>
            </a>
        </div>
    </div>
</header>

<!-- page content -->
<div class="container-fluid body-wrapper">
    
    <div class="row">
        <div class="col-md-12">
            
            <!-- content -->
            <div class="container col-xs-10 col-sm-6 col-md-6 col-lg-4 col-centered wr-content wr-login col-centered">
                <div>
                    <h2 class="wr-title blue-bg padding-double white boarder-bottom-blue margin-none">
                        Select sessions to terminate &nbsp;&nbsp;</h2>
                </div>
                <div class="boarder-all ">
                    <div class="clearfix"></div>
                    <div class="padding-double login-form">
                        <div id="errorDiv"></div>
                        <%
                            if ("true".equals(authenticationFailed)) {
                        %>
                        <div class="alert alert-danger" id="failed-msg">
                            <%=errorMessage%>
                        </div>
                        <% }
                        %>
                        <form id="pin_form" name="pin_form" action="../../commonauth" method="POST">
                            <div id="loginTable1" class="identity-box">
                                    
                                    
                                    <%
               String loginFailed = request.getParameter("authFailure");
               if (loginFailed != null && "true".equals(loginFailed)) {
           String authFailureMsg = request.getParameter("authFailureMsg");
           if (authFailureMsg != null && "login.fail.message".equals(authFailureMsg)) {
           %>
                                    
                                    
                                    <% } }  %>
                                
                                <div class="row">
                                    <div class="span6">
                                        <!-- Token Pin -->
                                        <div class="control-group">
                                        
                                        </div>
                                        
                                        <input type="hidden" name="sessionDataKey"
                                               value='<%=request.getParameter("sessionDataKey")%>'/>
                                        <input type="hidden" name="sessionTerminationDataInput"
                                               value="sessionTerminationDataInput"/>
                                        <div class='col-md-12 form-group'>
                                            <table name="sessionData" id="sessionData"
                                                   class="mdl-data-table  mdl-shadow--2dp"
                                                   align="center">
                                                <thead>
                                                <tr>
                                                    <th class="mdl-data-table__cell--non-numeric">Terminate</th>
                                                    <th class="mdl-data-table__cell--non-numeric">User Agent</th>
                                                    <th class="mdl-data-table__cell--non-numeric">Session
                                                        starting time</th>
                                                </tr>
                                                    <%
                                                        JSONObject sessionDataItem;
                                                        JSONObject sessionDataItemValues;
                                                        int index = 0;
                                                        while (index < sessionDataArray.length()){
                                                            sessionDataItem = new
                                                            JSONObject(sessionDataArray.get(index).toString());
                                                            sessionDataItemValues = new
                                                            JSONObject(sessionDataItem.getJSONObject("values").toString());
                                                            String userAgent = "Unknown";
                                                            if(!sessionDataItemValues.get("userAgent").toString().equals("null")){
                                                                userAgent =
                                                                String.valueOf(sessionDataItemValues.get("userAgent"));
                                                                userAgent = userAgent.split("/")[0];
                                                            }
                                                            String timestamp =
                                                            String.valueOf(sessionDataItemValues.get("startTimestamp"));
                                                            Timestamp stamp = new Timestamp(Long.parseLong(timestamp));
                                                            Date date = new Date(stamp.getTime());
                                                            String sessionId = sessionDataItem.getString("id");
                                                    %>
                                                
                                                <tr>
                                                    <td><input type="checkbox"
                                                               name=<%=sessionId%> value="valueTest" />&nbsp;
                                                    </td>
                                                    <td class="mdl-data-table__cell--non-numeric"><%= userAgent%></td>
                                                    <td class="mdl-data-table__cell--non-numeric"><%= date %></td>
                                                </tr>
                                                    <%
                                                        index++;
                                                        }
                                                    %>
                                            </table>
                                            </br></br>
                                            <div  align="Center">
                                            <button
                                                    class="mdl-button mdl-js-button mdl-button--raised
                                            mdl-js-ripple-effect"  onclick="$('#loading').show();">
                                                Terminate and Proceed
                                            </button></div>
                                        </div>
                                    </div>
                                </div>
                        </form>
                    
                    </div>
                </div>
                <!-- /content -->
            
            </div>
        </div>
        <!-- /content/body -->
    
    </div>
</div>

<!-- footer -->
<footer class="footer">
    <div class="container-fluid">
        <p>WSO2 Identity Server | &copy;
            <script>document.write(new Date().getFullYear());</script>
            <a href="http://wso2.com/" target="_blank"><i class="icon fw fw-wso2"></i> Inc</a>. All Rights Reserved.
        </p>
    </div>
</footer>
<script src="libs/jquery_1.11.3/jquery-1.11.3.js"></script>
<script src="libs/bootstrap_3.3.5/js/bootstrap.min.js"></script>
</body>
</html>