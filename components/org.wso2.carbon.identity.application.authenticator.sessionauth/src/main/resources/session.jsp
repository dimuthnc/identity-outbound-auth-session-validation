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
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.TenantDataManager" %>
<%@ page import="java.sql.Timestamp" %>
<%@ page import="java.util.Date" %>
<%@ page import="static java.lang.Math.round" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>

<%
    request.getSession().invalidate();
    
    String errorMessage = "Authentication Failed! Please Retry";
    String authenticationFailed = "false";
    
    byte[] sessionDataEncoded = request.getParameter("sessionData").getBytes("UTF-8");
    String sessionData = new String(Base64.decodeBase64(sessionDataEncoded));
    JSONArray sessionDataArray = new JSONArray(sessionData);
    
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
    
    
    <script src="js/scripts.js"></script>
    <script src="assets/js/jquery-1.7.1.min.js"></script>
    <script>
        function onSelectAllChecked() {
            var checked = document.getElementById("selectAll").checked;
            if(checked){
                var table = document.getElementById("sessionData");
                for (var i = 0, row; row = table.rows[i]; i++) {
                    var checkbox = document.getElementById(i.toString());
                    checkbox.checked = true;
                
                }
            }
            else{
                var table = document.getElementById("sessionData");
                for (var i = 0, row; row = table.rows[i]; i++) {
                    var checkbox = document.getElementById(i.toString());
                    checkbox.checked = false;

                }
            }

        }
    </script>
    <!--[if lt IE 9]>
    <script src="js/html5shiv.min.js"></script>
    <script src="js/respond.min.js"></script>
    <![endif]-->


</head>

<body onload="getLoginDiv()">

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
                        Select sessions to Terminate &nbsp;&nbsp;</h2>
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
                        
                        <%
                            }
                        %>
                        </div>
                        <div class="alert alert-danger" >
                            You have exceeded number of sessions x, Please terminate at-least y in order to proceed..
                        </div>
                        <form id="pin_form" name="pin_form" action="../../commonauth" method="POST">
                            <div id="loginTable1" class="identity-box">
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
                                                   class="table table-bordered"
                                                   align="center">
                                                <thead>
                                                <tr>
                                                    <th><input type="checkbox"
                                                               name="name" id="selectAll"
                                                               onclick="onSelectAllChecked()">
                                                        Terminate
                                                    </th>
                                                    <th>User Agent</th>
                                                    <th>IP/Location</th>
                                                    <th>Session
                                                        starting time
                                                    </th>
                                                    <th>Last Access Time</th>
                                                </tr>
                                                    <%
                                                        JSONObject sessionDataItem;
                                                        JSONObject sessionDataItemValues;
                                                        long currentTime = System.currentTimeMillis();
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
                                                            String sessionId =
                                                            sessionDataItemValues.getString("sessionId");
                                                            String remoteIp =
                                                            String.valueOf(sessionDataItemValues.get("remoteIp"));
                                                            long timeDiff = currentTime -Long.parseLong(timestamp);
                                                            String lastAccessed =null;
                                                            if(timeDiff<60000){
                                                                lastAccessed =String.valueOf(round(timeDiff/1000))+
                                                                " Seconds ago";
                                                            }
                                                            else if(timeDiff<3600000){
                                                                lastAccessed =String.valueOf(round(timeDiff/60000))+
                                                                " Minutes ago";
                                                            }
                                                            else if(timeDiff<86400000){
                                                                lastAccessed =String.valueOf(round(timeDiff/3600000))+
                                                                " Hours ago";
                                                            }
                                                    %>
                                                
                                                <tr>
                                                    <td><input type="checkbox"
                                                               name=<%=sessionId%> value=<%=sessionId%>
                                                               id=<%=index%> />&nbsp;
                                                    </td>
                                                    <td><%= userAgent%>
                                                    </td>
                                                    <td><%=remoteIp%>
                                                    </td>
                                                    <td><%= date %>
                                                    </td>
                                                    <td><%=lastAccessed%></td>
                                                </tr>
                                                    <%
                                                        index++;
                                                        }
                                                    %>
                                            </table>
                                            </br></br>
                                            <div  align="Center">
                                                
                                                <button
                                                        onclick="$('#loading').show();">
                                                    Terminate and Proceed
                                                </button>
                                            </div>
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