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
package org.wso2.carbon.identity.application.authenticator.sessionauth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.sessionauth.SessionCountAuthenticator;

@Component(
        name = "identity.application.authenticator.sessionauth.component",
        immediate = true
)
public class SessionAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(SessionAuthenticatorServiceComponent.class);
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            SessionCountAuthenticator sessionCountAuthenticator = new SessionCountAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    sessionCountAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.info("SessionCountAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("SAMLSSO Authenticator bundle activation Failed", e);
        }
    }
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("SessionCountAuthenticator bundle is deactivated");
        }
    }

}
