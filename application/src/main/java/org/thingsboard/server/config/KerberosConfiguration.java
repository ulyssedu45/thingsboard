/**
 * Copyright © 2016-2025 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.thingsboard.server.queue.util.TbCoreComponent;

@Configuration
@ConditionalOnProperty(prefix = "security.kerberos", name = "enabled", havingValue = "true")
@TbCoreComponent
public class KerberosConfiguration {

    @Value("${security.kerberos.service-principal:HTTP/localhost@REALM.COM}")
    private String servicePrincipal;

    @Value("${security.kerberos.keytab-location:/etc/krb5.keytab}")
    private String keytabLocation;

    @Value("${security.kerberos.kdc:localhost}")
    private String kdc;

    @Value("${security.kerberos.realm:REALM.COM}")
    private String realm;

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(servicePrincipal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
        ticketValidator.setDebug(true);
        return ticketValidator;
    }

    @Bean
    public SunJaasKerberosClient sunJaasKerberosClient() {
        SunJaasKerberosClient client = new SunJaasKerberosClient();
        client.setDebug(true);
        return client;
    }
}