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
package org.thingsboard.server.service.security.auth.kerberos;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.thingsboard.server.service.security.auth.kerberos.KerberosAuthenticationToken;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.stereotype.Component;
import org.thingsboard.server.common.data.User;
import org.thingsboard.server.common.data.audit.ActionType;
import org.thingsboard.server.common.data.id.EntityId;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.id.UserId;
import org.thingsboard.server.common.data.security.Authority;
import org.thingsboard.server.dao.user.UserService;
import org.thingsboard.server.queue.util.TbCoreComponent;
import org.thingsboard.server.service.security.model.SecurityUser;
import org.thingsboard.server.service.security.model.UserPrincipal;
import org.thingsboard.server.service.security.system.SystemSecurityService;

@Component
@Slf4j
@TbCoreComponent
@ConditionalOnProperty(prefix = "security.kerberos", name = "enabled", havingValue = "true")
public class KerberosAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;
    private final SystemSecurityService systemSecurityService;
    private final SunJaasKerberosClient kerberosClient;

    @Autowired
    public KerberosAuthenticationProvider(final UserService userService,
                                         final SystemSecurityService systemSecurityService,
                                         final SunJaasKerberosClient kerberosClient) {
        this.userService = userService;
        this.systemSecurityService = systemSecurityService;
        this.kerberosClient = kerberosClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        KerberosAuthenticationToken kerberosToken = (KerberosAuthenticationToken) authentication;
        String username = (String) kerberosToken.getPrincipal();
        
        try {
            // Validate Kerberos token
            String validatedUsername = kerberosClient.login(username, (String) kerberosToken.getCredentials());
            
            // Extract username from Kerberos principal (remove realm if present)
            String cleanUsername = extractUsername(validatedUsername);
            
            // Find user in ThingsBoard database
            SecurityUser securityUser = authenticateByUsername(cleanUsername);
            
            // Log successful authentication
            systemSecurityService.logLoginAction(securityUser.getUser(), authentication.getDetails(), 
                                                ActionType.LOGIN, "kerberos", null);
            
            return new KerberosAuthenticationToken(securityUser, null, securityUser.getAuthorities());
            
        } catch (Exception e) {
            log.error("Kerberos authentication failed for user: " + username, e);
            systemSecurityService.logLoginAction(null, authentication.getDetails(), 
                                                ActionType.LOGIN, "kerberos", e);
            throw new BadCredentialsException("Kerberos authentication failed", e);
        }
    }

    private String extractUsername(String kerberosUsername) {
        // Extract username from principal (user@REALM.COM -> user)
        if (kerberosUsername.contains("@")) {
            return kerberosUsername.substring(0, kerberosUsername.indexOf("@"));
        }
        return kerberosUsername;
    }

    private SecurityUser authenticateByUsername(String username) {
        UserPrincipal userPrincipal = new UserPrincipal(UserPrincipal.Type.USER_NAME, username);
        
        User user = userService.findUserByEmail(TenantId.SYS_TENANT_ID, username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        if (!user.isEnabled()) {
            throw new BadCredentialsException("User account is disabled");
        }

        return new SecurityUser(user, true, userPrincipal);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return KerberosAuthenticationToken.class.isAssignableFrom(authentication);
    }
}