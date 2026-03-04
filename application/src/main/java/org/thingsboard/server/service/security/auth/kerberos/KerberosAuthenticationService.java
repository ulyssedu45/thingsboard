/**
 * Copyright © 2016-2026 The Thingsboard Authors
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
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.thingsboard.server.common.data.User;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.security.Authority;
import org.thingsboard.server.common.data.security.UserCredentials;
import org.thingsboard.server.common.data.security.model.JwtPair;
import org.thingsboard.server.dao.user.UserService;
import org.thingsboard.server.service.security.model.SecurityUser;
import org.thingsboard.server.service.security.model.UserPrincipal;
import org.thingsboard.server.service.security.model.token.JwtTokenFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
@ConditionalOnProperty(prefix = "security.kerberos", value = "enabled", havingValue = "true")
public class KerberosAuthenticationService {

    private final KerberosProperties kerberosProperties;
    private final UserService userService;
    private final JwtTokenFactory tokenFactory;

    private static final Oid SPNEGO_OID;

    static {
        try {
            SPNEGO_OID = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException e) {
            throw new IllegalStateException("Failed to create SPNEGO OID", e);
        }
    }

    public KerberosAuthenticationService(KerberosProperties kerberosProperties,
                                         UserService userService,
                                         JwtTokenFactory tokenFactory) {
        this.kerberosProperties = kerberosProperties;
        this.userService = userService;
        this.tokenFactory = tokenFactory;
        initKerberosSystemProperties();
    }

    /**
     * Set Kerberos system properties once at startup to avoid thread-safety issues.
     */
    private void initKerberosSystemProperties() {
        if (kerberosProperties.getKdc() != null && !kerberosProperties.getKdc().isBlank()) {
            System.setProperty("java.security.krb5.kdc", kerberosProperties.getKdc());
        }
        if (kerberosProperties.getRealm() != null && !kerberosProperties.getRealm().isBlank()) {
            System.setProperty("java.security.krb5.realm", kerberosProperties.getRealm());
        }
    }

    /**
     * Authenticate a user with explicit Kerberos credentials (username + password).
     * Validates credentials against the KDC and returns a JWT token pair.
     */
    public JwtPair authenticateWithCredentials(String username, String password) {
        String principal = buildPrincipal(username);

        try {
            LoginContext loginContext = createLoginContext(principal, password);
            loginContext.login();
            loginContext.logout();
        } catch (LoginException e) {
            log.warn("Kerberos authentication failed for user [{}]: {}", username, e.getMessage());
            throw new BadCredentialsException("Kerberos authentication failed: " + e.getMessage(), e);
        }

        String email = extractEmailFromPrincipal(principal);
        SecurityUser securityUser = findOrProvisionUser(email);
        return tokenFactory.createTokenPair(securityUser);
    }

    /**
     * Authenticate using a SPNEGO token from the Authorization: Negotiate header.
     * Returns the authenticated principal name and JWT token pair.
     */
    public JwtPair authenticateWithSpnegoToken(byte[] spnegoToken) {
        String principalName = validateSpnegoToken(spnegoToken);
        String email = extractEmailFromPrincipal(principalName);
        SecurityUser securityUser = findOrProvisionUser(email);
        return tokenFactory.createTokenPair(securityUser);
    }

    /**
     * Validate a SPNEGO token using the service keytab.
     * Returns the client principal name.
     */
    String validateSpnegoToken(byte[] spnegoToken) {
        try {
            Subject serviceSubject = loginAsService();

            return Subject.doAs(serviceSubject, (PrivilegedAction<String>) () -> {
                try {
                    GSSManager manager = GSSManager.getInstance();
                    GSSCredential serverCreds = manager.createCredential(
                            null, GSSCredential.DEFAULT_LIFETIME, SPNEGO_OID, GSSCredential.ACCEPT_ONLY);
                    GSSContext context = manager.createContext(serverCreds);
                    try {
                        context.acceptSecContext(spnegoToken, 0, spnegoToken.length);
                        if (context.isEstablished()) {
                            GSSName clientName = context.getSrcName();
                            return clientName.toString();
                        } else {
                            throw new BadCredentialsException("SPNEGO context not established");
                        }
                    } finally {
                        context.dispose();
                    }
                } catch (GSSException e) {
                    throw new BadCredentialsException("SPNEGO token validation failed: " + e.getMessage(), e);
                }
            });
        } catch (LoginException e) {
            throw new BadCredentialsException("Service login failed for SPNEGO validation: " + e.getMessage(), e);
        }
    }

    SecurityUser findOrProvisionUser(String email) {
        TenantId tenantId = parseTenantId(kerberosProperties.getDefaultTenantId());
        User user = userService.findUserByEmail(TenantId.SYS_TENANT_ID, email);

        if (user == null) {
            if (!kerberosProperties.isUserAutoProvisioning()) {
                throw new BadCredentialsException("User not found and auto-provisioning is disabled: " + email);
            }
            user = createUser(email, tenantId);
            log.info("Auto-provisioned Kerberos user: {}", email);
        }

        UserCredentials userCredentials = userService.findUserCredentialsByUserId(TenantId.SYS_TENANT_ID, user.getId());
        boolean enabled = userCredentials != null && userCredentials.isEnabled();

        UserPrincipal principal = new UserPrincipal(UserPrincipal.Type.USER_NAME, user.getEmail());
        return new SecurityUser(user, enabled, principal);
    }

    private User createUser(String email, TenantId tenantId) {
        User user = new User();
        user.setEmail(email);
        user.setTenantId(tenantId);
        user.setAuthority(Authority.TENANT_ADMIN);
        user.setFirstName(extractFirstNameFromEmail(email));
        user.setLastName("");
        User savedUser = userService.saveUser(tenantId, user, false);
        userService.setUserCredentialsEnabled(tenantId, savedUser.getId(), true);
        return savedUser;
    }

    String buildPrincipal(String username) {
        if (username.contains("@")) {
            return username;
        }
        return username + "@" + kerberosProperties.getRealm();
    }

    String extractEmailFromPrincipal(String principal) {
        if (principal.contains("@")) {
            String[] parts = principal.split("@");
            String user = parts[0];
            String realmOrDomain = parts[1];
            return user + "@" + realmOrDomain.toLowerCase();
        }
        return principal;
    }

    private String extractFirstNameFromEmail(String email) {
        int atIndex = email.indexOf('@');
        return atIndex > 0 ? email.substring(0, atIndex) : email;
    }

    private TenantId parseTenantId(String tenantIdStr) {
        if (tenantIdStr == null || tenantIdStr.isBlank()) {
            return TenantId.SYS_TENANT_ID;
        }
        try {
            return TenantId.fromUUID(UUID.fromString(tenantIdStr));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid defaultTenantId [{}], using SYS_TENANT_ID", tenantIdStr);
            return TenantId.SYS_TENANT_ID;
        }
    }

    LoginContext createLoginContext(String principal, String password) throws LoginException {
        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useKeyTab", "false");
                options.put("storeKey", "true");
                options.put("isInitiator", "true");
                options.put("refreshKrb5Config", "true");
                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options
                        )
                };
            }
        };

        CallbackHandler callbackHandler = callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback nameCallback) {
                    nameCallback.setName(principal);
                } else if (callback instanceof PasswordCallback passwordCallback) {
                    passwordCallback.setPassword(password.toCharArray());
                }
            }
        };

        return new LoginContext("KerberosLogin", null, callbackHandler, config);
    }

    private Subject loginAsService() throws LoginException {
        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useKeyTab", "true");
                options.put("keyTab", kerberosProperties.getKeytabPath());
                options.put("principal", kerberosProperties.getServicePrincipal());
                options.put("storeKey", "true");
                options.put("isInitiator", "false");
                options.put("refreshKrb5Config", "true");
                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options
                        )
                };
            }
        };

        LoginContext loginContext = new LoginContext("ServiceLogin", null, callbacks -> {}, config);
        loginContext.login();
        return loginContext.getSubject();
    }

}
