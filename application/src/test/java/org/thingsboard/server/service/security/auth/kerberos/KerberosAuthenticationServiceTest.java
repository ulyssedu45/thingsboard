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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.BadCredentialsException;
import org.thingsboard.server.common.data.User;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.id.UserId;
import org.thingsboard.server.common.data.security.Authority;
import org.thingsboard.server.common.data.security.UserCredentials;
import org.thingsboard.server.common.data.security.model.JwtPair;
import org.thingsboard.server.dao.user.UserService;
import org.thingsboard.server.service.security.model.SecurityUser;
import org.thingsboard.server.service.security.model.UserPrincipal;
import org.thingsboard.server.service.security.model.token.JwtTokenFactory;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class KerberosAuthenticationServiceTest {

    @Mock
    private KerberosProperties kerberosProperties;

    @Mock
    private UserService userService;

    @Mock
    private JwtTokenFactory tokenFactory;

    private KerberosAuthenticationService kerberosAuthenticationService;

    @Before
    public void setUp() {
        kerberosAuthenticationService = new KerberosAuthenticationService(
                kerberosProperties, userService, tokenFactory);
    }

    @Test
    public void testBuildPrincipalWithRealm() {
        when(kerberosProperties.getRealm()).thenReturn("EXAMPLE.COM");
        String principal = kerberosAuthenticationService.buildPrincipal("testuser");
        Assert.assertEquals("testuser@EXAMPLE.COM", principal);
    }

    @Test
    public void testBuildPrincipalAlreadyHasRealm() {
        String principal = kerberosAuthenticationService.buildPrincipal("testuser@MYREALM.COM");
        Assert.assertEquals("testuser@MYREALM.COM", principal);
    }

    @Test
    public void testExtractEmailFromPrincipal() {
        String email = kerberosAuthenticationService.extractEmailFromPrincipal("testuser@EXAMPLE.COM");
        Assert.assertEquals("testuser@example.com", email);
    }

    @Test
    public void testExtractEmailFromPrincipalWithoutDomain() {
        String email = kerberosAuthenticationService.extractEmailFromPrincipal("testuser");
        Assert.assertEquals("testuser", email);
    }

    @Test
    public void testFindOrProvisionUserExistingUser() {
        String email = "testuser@example.com";
        UUID userId = UUID.randomUUID();
        User existingUser = new User();
        existingUser.setId(new UserId(userId));
        existingUser.setEmail(email);
        existingUser.setTenantId(TenantId.SYS_TENANT_ID);
        existingUser.setAuthority(Authority.TENANT_ADMIN);

        UserCredentials credentials = new UserCredentials();
        credentials.setEnabled(true);

        when(userService.findUserByEmail(TenantId.SYS_TENANT_ID, email)).thenReturn(existingUser);
        when(userService.findUserCredentialsByUserId(TenantId.SYS_TENANT_ID, existingUser.getId())).thenReturn(credentials);
        when(kerberosProperties.getDefaultTenantId()).thenReturn(null);

        SecurityUser result = kerberosAuthenticationService.findOrProvisionUser(email);

        Assert.assertNotNull(result);
        Assert.assertEquals(email, result.getEmail());
        Assert.assertTrue(result.isEnabled());
        verify(userService, never()).saveUser(any(), any(), eq(false));
    }

    @Test(expected = BadCredentialsException.class)
    public void testFindOrProvisionUserNotFoundAutoProvisioningDisabled() {
        String email = "newuser@example.com";
        when(userService.findUserByEmail(TenantId.SYS_TENANT_ID, email)).thenReturn(null);
        when(kerberosProperties.getDefaultTenantId()).thenReturn(null);
        when(kerberosProperties.isUserAutoProvisioning()).thenReturn(false);

        kerberosAuthenticationService.findOrProvisionUser(email);
    }

    @Test
    public void testFindOrProvisionUserAutoProvision() {
        String email = "newuser@example.com";
        UUID userId = UUID.randomUUID();
        TenantId tenantId = TenantId.fromUUID(UUID.randomUUID());

        User savedUser = new User();
        savedUser.setId(new UserId(userId));
        savedUser.setEmail(email);
        savedUser.setTenantId(tenantId);
        savedUser.setAuthority(Authority.TENANT_ADMIN);

        UserCredentials credentials = new UserCredentials();
        credentials.setEnabled(true);

        when(userService.findUserByEmail(TenantId.SYS_TENANT_ID, email)).thenReturn(null);
        when(kerberosProperties.getDefaultTenantId()).thenReturn(tenantId.getId().toString());
        when(kerberosProperties.isUserAutoProvisioning()).thenReturn(true);
        when(userService.saveUser(eq(tenantId), any(User.class), eq(false))).thenReturn(savedUser);
        when(userService.findUserCredentialsByUserId(TenantId.SYS_TENANT_ID, savedUser.getId())).thenReturn(credentials);

        SecurityUser result = kerberosAuthenticationService.findOrProvisionUser(email);

        Assert.assertNotNull(result);
        Assert.assertEquals(email, result.getEmail());
        verify(userService).saveUser(eq(tenantId), any(User.class), eq(false));
        verify(userService).setUserCredentialsEnabled(tenantId, savedUser.getId(), true);
    }

    @Test
    public void testAuthenticateWithCredentialsFailsWithInvalidKDC() {
        when(kerberosProperties.getRealm()).thenReturn("INVALID.REALM");
        when(kerberosProperties.getKdc()).thenReturn("nonexistent.kdc.example.com");

        try {
            kerberosAuthenticationService.authenticateWithCredentials("testuser", "password");
            Assert.fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException e) {
            Assert.assertTrue(e.getMessage().contains("Kerberos authentication failed"));
        }
    }

}
