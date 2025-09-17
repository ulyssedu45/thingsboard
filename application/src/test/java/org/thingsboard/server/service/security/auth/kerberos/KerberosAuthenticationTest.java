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

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic unit tests for Kerberos authentication components
 */
@SpringBootTest
@TestPropertySource(properties = {
    "security.kerberos.enabled=false" // Disable Kerberos for most tests to avoid setup complexity
})
public class KerberosAuthenticationTest {

    @Test
    public void testKerberosAuthenticationTokenCreation() {
        // Test creating a Kerberos authentication token
        String username = "testuser@REALM.COM";
        String token = "test-kerberos-token";
        
        KerberosAuthenticationToken authToken = new KerberosAuthenticationToken(username, token);
        
        assertNotNull(authToken);
        assertEquals(username, authToken.getPrincipal());
        assertEquals(token, authToken.getCredentials());
        assertFalse(authToken.isAuthenticated());
    }

    @Test
    public void testKerberosLoginRequestCreation() {
        // Test creating a Kerberos login request
        String username = "testuser@REALM.COM";
        String kerberosToken = "YIIEfgYJKoZIhvcSAQICAQBu...";
        
        KerberosLoginRequest loginRequest = new KerberosLoginRequest(username, kerberosToken);
        
        assertNotNull(loginRequest);
        assertEquals(username, loginRequest.getUsername());
        assertEquals(kerberosToken, loginRequest.getKerberosToken());
    }

    @Test
    public void testKerberosAuthenticationTokenWithAuthorities() {
        // Test creating an authenticated Kerberos token
        String username = "testuser@REALM.COM";
        String token = "test-kerberos-token";
        
        KerberosAuthenticationToken authToken = new KerberosAuthenticationToken(username, token, null);
        
        assertNotNull(authToken);
        assertEquals(username, authToken.getPrincipal());
        assertEquals(token, authToken.getCredentials());
        assertTrue(authToken.isAuthenticated());
    }

    @Test
    public void testKerberosAuthenticationTokenEraseCredentials() {
        // Test erasing credentials from token
        String username = "testuser@REALM.COM";
        String token = "test-kerberos-token";
        
        KerberosAuthenticationToken authToken = new KerberosAuthenticationToken(username, token);
        authToken.eraseCredentials();
        
        assertEquals(username, authToken.getPrincipal());
        assertNull(authToken.getCredentials());
    }
}