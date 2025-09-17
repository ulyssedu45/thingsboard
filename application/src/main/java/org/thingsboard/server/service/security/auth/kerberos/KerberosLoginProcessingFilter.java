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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.thingsboard.common.util.JacksonUtil;
import org.thingsboard.server.service.security.auth.rest.RestAuthenticationDetailsSource;
import org.thingsboard.server.service.security.exception.AuthMethodNotSupportedException;

import java.io.IOException;
import java.util.Base64;
import javax.security.auth.Subject;
import org.ietf.jgss.*;
import java.security.PrivilegedAction;

@Slf4j
public class KerberosLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new RestAuthenticationDetailsSource();
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    public KerberosLoginProcessingFilter(String defaultProcessUrl, 
                                       AuthenticationSuccessHandler successHandler,
                                       AuthenticationFailureHandler failureHandler) {
        super(defaultProcessUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        
        if (!HttpMethod.POST.name().equals(request.getMethod())) {
            if(log.isDebugEnabled()) {
                log.debug("Authentication method not supported. Request method: " + request.getMethod());
            }
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }

        // Check for Negotiate header (SPNEGO authentication)
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Negotiate ")) {
            return handleNegotiateAuthentication(request, authHeader);
        }

        // Handle JSON-based Kerberos login request
        return handleJsonAuthentication(request);
    }

    private Authentication handleJsonAuthentication(HttpServletRequest request) throws IOException {
        KerberosLoginRequest loginRequest;
        try {
            loginRequest = JacksonUtil.fromReader(request.getReader(), KerberosLoginRequest.class);
        } catch (Exception e) {
            log.error("Failed to parse Kerberos login request", e);
            throw new AuthenticationServiceException("Invalid Kerberos login request payload");
        }

        if (!StringUtils.hasText(loginRequest.getUsername()) || !StringUtils.hasText(loginRequest.getKerberosToken())) {
            throw new AuthenticationServiceException("Username or Kerberos token not provided");
        }

        log.debug("Processing JSON-based Kerberos authentication for user: {}", loginRequest.getUsername());

        KerberosAuthenticationToken token = new KerberosAuthenticationToken(
            loginRequest.getUsername(), 
            loginRequest.getKerberosToken()
        );
        token.setDetails(authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(token);
    }

    private Authentication handleNegotiateAuthentication(HttpServletRequest request, String authHeader) {
        try {
            log.debug("Processing SPNEGO authentication with Negotiate header");
            
            // Extract Kerberos token from Negotiate header
            String encodedToken = authHeader.substring("Negotiate ".length()).trim();
            byte[] kerberosToken = Base64.getDecoder().decode(encodedToken);
            
            // Extract username from the SPNEGO token
            String username = extractUsernameFromToken(kerberosToken);
            
            log.debug("Extracted username from SPNEGO token: {}", username);
            
            KerberosAuthenticationToken authToken = new KerberosAuthenticationToken(username, encodedToken);
            authToken.setDetails(authenticationDetailsSource.buildDetails(request));
            return this.getAuthenticationManager().authenticate(authToken);
            
        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 encoding in Negotiate header", e);
            throw new AuthenticationServiceException("Invalid token format in Negotiate header", e);
        } catch (Exception e) {
            log.error("Failed to process Negotiate authentication", e);
            throw new AuthenticationServiceException("Failed to process Negotiate authentication", e);
        }
    }

    private String extractUsernameFromToken(byte[] kerberosToken) {
        try {
            // Create GSS context to process the SPNEGO token
            GSSManager manager = GSSManager.getInstance();
            
            // Set up the service principal (this should match the configured service principal)
            Oid krb5Oid = new Oid("1.2.840.113554.1.2.2"); // Kerberos v5 OID
            Oid spnegoOid = new Oid("1.3.6.1.5.5.2"); // SPNEGO OID
            
            GSSCredential serverCredentials = manager.createCredential(null,
                    GSSCredential.INDEFINITE_LIFETIME,
                    new Oid[] { krb5Oid, spnegoOid },
                    GSSCredential.ACCEPT_ONLY);
            
            GSSContext context = manager.createContext(serverCredentials);
            
            // Process the SPNEGO token
            byte[] responseToken = context.acceptSecContext(kerberosToken, 0, kerberosToken.length);
            
            if (context.isEstablished()) {
                // Extract the client principal name
                GSSName clientName = context.getSrcName();
                String fullPrincipal = clientName.toString();
                
                log.debug("Extracted Kerberos principal: {}", fullPrincipal);
                
                // Extract username from principal (user@REALM.COM -> user)
                if (fullPrincipal.contains("@")) {
                    return fullPrincipal.substring(0, fullPrincipal.indexOf("@"));
                }
                return fullPrincipal;
            } else {
                throw new AuthenticationServiceException("Failed to establish GSS context");
            }
            
        } catch (GSSException e) {
            log.error("Failed to extract username from Kerberos token", e);
            throw new AuthenticationServiceException("Failed to process Kerberos token", e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, 
                                          FilterChain chain, Authentication authResult) 
                                          throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}