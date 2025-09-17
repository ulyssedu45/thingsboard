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

        // Check for Negotiate header
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Negotiate ")) {
            return handleNegotiateAuthentication(request, authHeader);
        }

        // Handle JSON-based Kerberos login request
        KerberosLoginRequest loginRequest;
        try {
            loginRequest = JacksonUtil.fromReader(request.getReader(), KerberosLoginRequest.class);
        } catch (Exception e) {
            throw new AuthenticationServiceException("Invalid Kerberos login request payload");
        }

        if (!StringUtils.hasText(loginRequest.getUsername()) || !StringUtils.hasText(loginRequest.getKerberosToken())) {
            throw new AuthenticationServiceException("Username or Kerberos token not provided");
        }

        KerberosAuthenticationToken token = new KerberosAuthenticationToken(
            loginRequest.getUsername(), 
            loginRequest.getKerberosToken()
        );
        token.setDetails(authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(token);
    }

    private Authentication handleNegotiateAuthentication(HttpServletRequest request, String authHeader) {
        try {
            // Extract Kerberos token from Negotiate header
            String token = authHeader.substring("Negotiate ".length());
            byte[] kerberosToken = Base64.getDecoder().decode(token);
            
            // For SPNEGO authentication, we would typically extract the username from the token
            // For simplicity, we'll use a placeholder approach here
            String username = extractUsernameFromToken(kerberosToken);
            
            KerberosAuthenticationToken authToken = new KerberosAuthenticationToken(username, token);
            authToken.setDetails(authenticationDetailsSource.buildDetails(request));
            return this.getAuthenticationManager().authenticate(authToken);
            
        } catch (Exception e) {
            throw new AuthenticationServiceException("Failed to process Negotiate authentication", e);
        }
    }

    private String extractUsernameFromToken(byte[] kerberosToken) {
        // In a real implementation, this would parse the Kerberos token to extract the principal
        // For now, we'll return a placeholder that can be configured
        return "kerberos-user";
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