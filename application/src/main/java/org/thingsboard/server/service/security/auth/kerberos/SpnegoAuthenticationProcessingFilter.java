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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thingsboard.common.util.JacksonUtil;
import org.thingsboard.server.common.data.security.model.JwtPair;

import java.io.IOException;
import java.util.Base64;

@Slf4j
public class SpnegoAuthenticationProcessingFilter extends OncePerRequestFilter {

    private static final String NEGOTIATE_PREFIX = "Negotiate ";

    private final KerberosAuthenticationService kerberosAuthenticationService;

    public SpnegoAuthenticationProcessingFilter(KerberosAuthenticationService kerberosAuthenticationService) {
        this.kerberosAuthenticationService = kerberosAuthenticationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(NEGOTIATE_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String spnegoTokenBase64 = authHeader.substring(NEGOTIATE_PREFIX.length()).trim();
            byte[] spnegoToken = Base64.getDecoder().decode(spnegoTokenBase64);

            JwtPair tokenPair = kerberosAuthenticationService.authenticateWithSpnegoToken(spnegoToken);

            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            JacksonUtil.writeValue(response.getWriter(), tokenPair);
        } catch (BadCredentialsException e) {
            log.warn("SPNEGO authentication failed: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.addHeader("WWW-Authenticate", "Negotiate");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"message\":\"SPNEGO authentication failed\",\"errorCode\":10}");
        } catch (Exception e) {
            log.error("Unexpected error during SPNEGO authentication", e);
            SecurityContextHolder.clearContext();
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"message\":\"Internal server error during SPNEGO authentication\",\"errorCode\":2}");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return !"/api/auth/spnego".equals(path);
    }

}
