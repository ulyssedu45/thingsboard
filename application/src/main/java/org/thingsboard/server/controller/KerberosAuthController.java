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
package org.thingsboard.server.controller;

import io.swagger.v3.oas.annotations.Parameter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.thingsboard.server.common.data.StringUtils;
import org.thingsboard.server.common.data.security.model.JwtPair;
import org.thingsboard.server.config.annotations.ApiOperation;
import org.thingsboard.server.queue.util.TbCoreComponent;
import org.thingsboard.server.service.security.auth.kerberos.KerberosAuthenticationService;
import org.thingsboard.server.service.security.auth.kerberos.KerberosLoginRequest;

@RestController
@TbCoreComponent
@RequestMapping("/api/noauth/kerberos")
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "security.kerberos", value = "enabled", havingValue = "true")
public class KerberosAuthController {

    private final KerberosAuthenticationService kerberosAuthenticationService;

    @ApiOperation(value = "Kerberos Login (kerberosLogin)",
            notes = "Authenticate a user with Kerberos credentials (username + password). "
                    + "Validates the credentials against the configured KDC/Active Directory. "
                    + "Returns a JWT token pair (access + refresh) on success. "
                    + "If the user does not exist in ThingsBoard and auto-provisioning is enabled, "
                    + "the user will be created automatically.")
    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public JwtPair kerberosLogin(
            @Parameter(description = "Kerberos login request with username and password")
            @RequestBody KerberosLoginRequest request) {
        if (StringUtils.isBlank(request.getUsername()) || StringUtils.isEmpty(request.getPassword())) {
            throw new BadCredentialsException("Username or Password not provided");
        }
        return kerberosAuthenticationService.authenticateWithCredentials(request.getUsername(), request.getPassword());
    }

}
