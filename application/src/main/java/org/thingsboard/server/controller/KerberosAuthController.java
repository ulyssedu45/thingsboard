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
package org.thingsboard.server.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.thingsboard.server.common.data.exception.ThingsboardException;
import org.thingsboard.server.queue.util.TbCoreComponent;
import org.thingsboard.server.service.security.auth.kerberos.KerberosLoginRequest;
import org.thingsboard.server.service.security.auth.rest.LoginResponse;

@RestController
@TbCoreComponent
@RequestMapping("/api")
@ConditionalOnProperty(prefix = "security.kerberos", name = "enabled", havingValue = "true")
@Tag(name = "Authentication", description = "Authentication operations")
public class KerberosAuthController extends BaseController {

    @Operation(summary = "Kerberos Authentication",
            description = "Authenticate using Kerberos token. This endpoint accepts either a JSON payload with username and Kerberos token, or handles SPNEGO authentication via the Authorization header.")
    @ApiResponse(responseCode = "200", description = "Successful authentication",
            content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = LoginResponse.class)))
    @ApiResponse(responseCode = "401", description = "Authentication failed")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @RequestMapping(value = "/auth/kerberos", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<LoginResponse> kerberosAuth(
            @Parameter(description = "Kerberos login request")
            @RequestBody(required = false) KerberosLoginRequest kerberosLoginRequest) throws ThingsboardException {
        
        // The actual authentication is handled by KerberosLoginProcessingFilter
        // This endpoint mainly serves as documentation for the Kerberos authentication API
        // In practice, the filter intercepts the request before it reaches this method
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new LoginResponse("Authentication failed", null, null));
    }

    @Operation(summary = "Kerberos Authentication Status",
            description = "Check if Kerberos authentication is enabled and available")
    @ApiResponse(responseCode = "200", description = "Kerberos status")
    @RequestMapping(value = "/auth/kerberos/status", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<String> kerberosStatus() {
        return ResponseEntity.ok("{\"enabled\": true, \"message\": \"Kerberos authentication is enabled\"}");
    }
}