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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema
public class KerberosLoginRequest {

    private String username;
    private String kerberosToken;

    @JsonCreator
    public KerberosLoginRequest(@JsonProperty("username") String username, 
                               @JsonProperty("kerberosToken") String kerberosToken) {
        this.username = username;
        this.kerberosToken = kerberosToken;
    }

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, 
            description = "Kerberos principal username", 
            example = "user@REALM.COM")
    public String getUsername() {
        return username;
    }

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, 
            description = "Base64-encoded Kerberos token", 
            example = "YIIEfgYJKoZIhvcSAQICAQBu...")
    public String getKerberosToken() {
        return kerberosToken;
    }
}