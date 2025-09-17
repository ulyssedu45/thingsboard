# Kerberos Authentication for ThingsBoard

This documentation describes how to configure and use Kerberos authentication in ThingsBoard.

## Overview

Kerberos authentication allows users to authenticate with ThingsBoard using Kerberos tickets, providing single sign-on (SSO) capabilities in enterprise environments.

## Configuration

### 1. Enable Kerberos Authentication

Add the following configuration to your `thingsboard.yml` file:

```yaml
security:
  kerberos:
    # Enable Kerberos authentication
    enabled: true
    # Kerberos service principal name
    service-principal: "HTTP/thingsboard.company.com@COMPANY.COM"
    # Path to the keytab file containing the service principal credentials
    keytab-location: "/etc/thingsboard/krb5.keytab"
    # Kerberos realm
    realm: "COMPANY.COM"
    # KDC (Key Distribution Center) hostname
    kdc: "kdc.company.com"
```

### 2. Environment Variables

You can also configure Kerberos using environment variables:

```bash
export SECURITY_KERBEROS_ENABLED=true
export SECURITY_KERBEROS_SERVICE_PRINCIPAL="HTTP/thingsboard.company.com@COMPANY.COM"
export SECURITY_KERBEROS_KEYTAB_LOCATION="/etc/thingsboard/krb5.keytab"
export SECURITY_KERBEROS_REALM="COMPANY.COM"
export SECURITY_KERBEROS_KDC="kdc.company.com"
export SECURITY_KERBEROS_DEBUG="false"
```

## Prerequisites

### 1. Service Principal and Keytab

Create a service principal for ThingsBoard in your Kerberos KDC:

```bash
# On the KDC server
kadmin.local
addprinc -randkey HTTP/thingsboard.company.com@COMPANY.COM
ktadd -k /tmp/thingsboard.keytab HTTP/thingsboard.company.com@COMPANY.COM
```

Copy the keytab file to your ThingsBoard server and ensure proper permissions:

```bash
sudo cp /tmp/thingsboard.keytab /etc/thingsboard/krb5.keytab
sudo chown thingsboard:thingsboard /etc/thingsboard/krb5.keytab
sudo chmod 400 /etc/thingsboard/krb5.keytab
```

### 2. Kerberos Configuration

Ensure your ThingsBoard server has a proper `/etc/krb5.conf` file:

```ini
[libdefaults]
    default_realm = COMPANY.COM
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    COMPANY.COM = {
        kdc = kdc.company.com:88
        admin_server = kdc.company.com:749
    }

[domain_realm]
    .company.com = COMPANY.COM
    company.com = COMPANY.COM
```

## Authentication Methods

### 1. SPNEGO Authentication (Browser-based)

For web browsers that support SPNEGO (Single Sign-On):

1. Configure your browser to enable SPNEGO for the ThingsBoard domain
2. Access ThingsBoard login page
3. Click the "Login with Kerberos SSO" button - authentication will happen automatically

**Browser Configuration:**

For Chrome/Edge:
```bash
# Add ThingsBoard domain to trusted sites for automatic authentication
chrome --auth-server-whitelist="thingsboard.company.com"
```

For Firefox:
1. Go to `about:config`
2. Set `network.negotiate-auth.trusted-uris` to `thingsboard.company.com`
3. Set `network.negotiate-auth.delegation-uris` to `thingsboard.company.com`

### 2. REST API Authentication

For programmatic access, use the Kerberos authentication endpoint:

#### Endpoint
```
POST /api/auth/kerberos
```

#### Request Body
```json
{
  "username": "user@COMPANY.COM",
  "kerberosToken": "YIIEfgYJKoZIhvcSAQICAQBu..."
}
```

#### Response
```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "eyJhbGciOiJIUzUxMiJ9..."
}
```

### 3. Negotiate Header Authentication

You can also use the standard HTTP Negotiate authentication:

```http
POST /api/auth/kerberos
Authorization: Negotiate YIIEfgYJKoZIhvcSAQICAQBu...
```

## User Interface

ThingsBoard provides an integrated Kerberos authentication interface on the login page:

1. **SPNEGO/SSO Button**: Click "Login with Kerberos SSO" for automatic authentication using your domain credentials
2. **Manual Authentication**: Expand the "Manual Kerberos Authentication" section to enter credentials manually
3. **Status Check**: The interface automatically detects if Kerberos is enabled on the server

The Kerberos login options appear below the standard username/password form when Kerberos authentication is enabled.

## User Mapping

Users authenticated via Kerberos must exist in the ThingsBoard database. The system will:

1. Extract the username from the Kerberos principal (user@REALM.COM → user)
2. Look up the user in the ThingsBoard database using the extracted username
3. Create a security context for the authenticated user

To create users that can authenticate via Kerberos:

1. Create users in ThingsBoard with usernames matching your Kerberos principals
2. Users do not need passwords set when using Kerberos authentication
3. Ensure users are enabled and have appropriate roles assigned

## Testing

### Check Kerberos Status

```bash
curl -X GET http://localhost:8080/api/auth/kerberos/status
```

### Test Authentication with curl

```bash
# First, obtain a Kerberos ticket
kinit user@COMPANY.COM

# Then use negotiate authentication
curl -X POST \
  --negotiate -u : \
  http://localhost:8080/api/auth/kerberos
```

## Troubleshooting

### Common Issues

1. **Clock Skew**: Ensure system clocks are synchronized between client, server, and KDC
2. **DNS Resolution**: Verify that hostnames can be resolved properly
3. **Keytab Permissions**: Check that ThingsBoard can read the keytab file
4. **User Not Found**: Ensure users exist in ThingsBoard database with matching usernames

### Enable Debug Logging

Add the following to your logging configuration:

```yaml
logging:
  level:
    org.thingsboard.server.service.security.auth.kerberos: DEBUG
    org.springframework.security.kerberos: DEBUG
```

### Verify Keytab

```bash
klist -k /etc/thingsboard/krb5.keytab
```

## Security Considerations

1. **Keytab Security**: Protect the keytab file with appropriate permissions (400)
2. **Network Security**: Use HTTPS in production to protect tokens
3. **Time Synchronization**: Maintain accurate time synchronization
4. **Principal Validation**: Ensure proper principal name validation

## Migration from Password Authentication

When migrating existing users to Kerberos authentication:

1. Keep password authentication enabled during transition
2. Test Kerberos authentication with a subset of users
3. Gradually migrate users and disable password authentication when ready