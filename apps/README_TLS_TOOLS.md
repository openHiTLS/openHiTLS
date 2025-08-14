# openHiTLS s_client and s_server Tools

This document describes the TLS/DTLS/TLCP client and server tools implemented for openHiTLS, similar to OpenSSL's s_client and s_server commands.

## Features

### Supported Protocols
- **TLS 1.2**: Standard TLS protocol version 1.2
- **TLS 1.3**: Latest TLS protocol version 1.3
- **DTLS 1.2**: Datagram TLS for UDP transport
- **TLCP**: Chinese national cryptographic protocol

### Key Features
- Certificate-based authentication
- Mutual TLS authentication
- Session resumption
- Cipher suite configuration
- Signature algorithm configuration
- Elliptic curve configuration
- Debug and verbose output modes
- Interactive and batch modes

## Building

To build the tools, ensure openHiTLS is compiled with the apps module:

```bash
# Build openHiTLS with apps
mkdir build && cd build
cmake .. -DHITLS_BUILD_APPS=ON
make
```

## Usage

### s_client (TLS Client)

#### Basic TLS Connection
```bash
# Connect to HTTPS server
./hitls s_client -host www.example.com -port 443

# Connect using specific TLS version
./hitls s_client -host server.com -port 443 -tls1_3

# Connect with custom cipher suites
./hitls s_client -host server.com -port 443 -cipher "ECDHE-RSA-AES256-GCM-SHA384"
```

#### Client Certificate Authentication
```bash
# Use client certificate for authentication
./hitls s_client -host server.com -port 443 \
    -cert client.pem -key client.key -pass password
```

#### Debug Mode
```bash
# Show detailed handshake information
./hitls s_client -host server.com -port 443 -debug -state -showcerts
```

#### DTLS Connection
```bash
# Connect using DTLS
./hitls s_client -dtls1_2 -host 192.168.1.100 -port 4433 -mtu 1400
```

#### TLCP Connection
```bash
# Connect using TLCP with dual certificates
./hitls s_client -tlcp -host gmserver.com -port 443 \
    -tlcp_sign_cert client_sign.pem -tlcp_sign_key client_sign.key \
    -tlcp_enc_cert client_enc.pem -tlcp_enc_key client_enc.key
```

#### Send Test Data
```bash
# Send HTTP request and show response
./hitls s_client -host www.example.com -port 443 -testdata

# Send custom message
./hitls s_client -host server.com -port 443 -msg "Hello Server"

# Exit after handshake
./hitls s_client -host server.com -port 443 -prexit
```

### s_server (TLS Server)

#### Basic TLS Server
```bash
# Start basic TLS server
./hitls s_server -cert server.pem -key server.key -port 4433

# Accept only one connection
./hitls s_server -cert server.pem -key server.key -port 4433 -accept_once
```

#### Mutual Authentication
```bash
# Require client certificate
./hitls s_server -cert server.pem -key server.key -port 4433 \
    -CAfile ca.pem -verify 1

# Force client certificate (fail if not provided)
./hitls s_server -cert server.pem -key server.key -port 4433 \
    -CAfile ca.pem -Verify 1
```

#### Protocol-Specific Servers
```bash
# TLS 1.3 server
./hitls s_server -tls1_3 -cert server.pem -key server.key -port 4433

# DTLS server
./hitls s_server -dtls1_2 -cert server.pem -key server.key -port 4433

# TLCP server with dual certificates
./hitls s_server -tlcp -port 4433 \
    -tlcp_sign_cert server_sign.pem -tlcp_sign_key server_sign.key \
    -tlcp_enc_cert server_enc.pem -tlcp_enc_key server_enc.key
```

#### Server Configuration
```bash
# Use server cipher preference
./hitls s_server -cert server.pem -key server.key -port 4433 -serverpref

# Set custom response message
./hitls s_server -cert server.pem -key server.key -port 4433 \
    -msg "Custom Server Response"

# Run as daemon
./hitls s_server -cert server.pem -key server.key -port 4433 -daemon
```

## Command Line Options

### Common Options

| Option | Description |
|--------|-------------|
| `-help` | Show help message |
| `-quiet` | Quiet mode (minimal output) |
| `-debug` | Debug mode (verbose output) |
| `-state` | Show handshake state |
| `-4` | Force IPv4 |
| `-6` | Force IPv6 |

### Protocol Options

| Option | Description |
|--------|-------------|
| `-tls1_2` | Use TLS 1.2 |
| `-tls1_3` | Use TLS 1.3 |
| `-dtls1_2` | Use DTLS 1.2 |
| `-tlcp` | Use TLCP |
| `-cipher <list>` | Cipher suites |
| `-ciphersuites <list>` | TLS 1.3 cipher suites |
| `-sigalgs <list>` | Signature algorithms |
| `-curves <list>` | Elliptic curves |

### Certificate Options

| Option | Description |
|--------|-------------|
| `-cert <file>` | Certificate file |
| `-key <file>` | Private key file |
| `-pass <password>` | Private key password |
| `-CAfile <file>` | CA certificate file |
| `-CApath <dir>` | CA certificate directory |
| `-verify <depth>` | Verification depth |
| `-showcerts` | Show certificate chain |

### TLCP Options

| Option | Description |
|--------|-------------|
| `-tlcp_sign_cert <file>` | TLCP signature certificate |
| `-tlcp_sign_key <file>` | TLCP signature private key |
| `-tlcp_enc_cert <file>` | TLCP encryption certificate |
| `-tlcp_enc_key <file>` | TLCP encryption private key |

### DTLS Options

| Option | Description |
|--------|-------------|
| `-mtu <size>` | MTU size for DTLS |
| `-cookie` | Enable cookie exchange |

## Examples

### Testing TLS Connection
```bash
# Test connection to OpenSSL s_server
openssl s_server -cert server.pem -key server.key -port 4433 &
./hitls s_client -host localhost -port 4433 -CAfile ca.pem

# Test our server with OpenSSL client
./hitls s_server -cert server.pem -key server.key -port 4433 &
openssl s_client -connect localhost:4433 -CAfile ca.pem
```

### DTLS Example
```bash
# DTLS server
./hitls s_server -dtls1_2 -cert server.pem -key server.key -port 4433 -mtu 1400

# DTLS client
./hitls s_client -dtls1_2 -host localhost -port 4433 -CAfile ca.pem
```

### TLCP Example
```bash
# TLCP server
./hitls s_server -tlcp -port 4433 \
    -tlcp_sign_cert server_sign.pem -tlcp_sign_key server_sign.key \
    -tlcp_enc_cert server_enc.pem -tlcp_enc_key server_enc.key

# TLCP client
./hitls s_client -tlcp -host localhost -port 4433 \
    -tlcp_sign_cert client_sign.pem -tlcp_sign_key client_sign.key \
    -tlcp_enc_cert client_enc.pem -tlcp_enc_key client_enc.key
```

## Certificate Generation

For testing purposes, you can generate certificates using openHiTLS tools:

```bash
# Generate CA certificate
./hitls genpkey -algorithm RSA -out ca.key -pkcs8
./hitls req -new -x509 -key ca.key -out ca.pem -days 365 -subj "/CN=Test CA"

# Generate server certificate
./hitls genpkey -algorithm RSA -out server.key -pkcs8
./hitls req -new -key server.key -out server.csr -subj "/CN=localhost"
./hitls x509 -req -in server.csr -CA ca.pem -CAkey ca.key -out server.pem -days 365

# Generate client certificate
./hitls genpkey -algorithm RSA -out client.key -pkcs8
./hitls req -new -key client.key -out client.csr -subj "/CN=client"
./hitls x509 -req -in client.csr -CA ca.pem -CAkey ca.key -out client.pem -days 365
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Check if server is running and port is correct
2. **Certificate verification failed**: Ensure CA certificate is provided and valid
3. **Handshake failure**: Check protocol version and cipher suite compatibility
4. **Permission denied**: Ensure proper file permissions for certificates and keys

### Debug Tips

- Use `-debug` and `-state` options for detailed handshake information
- Use `-showcerts` to examine certificate chain
- Check server logs for error messages
- Verify certificate validity and chain

## Compatibility

These tools are designed to be compatible with:
- OpenSSL s_client and s_server
- Standard TLS/DTLS implementations
- TLCP implementations compliant with GM/T standards

## Support

For questions or issues related to these tools, please refer to the openHiTLS documentation or community support channels.