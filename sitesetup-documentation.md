# Nginx and Let's Encrypt Automation Script

## Overview

This bash script automates the creation and management of Nginx virtual hosts for FastAPI applications, including obtaining and configuring SSL certificates via Let's Encrypt. The script streamlines the process of setting up secure, production-ready web services by handling Nginx configuration, SSL certificate issuance, and security best practices.

## Features

- **Automated Site Creation**: Generate Nginx configurations for subdomains
- **SSL Certificate Management**: Obtain and configure Let's Encrypt certificates
- **Security Headers**: Implement modern security headers (HSTS, CSP, XSS Protection)
- **Rate Limiting**: Configure rate limiting to protect against abuse
- **WebSocket Support**: Optional WebSocket protocol support
- **DNS Verification**: Check DNS records before attempting certificate issuance
- **Test Mode**: Preview configurations without applying changes
- **Site Removal**: Clean removal of sites and certificates
- **Multiple Authentication Methods**: Fallback to standalone mode if webroot fails

## Prerequisites

- Nginx web server
- Certbot installed
- Sudo privileges
- Properly configured DNS for your domain
- Open ports 80 and 443 on your firewall

## Usage

### Command Structure

```bash
./setup-site.sh [command] [options]
```

### Commands

- `create`: Create a new Nginx site configuration
- `remove`: Remove an existing site configuration
- `list`: List all configured sites

### Options for `create`

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `-s` | `--subdomain` | Subdomain name | Yes |
| `-i` | `--ip` | IP address of the service | Yes |
| `-p` | `--port` | Port of the service | Yes |
| `-r` | `--rate-limit` | Rate limit (default: 15r/s) | No |
| `-w` | `--websocket` | Enable WebSocket support | No |
| `-n` | `--no-ssl` | Don't configure SSL (testing only) | No |
| `-t` | `--test-only` | Test configuration without applying | No |

### Options for `remove`

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `-s` | `--subdomain` | Subdomain name to remove | Yes |

### Examples

Create a new site configuration:
```bash
./setup-site.sh create -s api -i 192.168.1.144 -p 8000
```

Create a site with WebSocket support:
```bash
./setup-site.sh create -s socket -i 192.168.1.144 -p 8001 -w
```

Test a configuration without applying changes:
```bash
./setup-site.sh create -s test -i 192.168.1.144 -p 8002 -t
```

Remove an existing site:
```bash
./setup-site.sh remove -s api
```

List all configured sites:
```bash
./setup-site.sh list
```

## Process Flow

### Site Creation

1. Validate input parameters (subdomain, IP, port)
2. Check if the DNS record exists for the subdomain
3. Create temporary Nginx configuration for Let's Encrypt verification
4. Reload Nginx to apply the temporary configuration
5. Obtain SSL certificate using the webroot method
6. If webroot method fails, attempt standalone method
7. Create final Nginx configuration with SSL, security headers, and proxy settings
8. Reload Nginx to apply the final configuration

### Site Removal

1. Validate input parameters (subdomain)
2. Remove Nginx configuration file
3. Reload Nginx
4. Optionally remove the Let's Encrypt certificate

## Configuration Generated

The script generates two types of Nginx configurations:

### Temporary Configuration (for certificate validation)

```nginx
server {
    listen 80;
    server_name subdomain.example.com;
    
    # For Let's Encrypt webroot verification
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }
    
    location / {
        return 200 "Certbot validation server";
    }
}
```

### Final Configuration

```nginx
server {
    listen 80;
    server_name subdomain.example.com;
    
    # For Let's Encrypt webroot verification
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name subdomain.example.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/subdomain.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/subdomain.example.com/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # Modern configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    # Additional security headers
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self';";
    
    # Rate limiting
    limit_req zone=limit_per_ip burst=30 nodelay;
    
    location / {
        proxy_pass http://192.168.1.144:8000;
        proxy_buffering off;
        proxy_http_version 1.1;
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

## Security Features

The script implements several security best practices:

1. **HTTPS Redirection**: All HTTP traffic is redirected to HTTPS
2. **Modern SSL Configuration**: Using modern protocols and ciphers
3. **HTTP Strict Transport Security (HSTS)**: Enforces secure connections
4. **Content Security Policy (CSP)**: Prevents XSS attacks
5. **X-Frame-Options**: Prevents clickjacking
6. **X-Content-Type-Options**: Prevents MIME type sniffing
7. **X-XSS-Protection**: Browser built-in XSS protection
8. **Rate Limiting**: Protects against brute force and DoS attacks

## Troubleshooting

If you encounter issues during certificate issuance:

1. **DNS Problems**: Ensure your subdomain has a correct A record pointing to your server's public IP
2. **Firewall Issues**: Make sure ports 80 and 443 are open
3. **Permission Problems**: The script needs to be run with sudo privileges
4. **Certificate Already Exists**: Use the `remove` command to clean up before recreating
5. **Webroot Path**: Ensure the webroot path (/var/www/html by default) exists and is writable

## Customization

The script can be customized by modifying these variables:

- `NGINX_SITES_DIR`: Location of Nginx site configurations
- `LETSENCRYPT_DIR`: Location of Let's Encrypt certificates
- `WEBROOT_PATH`: Path for webroot authentication
- `PARENT_DOMAIN`: Your parent domain name
- `EMAIL`: Email for Let's Encrypt notifications
- `RATE_LIMIT`: Default rate limit setting
