#!/bin/bash

# Nginx and Let's Encrypt Automation Script - Revised with correct domain
# Usage: ./setup-site.sh [command] [options]
#   Commands:
#     create - Create a new site configuration
#     remove - Remove an existing site configuration
#     list   - List all configured sites
#
# Example: ./setup-site.sh create -s api -i 192.168.1.144 -p 8000

set -e

# Configuration variables
NGINX_SITES_DIR="/etc/nginx/sites-enabled"
LETSENCRYPT_DIR="/etc/letsencrypt/live"
WEBROOT_PATH="/var/www/html"  # Standard webroot path
PARENT_DOMAIN="ill13.com"     # Fixed domain name with two L's
EMAIL="admin@${PARENT_DOMAIN}"  # Replace with your email
RATE_LIMIT="15r/s"  # Default rate limit
RATE_LIMIT_ZONE="limit_per_ip"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to display usage information
show_usage() {
    echo -e "Usage: $0 [command] [options]"
    echo -e "Commands:"
    echo -e "  create  - Create a new site configuration"
    echo -e "  remove  - Remove an existing site configuration"
    echo -e "  list    - List all configured sites"
    echo -e ""
    echo -e "Options for create:"
    echo -e "  -s, --subdomain SUBDOMAIN    Subdomain name (required)"
    echo -e "  -i, --ip IP                  IP address of the service (required)"
    echo -e "  -p, --port PORT              Port of the service (required)"
    echo -e "  -r, --rate-limit RATE        Rate limit (default: ${RATE_LIMIT})"
    echo -e "  -w, --websocket              Enable WebSocket support"
    echo -e "  -n, --no-ssl                 Don't configure SSL (testing only)"
    echo -e "  -t, --test-only              Test configuration without applying"
    echo -e ""
    echo -e "Options for remove:"
    echo -e "  -s, --subdomain SUBDOMAIN    Subdomain name to remove (required)"
    echo -e ""
    echo -e "Example: $0 create -s api -i 192.168.1.144 -p 8000"
}

# Function to validate inputs
validate_inputs() {
    if [[ -z "$SUBDOMAIN" ]]; then
        echo -e "${RED}Error: Subdomain is required${NC}"
        show_usage
        exit 1
    fi
    
    if [[ "$COMMAND" == "create" ]]; then
        if [[ -z "$IP_ADDRESS" || -z "$PORT" ]]; then
            echo -e "${RED}Error: IP address and port are required for create command${NC}"
            show_usage
            exit 1
        fi
        
        # Validate IP address format
        if ! [[ $IP_ADDRESS =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Error: Invalid IP address format${NC}"
            exit 1
        fi
        
        # Validate port number
        if ! [[ $PORT =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
            echo -e "${RED}Error: Invalid port number${NC}"
            exit 1
        fi
    fi
}

# Function to check DNS record
check_dns_record() {
    local FULL_DOMAIN="$1"
    echo -e "${YELLOW}Checking DNS record for ${FULL_DOMAIN}...${NC}"
    
    if host "$FULL_DOMAIN" > /dev/null 2>&1; then
        echo -e "${GREEN}DNS record found for ${FULL_DOMAIN}${NC}"
        return 0
    else
        echo -e "${RED}No DNS record found for ${FULL_DOMAIN}${NC}"
        echo -e "${YELLOW}Please make sure you have added an A record for ${FULL_DOMAIN} pointing to this server's public IP address${NC}"
        
        read -p "Continue anyway? (y/n): " CONTINUE
        if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
            echo -e "${YELLOW}Operation cancelled${NC}"
            return 1
        fi
        return 0
    fi
}

# Function to create Nginx configuration
create_nginx_config() {
    local FULL_DOMAIN="${SUBDOMAIN}.${PARENT_DOMAIN}"
    local CONFIG_FILE="${NGINX_SITES_DIR}/${FULL_DOMAIN}"
    
    echo -e "${GREEN}Creating Nginx configuration for ${FULL_DOMAIN}...${NC}"
    
    # Create rate limiting zone if it doesn't exist in nginx.conf
    if ! grep -q "${RATE_LIMIT_ZONE}" /etc/nginx/nginx.conf; then
        echo -e "${YELLOW}Adding rate limiting zone to nginx.conf${NC}"
        # This approach isn't ideal - consider adding to a separate conf file instead
        sudo sed -i "/http {/a \    limit_req_zone \$binary_remote_addr zone=${RATE_LIMIT_ZONE}:10m rate=${RATE_LIMIT};" /etc/nginx/nginx.conf
    fi
    
    # Create the nginx configuration
    cat > "/tmp/${FULL_DOMAIN}.conf" << EOF
# Configuration for ${FULL_DOMAIN}
# Generated on $(date)

server {
    listen 80;
    server_name ${FULL_DOMAIN};
    
    # For Let's Encrypt webroot verification
    location /.well-known/acme-challenge/ {
        root ${WEBROOT_PATH};
    }
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${FULL_DOMAIN};
    
    # SSL Configuration
    ssl_certificate ${LETSENCRYPT_DIR}/${FULL_DOMAIN}/fullchain.pem;
    ssl_certificate_key ${LETSENCRYPT_DIR}/${FULL_DOMAIN}/privkey.pem;
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
    limit_req zone=${RATE_LIMIT_ZONE} burst=30 nodelay;
    
    location / {
        proxy_pass http://${IP_ADDRESS}:${PORT};
        proxy_buffering off;
        proxy_http_version 1.1;
        
        # Headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
EOF

    # Add WebSocket support if requested
    if [[ "$ENABLE_WEBSOCKET" == true ]]; then
        cat >> "/tmp/${FULL_DOMAIN}.conf" << EOF
        
        # WebSocket support
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
EOF
    fi

    # Close the location and server blocks
    cat >> "/tmp/${FULL_DOMAIN}.conf" << EOF
    }
}
EOF

    if [[ "$TEST_ONLY" == true ]]; then
        echo -e "${YELLOW}Test mode enabled. Configuration created but not applied.${NC}"
        echo -e "Configuration would be saved to: ${CONFIG_FILE}"
        echo -e "Preview of the configuration:"
        cat "/tmp/${FULL_DOMAIN}.conf"
        return
    fi
    
    # Test the configuration before applying
    echo -e "${YELLOW}Testing Nginx configuration...${NC}"
    sudo cp "/tmp/${FULL_DOMAIN}.conf" "${CONFIG_FILE}"
    if sudo nginx -t; then
        echo -e "${GREEN}Nginx configuration test passed${NC}"
    else
        echo -e "${RED}Nginx configuration test failed. Reverting changes.${NC}"
        sudo rm "${CONFIG_FILE}"
        return 1
    fi
}

# Function to obtain Let's Encrypt certificate using webroot
obtain_certificate() {
    local FULL_DOMAIN="${SUBDOMAIN}.${PARENT_DOMAIN}"
    
    echo -e "${GREEN}Obtaining Let's Encrypt certificate for ${FULL_DOMAIN}...${NC}"
    
    # Ensure webroot path exists
    if [ ! -d "$WEBROOT_PATH" ]; then
        echo -e "${YELLOW}Creating webroot directory ${WEBROOT_PATH}${NC}"
        sudo mkdir -p "$WEBROOT_PATH"
    fi
    
    # Ensure .well-known/acme-challenge directory exists and has proper permissions
    sudo mkdir -p "${WEBROOT_PATH}/.well-known/acme-challenge"
    sudo chmod -R 755 "${WEBROOT_PATH}/.well-known"
    
    if [[ "$TEST_ONLY" == true ]]; then
        echo -e "${YELLOW}Test mode enabled. Certificate would be obtained with:${NC}"
        echo -e "certbot certonly --webroot -w ${WEBROOT_PATH} -d ${FULL_DOMAIN} --non-interactive --agree-tos --email ${EMAIL}"
        return
    fi
    
    # Check if certificate already exists
    if [[ -d "${LETSENCRYPT_DIR}/${FULL_DOMAIN}" ]]; then
        echo -e "${YELLOW}Certificate already exists for ${FULL_DOMAIN}${NC}"
        return
    fi
    
    # Sleep to allow DNS changes to propagate
    echo -e "${YELLOW}Waiting 10 seconds for any DNS changes to propagate...${NC}"
    sleep 10
    
    # Added verbose flag to get more information in case of issues
    if sudo certbot certonly --webroot -w "${WEBROOT_PATH}" -d "${FULL_DOMAIN}" --non-interactive --agree-tos --email "${EMAIL}" -v; then
        echo -e "${GREEN}Certificate obtained successfully${NC}"
    else
        echo -e "${RED}Failed to obtain certificate. Check DNS settings and domain ownership${NC}"
        # Try HTTP authentication if webroot fails
        echo -e "${YELLOW}Trying standalone method as fallback...${NC}"
        echo -e "${YELLOW}Stopping nginx temporarily...${NC}"
        sudo systemctl stop nginx
        if sudo certbot certonly --standalone -d "${FULL_DOMAIN}" --non-interactive --agree-tos --email "${EMAIL}" -v; then
            echo -e "${GREEN}Certificate obtained successfully using standalone method${NC}"
            sudo systemctl start nginx
        else
            echo -e "${RED}Failed to obtain certificate using standalone method as well.${NC}"
            echo -e "${RED}Please ensure that:${NC}"
            echo -e "${RED}1. DNS record for ${FULL_DOMAIN} points to this server${NC}"
            echo -e "${RED}2. Port 80 is open in your firewall${NC}"
            echo -e "${RED}3. Your domain is properly registered and active${NC}"
            sudo systemctl start nginx
            return 1
        fi
    fi
}

# Function to create a site
create_site() {
    local FULL_DOMAIN="${SUBDOMAIN}.${PARENT_DOMAIN}"
    
    echo -e "${GREEN}Creating site for ${FULL_DOMAIN}...${NC}"
    
    # Check DNS record first
    if ! check_dns_record "$FULL_DOMAIN"; then
        return 1
    fi
    
    # Check if site already exists
    if [[ -f "${NGINX_SITES_DIR}/${FULL_DOMAIN}" ]]; then
        echo -e "${YELLOW}Site already exists for ${FULL_DOMAIN}${NC}"
        read -p "Do you want to overwrite it? (y/n): " OVERWRITE
        if [[ "$OVERWRITE" != "y" && "$OVERWRITE" != "Y" ]]; then
            echo -e "${YELLOW}Operation cancelled${NC}"
            return
        fi
    fi
    
    # Set up initial nginx config for the webroot challenge
    cat > "/tmp/${FULL_DOMAIN}.init.conf" << EOF
# Initial configuration for ${FULL_DOMAIN} - For Let's Encrypt verification
server {
    listen 80;
    server_name ${FULL_DOMAIN};
    
    # For Let's Encrypt webroot verification
    location /.well-known/acme-challenge/ {
        root ${WEBROOT_PATH};
        allow all;
    }
    
    location / {
        return 200 "Certbot validation server for ${FULL_DOMAIN}";
    }
}
EOF
    
    sudo cp "/tmp/${FULL_DOMAIN}.init.conf" "${NGINX_SITES_DIR}/${FULL_DOMAIN}"
    
    # Test and reload nginx
    if sudo nginx -t; then
        sudo systemctl reload nginx
        echo -e "${GREEN}Temporary configuration applied for certificate validation${NC}"
        
        # Obtain certificate if SSL is enabled
        if [[ "$SKIP_SSL" != true ]]; then
            obtain_certificate
            
            # Create final configuration
            create_nginx_config
        else
            echo -e "${YELLOW}Skipping SSL configuration as requested${NC}"
            create_nginx_config
        fi
    else
        echo -e "${RED}Nginx configuration test failed${NC}"
        sudo rm "${NGINX_SITES_DIR}/${FULL_DOMAIN}"
        return 1
    fi
    
    # Reload nginx 
    if [[ "$TEST_ONLY" != true ]]; then
        echo -e "${GREEN}Reloading Nginx...${NC}"
        sudo systemctl reload nginx
    fi
    
    echo -e "${GREEN}Site ${FULL_DOMAIN} has been successfully set up!${NC}"
}

# Function to remove a site
remove_site() {
    local FULL_DOMAIN="${SUBDOMAIN}.${PARENT_DOMAIN}"
    
    echo -e "${YELLOW}Removing site ${FULL_DOMAIN}...${NC}"
    
    # Check if site exists
    if [[ ! -f "${NGINX_SITES_DIR}/${FULL_DOMAIN}" ]]; then
        echo -e "${RED}Site does not exist for ${FULL_DOMAIN}${NC}"
        return 1
    fi
    
    # Remove nginx configuration
    sudo rm "${NGINX_SITES_DIR}/${FULL_DOMAIN}"
    
    # Reload nginx
    sudo nginx -t && sudo systemctl reload nginx
    
    echo -e "${GREEN}Site ${FULL_DOMAIN} has been removed${NC}"
    
    # Ask to remove certificate
    read -p "Do you want to remove the Let's Encrypt certificate as well? (y/n): " REMOVE_CERT
    if [[ "$REMOVE_CERT" == "y" || "$REMOVE_CERT" == "Y" ]]; then
        echo -e "${YELLOW}Removing certificate for ${FULL_DOMAIN}...${NC}"
        sudo certbot delete --cert-name "${FULL_DOMAIN}"
        echo -e "${GREEN}Certificate removed${NC}"
    fi
}

# Function to list all sites
list_sites() {
    echo -e "${GREEN}Listing all configured sites:${NC}"
    
    if [[ -d "$NGINX_SITES_DIR" ]]; then
        echo -e "Sites in ${NGINX_SITES_DIR}:"
        for site in "$NGINX_SITES_DIR"/*; do
            if [[ -f "$site" ]]; then
                SITE_NAME=$(basename "$site")
                if grep -q "server_name" "$site"; then
                    SERVER_NAME=$(grep "server_name" "$site" | head -1 | sed 's/.*server_name \(.*\);/\1/' | tr -d ';')
                    echo -e "  ${SITE_NAME} (${SERVER_NAME})"
                else
                    echo -e "  ${SITE_NAME}"
                fi
            fi
        done
    else
        echo -e "${RED}Nginx sites directory not found${NC}"
    fi
    
    echo -e "\n${GREEN}Let's Encrypt certificates:${NC}"
    sudo certbot certificates
}

# Parse command line arguments
COMMAND=$1
shift

if [[ -z "$COMMAND" ]]; then
    show_usage
    exit 1
fi

# Default values
SUBDOMAIN=""
IP_ADDRESS=""
PORT=""
ENABLE_WEBSOCKET=false
SKIP_SSL=false
TEST_ONLY=false

# Parse options based on command
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--subdomain)
            SUBDOMAIN="$2"
            shift 2
            ;;
        -i|--ip)
            IP_ADDRESS="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -r|--rate-limit)
            RATE_LIMIT="$2"
            shift 2
            ;;
        -w|--websocket)
            ENABLE_WEBSOCKET=true
            shift
            ;;
        -n|--no-ssl)
            SKIP_SSL=true
            shift
            ;;
        -t|--test-only)
            TEST_ONLY=true
            shift
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
done

# Execute the appropriate command
case "$COMMAND" in
    create)
        validate_inputs
        create_site
        ;;
    remove)
        validate_inputs
        remove_site
        ;;
    list)
        list_sites
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        show_usage
        exit 1
        ;;
esac

exit 0
