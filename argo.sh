#!/bin/bash

# Exit on error
set -e

# Global variables
LOG_FILE="/var/log/argo-setup.log"
ARGO_DIR="/etc/argo"
CONFIG_FILE="${ARGO_DIR}/config.txt"
JSON_CONFIG="${ARGO_DIR}/config.json"
SCRIPT_VERSION="2.0.0"
SCRIPT_DATE="2024-12-28"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or using sudo."
  exit 1
fi

# Setup logging
setup_logging() {
  touch "$LOG_FILE"
  chmod 640 "$LOG_FILE"
  exec 1> >(tee -a "$LOG_FILE")
  exec 2> >(tee -a "$LOG_FILE" >&2)
  log_message "Starting Argo setup v${SCRIPT_VERSION}"
}

# Logging function
log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Improved spinner function
spinner() {
  local pid=$1
  local delay=0.75
  local spin='-\|/'
  local spinpos=0

  while ps -p $pid &>/dev/null; do
    printf "\r[%c] " "${spin:$spinpos:1}"
    spinpos=$(((spinpos + 1) % 4))
    sleep $delay
  done
  printf "\r   \r"
}

# Print banner
print_banner() {
    clear
    cat << "EOF"
 █████╗ ██████╗  ██████╗  ██████╗ 
██╔══██╗██╔══██╗██║  ██║██╔═══██╗
███████║██████╔╝██║  ██║██║   ██║
██╔══██║██╔══██╗██║  ██║██║   ██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ 
EOF
    cat << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 VLESS WebSocket + Cloudflare Tunnel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Version: ${SCRIPT_VERSION} 
Date:    ${SCRIPT_DATE}    
Author:  @theTCS_
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
}

# Menu Display
show_menu() {
  echo -e "\e[96m╭────────── Menu Options ────────╮\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m1\e[0m] ⚡ Install                 \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m2\e[0m] 📋 Show Config             \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m3\e[0m] 🗑️  Uninstall               \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m0\e[0m] 🚪 Exit                    \e[96m│\e[0m"
  echo -e "\e[96m╰────────────────────────────────╯\e[0m"
  echo
  echo -e "\e[93mEnter your choice \e[92m[0-3]\e[93m: \e[0m"
}

# Check dependencies
check_dependencies() {
  local deps=("curl" "wget" "tar" "ufw" "qrencode" "systemctl")
  local missing_deps=()

  log_message "Checking dependencies..."
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing_deps+=("$dep")
    fi
  done

  if [ ${#missing_deps[@]} -ne 0 ]; then
    log_message "Missing dependencies: ${missing_deps[*]}"
    echo "The following dependencies are missing: ${missing_deps[*]}"
    read -p "Would you like to install missing dependencies? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      apt-get update
      apt-get install -y "${missing_deps[@]}"
      log_message "Dependencies installed successfully"
    else
      log_message "Cannot proceed without required dependencies"
      exit 1
    fi
  fi
}

# Input validation
validate_input() {
  local port=$1
  local tunnelname=$2
  local subdomain=$3

  # Validate port
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    log_message "Error: Invalid port number. Must be between 1-65535"
    return 1
  fi

  # Validate tunnel name
  if [[ ! "$tunnelname" =~ ^[a-zA-Z0-9-]+$ ]]; then
    log_message "Error: Invalid tunnel name. Use only letters, numbers, and hyphens"
    return 1
  fi

  # Validate subdomain format
  if [[ ! "$subdomain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    log_message "Error: Invalid subdomain format"
    return 1
  fi

  return 0
}
# Backup configuration
backup_config() {
  if [ -d "$ARGO_DIR" ]; then
    local backup_dir="${ARGO_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
    cp -r "$ARGO_DIR" "$backup_dir"
    log_message "Configuration backed up to $backup_dir"
  fi
}

# Secure permissions
secure_permissions() {
  log_message "Setting secure permissions..."
  mkdir -p "$ARGO_DIR"
  chmod 750 "$ARGO_DIR"
  chmod 640 "$JSON_CONFIG"
  chmod 644 /etc/systemd/system/argo-vless.service
  chmod 644 /etc/systemd/system/cloudflared.service
  chown -R root:root "$ARGO_DIR"
  log_message "Permissions set successfully"
}

# Service management
manage_service() {
  local action=$1
  local service=$2

  log_message "Managing service $service: $action"
  if ! systemctl "$action" "$service"; then
    log_message "Failed to $action $service"
    return 1
  fi
  return 0
}

# Cleanup on failure
cleanup_failed_install() {
  log_message "Error occurred. Cleaning up..."
  systemctl stop argo-vless.service cloudflared.service 2>/dev/null || true
  rm -f /etc/systemd/system/argo-vless.service /etc/systemd/system/cloudflared.service
  rm -rf "$ARGO_DIR"
  systemctl daemon-reload
  log_message "Cleanup completed"
}

# Install service
install_service() {
  trap cleanup_failed_install ERR

  print_banner
  setup_logging
  check_dependencies
  backup_config

  # Get user input with validation
  while true; do
    read -p "Enter your desired config port: " user_port
    read -p "Enter your desired Tunnel name: " user_tunnelname
    read -p "Enter your desired subdomain (e.g., sub.mydomain.com): " user_subdomain

    if validate_input "$user_port" "$user_tunnelname" "$user_subdomain"; then
      break
    fi
    echo "Please try again..."
  done

  # Generate UUID
  uuid=$(cat /proc/sys/kernel/random/uuid)
  log_message "Generated UUID: $uuid"

  # Install cloudflared if not present
  if ! command -v cloudflared &>/dev/null; then
    log_message "Installing Cloudflared..."
    echo "Downloading Cloudflare Argo Tunnel binary..."
    LATEST_CLFD_URL=$(curl -Ls -o /dev/null -w "%{url_effective}" https://github.com/cloudflare/cloudflared/releases/latest | sed 's/tag/download/g')
    curl -fsSL "${LATEST_CLFD_URL}/cloudflared-linux-amd64" -o /usr/bin/cloudflared &
    spinner $!
    chmod +x /usr/bin/cloudflared
    log_message "Cloudflared installed successfully"
  fi

  # Authenticate and create tunnel
  log_message "Starting Cloudflare authentication..."
  echo "Authenticating with Cloudflare..."
  cloudflared tunnel login &
  spinner $!

  log_message "Creating tunnel: $user_tunnelname"
  cloudflared tunnel create "$user_tunnelname"
  cloudflared tunnel route dns "$user_tunnelname" "$user_subdomain"

  # Create configuration directory and files
  mkdir -p "$ARGO_DIR"

  # Create JSON configuration
  log_message "Creating configuration files..."
  cat >"$JSON_CONFIG" <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "route": {
    "rules": [
      {
        "rule_set": [
          "geosite-category-ads-all",
          "geosite-malware",
          "geosite-phishing",
          "geosite-cryptominers",
          "geoip-malware",
          "geoip-phishing",
          "geosite-ir",
          "geoip-ir"
        ],
        "outbound": "block"
      },
      {
        "inbound": ["vless-in"],
        "outbound": "direct"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-ir",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs"
      },
      {
        "tag": "geosite-malware",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs"
      },
      {
        "tag": "geosite-phishing",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs"
      },
      {
        "tag": "geosite-cryptominers",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs"
      },
      {
        "tag": "geoip-ir",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs"
      },
      {
        "tag": "geoip-malware",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs"
      },
      {
        "tag": "geoip-phishing",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs"
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $user_port,
      "sniff": true,
      "sniff_override_destination": true,
      "tls": {},
      "multiplex": {
        "enabled": true,
        "padding": false,
        "brutal": {}
      },      
      "transport": {
        "type": "ws",
        "path": "",
        "headers": {},
        "max_early_data": 0,
        "early_data_header_name": ""
      },
      "users": [
        {
          "name": "Argo-WebSocket",
          "uuid": "$uuid"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  }
}
EOF

  # Create systemd service files
  log_message "Creating service files..."
  cat >/etc/systemd/system/argo-vless.service <<EOF
[Unit]
Description=Argo VLESS Service
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=$ARGO_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/bin/argo-vless run -c $JSON_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Argo Tunnel Service
After=network.target

[Service]
ExecStart=/usr/bin/cloudflared tunnel --url localhost:$user_port run "$user_tunnelname"
Restart=always
User=root
Group=root
WorkingDirectory=$ARGO_DIR

[Install]
WantedBy=multi-user.target
EOF

  # Install sing-box
  log_message "Installing sing-box..."
  mkdir -p /root/singbox && cd /root/singbox
  LATEST_URL=$(curl -Ls -o /dev/null -w "%{url_effective}" https://github.com/SagerNet/sing-box/releases/latest)
  LATEST_VERSION="$(echo "$LATEST_URL" | grep -o -E '/.?[0-9|\.]+$' | grep -o -E '[0-9|\.]+')"
  LINK="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-amd64.tar.gz"

  echo "Downloading sing-box..."
  wget "$LINK" &
  spinner $!

  tar -xf "sing-box-${LATEST_VERSION}-linux-amd64.tar.gz"
  cp "sing-box-${LATEST_VERSION}-linux-amd64/sing-box" "/usr/bin/argo-vless"
  cd && rm -rf singbox

  # Configure firewall
  if ufw status | grep -q "Status: active"; then
    log_message "Configuring UFW..."
    ufw disable
    ufw allow "$user_port"
    echo "y" | ufw enable
    ufw reload
    log_message "UFW rules updated"
  else
    log_message "UFW is not active, skipping firewall configuration"
  fi

  # Set permissions and start services
  secure_permissions

  log_message "Starting services..."
  systemctl daemon-reload
  manage_service "enable" "argo-vless.service"
  manage_service "enable" "cloudflared.service"
  manage_service "start" "argo-vless.service"
  manage_service "start" "cloudflared.service"

  # Generate and save configuration URL
  result_url="vless://$uuid@$user_subdomain:443?security=tls&sni=$user_subdomain&alpn=http/1.1&fp=firefox&type=ws&host=$user_subdomain&encryption=none#Argo-WebSocket"
  echo -e "$result_url" >"$CONFIG_FILE"

  # Display configuration
  echo -e "\n================== Configuration ==================="
  echo -e "Config URL: \e[91m$result_url\e[0m"
  echo -e "\nQR Code:"
  qrencode -t ANSIUTF8 <<<"$result_url"

  log_message "Installation completed successfully"

  echo -e "\n\e[31mPress Enter to Exit\e[0m"
  read
  clear
}

# Show configuration
show_config() {
  if [ -f "$CONFIG_FILE" ]; then
    echo -e "Config URL: \e[91m$(cat "$CONFIG_FILE")\e[0m"
    echo -e "\nQR Code:"
    qrencode -t ANSIUTF8 <<<"$(cat "$CONFIG_FILE")"
  else
    log_message "Configuration file not found"
    echo "Argo is not installed yet"
  fi

  echo -e "\n\e[31mPress Enter to Exit\e[0m"
  read
  clear
}

# Uninstall service
uninstall_service() {
  log_message "Starting uninstallation..."

  # Backup before uninstall
  backup_config

  # Stop and disable services
  manage_service "stop" "argo-vless.service" || true
  manage_service "stop" "cloudflared.service" || true
  manage_service "disable" "argo-vless.service" || true
  manage_service "disable" "cloudflared.service" || true

  # Remove files
  rm -f /etc/systemd/system/argo-vless.service
  rm -f /etc/systemd/system/cloudflared.service
  rm -f /usr/bin/cloudflared
  rm -f /usr/bin/argo-vless
  rm -rf "$ARGO_DIR"

  systemctl daemon-reload
  log_message "Uninstallation completed"

  echo "Argo uninstalled successfully"
  sleep 2
  clear
}

# Main program loop
while true; do
  print_banner
  show_menu
  read choice

  case $choice in
  1)
    clear
    install_service
    ;;
  2)
    clear
    show_config
    ;;
  3)
    clear
    uninstall_service
    ;;
  0)
    clear
    echo -e "\e[92m👋 Thank you for using Argo! Goodbye!\e[0m"
    exit 0
    ;;
  *)
    echo -e "\e[91m❌ Invalid choice. Please select a valid option.\e[0m"
    sleep 2
    clear
    ;;
  esac
done
