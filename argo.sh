#!/bin/bash

# Exit on error and unset variables
set -euo pipefail

# Global variables
LOG_FILE="/var/log/argo-setup.log"
ARGO_DIR="/etc/argo"
CONFIG_FILE="${ARGO_DIR}/config.txt"
JSON_CONFIG="${ARGO_DIR}/config.json"
SCRIPT_VERSION="2.2.0"
SCRIPT_DATE="2025-01-26"
TMP_DIR=$(mktemp -d -t argo-XXXXXXXXXX)

# Cleanup function
cleanup() {
  rm -rf "$TMP_DIR"
  log_message "Temporary files cleaned up"
}

trap cleanup EXIT

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or using sudo."
  exit 1
fi

# Setup logging
setup_logging() {
  touch "$LOG_FILE"
  chmod 640 "$LOG_FILE"
  exec 3>&1 # Save original stdout to FD 3
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

  while ps -p "$pid" &>/dev/null; do
    printf "\r[%c] " "${spin:$spinpos:1}" >&3
    spinpos=$(((spinpos + 1) % 4))
    sleep "$delay"
  done
  printf "\r   \r" >&3
}

# Print banner
print_banner() {
  clear
  cat <<"EOF"
 █████╗ ██████╗  ██████╗  ██████╗ 
██╔══██╗██╔══██╗██║  ██║██╔═══██╗
███████║██████╔╝██║  ██║██║   ██║
██╔══██║██╔══██╗██║  ██║██║   ██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ 
EOF
  cat <<EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 VLESS + Cloudflare Tunnel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Version: ${SCRIPT_VERSION} 
Date:    ${SCRIPT_DATE}    
Author:  @theTCS_
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
}

# Menu Display
show_menu() {
  echo -e "\e[96m╭────────── Menu Options ────────╮\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m1\e[0m] ⚡ Install                 \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m2\e[0m] 📋 Show Config             \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m3\e[0m] 🆕 Update Components       \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m4\e[0m] 🗑️  Uninstall               \e[96m│\e[0m"
  echo -e "\e[96m│\e[0m [\e[92m0\e[0m] 🚪 Exit                    \e[96m│\e[0m"
  echo -e "\e[96m╰────────────────────────────────╯\e[0m"
  echo
  echo -en "\e[93mEnter your choice \e[92m[0-4]\e[93m: \e[0m"
}

# Check dependencies
check_dependencies() {
  local deps=("curl" "wget" "tar" "qrencode")
  local missing_deps=()

  log_message "Checking dependencies..."
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing_deps+=("$dep")
    fi
  done

  if [ ${#missing_deps[@]} -ne 0 ]; then
    log_message "Missing dependencies: ${missing_deps[*]}"
    echo "The following dependencies are missing: ${missing_deps[*]}" >&3
    read -rp "Would you like to install missing dependencies? [y/N] " -n 1 -r
    echo >&3
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      if command -v apt-get &>/dev/null; then
        apt-get update
        apt-get install -y "${missing_deps[@]}"
      elif command -v yum &>/dev/null; then
        yum install -y "${missing_deps[@]}"
      else
        log_message "Unsupported package manager"
        exit 1
      fi
      log_message "Dependencies installed successfully"
    else
      log_message "Aborting due to missing dependencies"
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
    log_message "Invalid port number: $port"
    echo "Error: Invalid port number. Must be between 1-65535" >&3
    return 1
  fi

  # Validate tunnel name
  if [[ ! "$tunnelname" =~ ^[a-zA-Z0-9-]{1,128}$ ]]; then
    log_message "Invalid tunnel name: $tunnelname"
    echo "Error: Invalid tunnel name. Use 1-128 letters, numbers, or hyphens" >&3
    return 1
  fi

  # Validate subdomain format
  if [[ ! "$subdomain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    log_message "Invalid subdomain format: $subdomain"
    echo "Error: Invalid subdomain format. Use valid domain format (e.g., sub.example.com)" >&3
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
    # Keep only last 3 backups
    find "${ARGO_DIR}.backup."* -maxdepth 0 -type d | sort -r | tail -n +4 | xargs rm -rf
  fi
}

# Secure permissions
secure_permissions() {
  log_message "Setting secure permissions..."
  mkdir -p "$ARGO_DIR"
  chmod 750 "$ARGO_DIR"
  [ -f "$JSON_CONFIG" ] && chmod 640 "$JSON_CONFIG"
  [ -f "/etc/systemd/system/argo-vless.service" ] && chmod 644 /etc/systemd/system/argo-vless.service
  [ -f "/etc/systemd/system/cloudflared.service" ] && chmod 644 /etc/systemd/system/cloudflared.service
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

# Get latest GitHub release
get_latest_release() {
  local repo=$1
  local attempt=0
  local max_attempts=3
  local result

  while [ $attempt -lt $max_attempts ]; do
    result=$(curl -s \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -n "$result" ]; then
      echo "$result"
      return 0
    fi

    attempt=$((attempt + 1))
    sleep 1
  done

  log_message "Failed to get latest release for $repo after $max_attempts attempts"
  echo "unknown"
  return 1
}

# Install cloudflared
install_cloudflared() {
  log_message "Installing Cloudflared..."
  local CLFD_VERSION
  CLFD_VERSION=$(get_latest_release "cloudflare/cloudflared")
  CLFD_URL="https://github.com/cloudflare/cloudflared/releases/download/${CLFD_VERSION}/cloudflared-linux-amd64"

  echo "Downloading Cloudflared ${CLFD_VERSION}..." >&3
  curl -fsSL "$CLFD_URL" -o "${TMP_DIR}/cloudflared" &
  spinner $!
  install -m 755 "${TMP_DIR}/cloudflared" /usr/bin/cloudflared
  log_message "Cloudflared installed successfully"
}

# Install sing-box
install_singbox() {
  log_message "Installing sing-box..."
  local SB_VERSION
  SB_VERSION=$(get_latest_release "SagerNet/sing-box" | sed 's/^v//')
  SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-amd64.tar.gz"

  echo "Downloading sing-box ${SB_VERSION}..." >&3
  curl -fsSL "$SB_URL" -o "${TMP_DIR}/singbox.tar.gz" &
  spinner $!
  tar -xzf "${TMP_DIR}/singbox.tar.gz" -C "${TMP_DIR}"
  install -m 755 "${TMP_DIR}/sing-box-${SB_VERSION}-linux-amd64/sing-box" /usr/bin/argo-vless
  log_message "sing-box installed successfully"
}

# Configure firewall
configure_firewall() {
  local port=$1
  if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    log_message "Configuring UFW..."
    ufw allow "$port"/tcp
    ufw reload
    log_message "UFW rules updated"
  elif command -v firewall-cmd &>/dev/null; then
    log_message "Configuring firewalld..."
    firewall-cmd --permanent --add-port="$port"/tcp
    firewall-cmd --reload
    log_message "Firewalld rules updated"
  else
    log_message "No active firewall detected, skipping configuration"
  fi
}

# Main installation function
install_service() {
  trap cleanup_failed_install ERR

  print_banner
  setup_logging
  check_dependencies
  backup_config

  # Get user input with validation
  while true; do
    read -rp "Enter your desired config port [443]: " user_port
    user_port=${user_port:-443}
    read -rp "Enter your desired Tunnel name [argo-tunnel]: " user_tunnelname
    user_tunnelname=${user_tunnelname:-argo-tunnel}
    read -rp "Enter your subdomain (e.g., sub.example.com): " user_subdomain

    if validate_input "$user_port" "$user_tunnelname" "$user_subdomain"; then
      break
    fi
  done

  # Generate UUID
  uuid=$(uuidgen || cat /proc/sys/kernel/random/uuid)
  log_message "Generated UUID: $uuid"

  # Install cloudflared if not present
  if ! command -v cloudflared &>/dev/null; then
    install_cloudflared
  fi

  # Authenticate and create tunnel
  log_message "Starting Cloudflare authentication..."
  echo "Authenticate Cloudflare tunnel here:" >&3
  cloudflared tunnel login 2>&3

  log_message "Creating tunnel: $user_tunnelname"
  cloudflared tunnel create "$user_tunnelname" 2>&3
  cloudflared tunnel route dns "$user_tunnelname" "$user_subdomain" 2>&3

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
  if ! command -v argo-vless &>/dev/null; then
    install_singbox
  fi

  # Configure firewall
  configure_firewall "$user_port"

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
  echo -e "\n================== Configuration ===================" >&3
  echo -e "Config URL: \e[91m$result_url\e[0m" >&3
  echo -e "\nQR Code:" >&3
  qrencode -t ANSIUTF8 <<<"$result_url" >&3

  log_message "Installation completed successfully"

  echo -e "\n\e[31mPress Enter to Exit\e[0m" >&3
  read -r
  clear
}

# Show configuration
show_config() {
  if [ -f "$CONFIG_FILE" ]; then
    echo -e "Config URL: \e[91m$(cat "$CONFIG_FILE")\e[0m" >&3
    echo -e "\nQR Code:" >&3
    qrencode -t ANSIUTF8 <<<"$(cat "$CONFIG_FILE")" >&3
  else
    log_message "Configuration file not found"
    echo "Argo is not installed yet" >&3
  fi

  echo -e "\n\e[31mPress Enter to Exit\e[0m" >&3
  read -r
  clear
}

# Update binaries
update_components() {
  clear
  print_banner
  log_message "Starting component update process"

  any_updated=false

  # Cloudflared update
  if command -v cloudflared &>/dev/null; then
    current_cf_version=$(cloudflared --version | grep -Po '\d+\.\d+\.\d+')
    latest_cf_version=$(get_latest_release "cloudflare/cloudflared")

    if [ "$current_cf_version" != "$latest_cf_version" ]; then
      echo -e "\e[93mUpdating Cloudflared from v${current_cf_version} to v${latest_cf_version}\e[0m" >&3
      systemctl stop cloudflared.service 2>/dev/null || true
      install_cloudflared
      systemctl start cloudflared.service 2>/dev/null || true
      any_updated=true
    else
      echo -e "\e[92mCloudflared is already up-to-date (v${current_cf_version})\e[0m" >&3
    fi
  else
    echo -e "\e[91mCloudflared not installed - skipping update\e[0m" >&3
  fi

  # sing-box update
  if command -v argo-vless &>/dev/null; then
    current_sb_version=$(argo-vless version 2>&1 | grep -m1 'sing-box version' | awk '{print $3}')
    latest_sb_version=$(get_latest_release "SagerNet/sing-box" | sed 's/^v//')

    if [ "$current_sb_version" != "$latest_sb_version" ]; then
      echo -e "\e[93mUpdating sing-box from v${current_sb_version} to v${latest_sb_version}\e[0m" >&3
      systemctl stop argo-vless.service 2>/dev/null || true
      install_singbox
      systemctl start argo-vless.service 2>/dev/null || true
      any_updated=true
    else
      echo -e "\e[92msing-box is already up-to-date (v${current_sb_version})\e[0m" >&3
    fi
  else
    echo -e "\e[91msing-box not installed - skipping update\e[0m" >&3
  fi

  if [ "$any_updated" = true ]; then
    echo -e "\e[92mUpdate completed successfully!\e[0m" >&3
    log_message "Components updated successfully"
  else
    echo -e "\e[93mNo updates were available\e[0m" >&3
  fi

  echo -e "\n\e[31mPress Enter to Continue\e[0m" >&3
  read -r
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
  rm -f /etc/systemd/system/argo-vless.service \
    /etc/systemd/system/cloudflared.service \
    /usr/bin/cloudflared \
    /usr/bin/argo-vless
  rm -rf "$ARGO_DIR"

  systemctl daemon-reload
  log_message "Uninstallation completed"

  echo "Argo uninstalled successfully" >&3
  sleep 2
  clear
}

setup_logging

# Main program loop
while true; do
  print_banner
  show_menu
  read -r choice

  case $choice in
  1)
    install_service
    ;;
  2)
    show_config
    ;;
  3)
    update_components
    ;;
  4)
    uninstall_service
    ;;
  0)
    echo -e "\e[92m👋 Thank you for using Argo! Goodbye!\e[0m" >&3
    exit 0
    ;;
  *)
    echo -e "\e[91m❌ Invalid choice. Please select a valid option.\e[0m" >&3
    sleep 2
    ;;
  esac
  clear
done
