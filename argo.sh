#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root or using sudo."
    exit
fi

spinner() {
    local pid=$1
    local delay=0.75
    local spin='-\|/'

    while ps -p $pid &>/dev/null; do
        local temp=${spin#?}
        printf " [%c]  " "$spin"
        local spin=$temp${spin%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

install_service() {
    if ! command -v qrencode &>/dev/null; then
        apt install -y qrencode
    fi
    if ! command -v cloudflared &>/dev/null; then
    
        # Getting latest Cloudflared binary URL To Download 
        LATEST_CLFD_URL=$(curl -Ls -o /dev/null -w "%{url_effective}" https://github.com/cloudflare/cloudflared/releases/latest | sed 's/tag/download/g')

        echo "Downloading Cloudflare Argo Tunnel binary..."
        curl -fsSL ${LATEST_CLFD_URL}/cloudflared-linux-amd64 \
            -o /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared &
        spinner $!

    else
        echo "Cloudflare Argo Tunnel is already installed."
    fi

    echo "Authenticating with Cloudflare..."
    cloudflared tunnel login &
    spinner $!
    echo "Authentication successful."

    read -p "Enter your desired config port: " user_port
    read -p "Enter your desired Tunnel name: " user_tunnelname
    read -p "Enter your desired subdomain (e.g., sub.mydomain.com): " user_subdomain
    uuid=$(cat /proc/sys/kernel/random/uuid)

    echo "Creating tunnel..."
    cloudflared tunnel create "$user_tunnelname"

    echo "Linking the Tunnel to your Domain..."
    cloudflared tunnel route dns "$user_tunnelname" "$user_subdomain"

    mkdir /etc/argo
    cat <<EOF >/etc/argo/config.json
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
        "inbound": [
          "vless-in"
        ],
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

    cat <<EOF >/etc/systemd/system/argo-vless.service
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/argo
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/bin/argo-vless run -c /etc/argo/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    mkdir /root/singbox && cd /root/singbox || exit
    LATEST_URL=$(curl -Ls -o /dev/null -w "%{url_effective}" https://github.com/SagerNet/sing-box/releases/latest)
    LATEST_VERSION="$(echo "$LATEST_URL" | grep -o -E '/.?[0-9|\.]+$' | grep -o -E '[0-9|\.]+')"
    LINK="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-amd64.tar.gz" 
    wget "$LINK"
    tar -xf "sing-box-${LATEST_VERSION}-linux-amd64.tar.gz"
    cp "sing-box-${LATEST_VERSION}-linux-amd64/sing-box" "/usr/bin/argo-vless"
    cd && rm -rf singbox

    cat <<EOF >/etc/systemd/system/cloudflared.service
[Unit]
Description=Cloudflare Argo Tunnel Service
After=network.target

[Service]
ExecStart=/usr/bin/cloudflared tunnel --url localhost:"$user_port" run "$user_tunnelname"
Restart=always
User=root
Group=root
WorkingDirectory=/etc/argo

[Install]
WantedBy=multi-user.target
EOF

    if ufw status | grep -q "Status: active"; then
        ufw disable

        ufw allow "$user_port"

        sleep 0.5
        echo "y" | ufw enable
        ufw reload
        echo 'UFW is Optimized.'
        sleep 0.5
    else
        echo "UFW is not active"
    fi

    systemctl daemon-reload
    systemctl enable --now argo-vless.service
    systemctl enable --now cloudflared.service

    spinner $!
    echo "Cloudflare Argo Tunnel started successfully!"

    result_url="vless://$uuid@$user_subdomain:443?security=tls&sni=$user_subdomain&alpn=http/1.1&fp=firefox&type=ws&host=$user_subdomain&encryption=none#Argo-WebSocket"

    echo -e "$result_url" >/etc/argo/config.txt
    echo -e "Config URL: \e[91m$result_url\e[0m"

    config=$(cat /etc/argo/config.txt)

    echo QR:
    qrencode -t ANSIUTF8 <<<"$config"

    echo -e "\e[31mPress Enter to Exit\e[0m"
    read
    clear
}

show_config() {
    argo_check="/etc/argo/config.txt"

    if [ -e "$argo_check" ]; then
        echo -e "Config URL: \e[91m$(cat /etc/argo/config.txt)\e[0m"

        config=$(cat /etc/argo/config.txt)

        echo QR:
        qrencode -t ANSIUTF8 <<<"$config"
        echo -e "\e[31mPress Enter to Exit\e[0m"
        read
        clear
    else
        echo -e "Argo is not installed yet"
    fi

}

uninstall_service() {

    systemctl disable --now argo-vless.service
    systemctl disable --now cloudflared.service
    rm -f /etc/systemd/system/argo-vless.service /etc/systemd/system/cloudflared.service /usr/bin/cloudflared /usr/bin/argo-vless
    rm -rf /etc/argo
    systemctl daemon-reload
    clear

    echo -e "Argo uninstalled successfully"
}

while true; do
    echo "┏┓      ┏┳┓       ┓ ┳      ┓    
┣┫┏┓┏┓┏┓ ┃┓┏┏┓┏┓┏┓┃ ┃┏┓┏╋┏┓┃┏┓┏┓
┛┗┛ ┗┫┗┛ ┻┗┻┛┗┛┗┗ ┗ ┻┛┗┛┗┗┻┗┗ ┛ 
     ┛                        by theTCS

"
    echo "1. Install"
    echo "2. Show Config"
    echo "3. Uninstall"
    echo "0. Exit"

    read -p "Enter your choice: " choice

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
        echo "Exiting..."
        break
        ;;
    *)
        echo "Invalid choice. Please select a valid option."
        ;;
    esac
done
