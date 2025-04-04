#!/bin/bash

REPO="gfw_resist_tcp_proxy"
FORK_URL="https://github.com/sarabbafrani/gfw_resist_tcp_proxy.git"

echo "=== GFW Resist TCP Proxy Setup (via sarabbafrani fork) ==="
echo "Are you setting up the server or the client?"
select role in "Server (VPS)" "Client (Inside China)"; do
    case $role in
        "Server (VPS)")
            echo "[+] Setting up the server..."
            sudo apt update
            sudo apt install -y python3-pip git
            pip3 install --break-system-packages scapy

            if [ ! -d "$REPO" ]; then
                git clone "$FORK_URL"
            fi
            cd "$REPO/method1" || exit

            echo "[+] Starting server script..."
            sudo python3 server.py
            break
            ;;
        "Client (Inside China)")
            echo "[+] Setting up the client..."
            sudo apt update
            sudo apt install -y python3-pip git
            pip3 install --break-system-packages scapy

            if [ ! -d "$REPO" ]; then
                git clone "$FORK_URL"
            fi
            cd "$REPO/method1" || exit

            read -p "Enter your VPS IP address: " SERVER_IP
            echo "[+] Starting client script to connect to $SERVER_IP..."
            sudo python3 client.py --server-ip "$SERVER_IP"
            break
            ;;
        *)
            echo "Invalid option, please choose 1 or 2."
            ;;
    esac
done
