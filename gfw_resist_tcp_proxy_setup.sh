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

            echo "[+] Installing Python modules..."
            pip3 install scapy aioquic

            if [ ! -f "$REPO/method1/mainserver.py" ]; then
                echo "[i] Re-downloading clean repo..."
                rm -rf "$REPO"
                git clone "$FORK_URL"
            fi

            cd "$REPO/method1" || { echo "[!] Failed to enter method1 directory"; exit 1; }

            echo "[+] Starting mainserver.py..."
            sudo python3 mainserver.py
            break
            ;;
        "Client (Inside China)")
            echo "[+] Setting up the client..."
            sudo apt update
            sudo apt install -y python3-pip git

            echo "[+] Installing Python modules..."
            pip3 install scapy aioquic

            if [ ! -f "$REPO/method1/mainclient.py" ]; then
                echo "[i] Re-downloading clean repo..."
                rm -rf "$REPO"
                git clone "$FORK_URL"
            fi

            cd "$REPO/method1" || { echo "[!] Failed to enter method1 directory"; exit 1; }

            read -p "Enter your VPS IP address: " SERVER_IP
            echo "[+] Starting mainclient.py to connect to $SERVER_IP..."
            sudo python3 mainclient.py --server-ip "$SERVER_IP"
            break
            ;;
        *)
            echo "Invalid option, please choose 1 or 2."
            ;;
    esac
done
