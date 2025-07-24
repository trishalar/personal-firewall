        if (line == ip) return true;
    }
    return false;
}

int main() {
    HANDLE handle;
    WINDIVERT_ADDRESS addr;
    char packet[MAX_PACKET_SIZE];
    UINT packetLen;

    // Filter TCP/IP packets
    std::string filter = "ip and outbound";
    handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Unable to open WinDivert handle." << std::endl;
        return 1;
    }

    std::cout << "[*] Firewall started. Monitoring traffic...\n";

    while (true) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
            continue;
        }

        // Extract source/destination IP
        WINDIVERT_IPHDR* ip_header = (WINDIVERT_IPHDR*)(packet);
        char dst_ip[16];
        sprintf(dst_ip, "%d.%d.%d.%d",
                ip_header->DstAddr >> 0 & 0xFF,
                ip_header->DstAddr >> 8 & 0xFF,
                ip_header->DstAddr >> 16 & 0xFF,
                ip_header->DstAddr >> 24 & 0xFF);

        if (isBlockedIP(std::string(dst_ip))) {
            std::cout << "[BLOCKED] Packet to: " << dst_ip << std::endl;
            continue; // Drop packet
        }

        // Forward the packet
        WinDivertSend(handle, packet, packetLen, NULL, &addr);
    }

    WinDivertClose(handle);
    return 0;
}
