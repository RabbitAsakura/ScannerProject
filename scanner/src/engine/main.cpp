//Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown

#include <iostream>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <string>
#include <cstring>
#include <algorithm>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sqlite3.h>
#include <netinet/ip_icmp.h>

std::mutex queue_mutex;
std::mutex print_mutex;
std::queue<int> port_queue;

unsigned short calculate_checksum(void* b, int len) {
    unsigned short* buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

bool is_host_alive(const char* target_ip) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        std::cerr << "[-] Error: Raw socket creation failed. Did you run with sudo?" << std::endl;
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    struct icmphdr icmp_hdr;
    bzero(&icmp_hdr, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.checksum = calculate_checksum(&icmp_hdr, sizeof(icmp_hdr));

    if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        close(sockfd);
        return false;
    }

    char buffer[1024];
    struct sockaddr_in r_addr;
    socklen_t addr_len = sizeof(r_addr);
    if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&r_addr, &addr_len) > 0) {
        close(sockfd);
        return true;
    }

    close(sockfd);
    return false;
}


void check_vulnerabilities(const std::string& banner) {
    sqlite3* db;
    if (sqlite3_open("nvd_cache.db", &db) != SQLITE_OK) return;

    std::string sql = "SELECT cve_id, severity FROM vulnerabilities WHERE ? LIKE '%' || software || '%' AND ? LIKE '%' || version || '%';";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, banner.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, banner.c_str(), -1, SQLITE_TRANSIENT);

        bool found = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            found = true;
            const unsigned char* cve = sqlite3_column_text(stmt, 0);
            const unsigned char* severity = sqlite3_column_text(stmt, 1);
            std::cout << "      [!] VULNERABILITY FOUND: " << cve << " (Severity: " << severity << ")" << std::endl;
        }
        if (!found) {
            std::cout << "      [-] No known vulnerabilities found in local database." << std::endl;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

std::pair<bool, std::string> check_port(const char* ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return {false, ""};

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &target.sin_addr) <= 0) {
        close(sock);
        return {false, ""};
    }

    if (connect(sock, (struct sockaddr*)&target, sizeof(target)) < 0) {
        close(sock);
        return {false, ""};
    }

    char buffer[1024] = {0};
    std::string banner = "";
    int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        banner = std::string(buffer, bytes_received);
    } else {
        const char* http_req = "HEAD / HTTP/1.1\r\nHost: target\r\n\r\n";
        send(sock, http_req, strlen(http_req), 0);
        bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) banner = std::string(buffer, bytes_received);
    }

    close(sock);

    if (!banner.empty()) {
        size_t newline_pos = banner.find('\n');
        if (newline_pos != std::string::npos) banner = banner.substr(0, newline_pos);
        banner.erase(std::remove(banner.begin(), banner.end(), '\r'), banner.end());
    }
    return {true, banner};
}

void worker(const char* target_ip) {
    while (true) {
        int port = 0;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (port_queue.empty()) return;
            port = port_queue.front();
            port_queue.pop();
        } 
        
        auto [is_open, banner] = check_port(target_ip, port);
        
        if (is_open) {
            std::lock_guard<std::mutex> print_lock(print_mutex);
            std::cout << "[+] Port " << port << " is OPEN.";
            if (!banner.empty()) {
                std::cout << " Banner: [" << banner << "]" << std::endl;
                check_vulnerabilities(banner);
            } else {
                std::cout << std::endl;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <IP_ADDRESS>\n";
        return 1;
    }

    const char* target_ip = argv[1];

    std::cout << "Initiating ping sweep on " << target_ip << "..." << std::endl;
    
    if (!is_host_alive(target_ip)) {
        std::cout << "[-] Host appears to be down or is blocking ICMP. Skipping port scan." << std::endl;
        return 0;
    }
    
    std::cout << "[+] Host is up. Starting threaded port scan...\n" << std::endl;

    int num_threads = 100; 

    std::vector<int> common_ports = {21, 22, 23, 25, 53, 80, 110, 443, 8000, 8080};
    for (int p : common_ports) {
        port_queue.push(p);
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, target_ip);
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "\nScan complete." << std::endl;
    return 0;
}