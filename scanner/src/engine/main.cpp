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

std::mutex queue_mutex;
std::mutex print_mutex;
std::queue<int> port_queue;

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
    int num_threads = 100; 

    std::vector<int> common_ports = {21, 22, 23, 25, 53, 80, 110, 443, 8000, 8080};
    for (int p : common_ports) {
        port_queue.push(p);
    }

    std::cout << "Scanning target: " << target_ip << " with " << num_threads << " threads...\n" << std::endl;

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