//Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown
//This is primarily a test code here, not final
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8000);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);

    std::cout << "C++ Test Server listening on port 8000..." << std::endl;

    int new_socket = accept(server_fd, nullptr, nullptr);
    if (new_socket >= 0) {
        const char* fake_banner = "Apache/2.4.49\n";
        send(new_socket, fake_banner, strlen(fake_banner), 0);
        std::cout << "Connection received. Sent vulnerable banner." << std::endl;
        close(new_socket);
    }

    close(server_fd);
    return 0;
}