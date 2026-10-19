//Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown
//This is primarily a test code here, not final
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        std::cerr << "Socket creation failed." << std::endl;
        return 1;
    }

    
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(8000);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed. Port might be in use." << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "C++ Test Server listening on port 8000..." << std::endl;

    int new_socket = accept(server_fd, nullptr, nullptr);
    if (new_socket >= 0) {
        std::cout << "Connection received! Your scanner successfully found the open port." << std::endl;
        close(new_socket);
    }
    close(server_fd);
    return 0;
}
