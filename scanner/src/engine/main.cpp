//Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown

#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        std::cerr << "Failed to connect to socket." << std::endl;
        return 1;
    }

    sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(8000);


    if(inet_pton(AF_INET, "127.0.0.1", &target.sin_addr) <= 0)
    {
        std::cerr << "Invalid address format." << std::endl;
        close(sock);
        return 1;
    }

    std::cout << "Attempting to connect to 127.0.0.1:80..." << std::endl;
    if (connect(sock, (struct sockaddr*)&target, sizeof(target)) < 0) {
        std::cout << "Port 8000 is CLOSED or unreachable." << std::endl;
    } else {
        std::cout << "Port 8000 is OPEN." << std::endl;
    }

    close(sock);
    return 0;
}