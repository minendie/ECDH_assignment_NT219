#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include <sstream>
#include <thread>  // Thêm thư viện thread

#pragma comment (lib, "ws2_32.lib")

using namespace std;

// Hàm xử lý luồng nhận tin nhắn từ một client và broadcast tin nhắn đến tất cả các client khác
void ClientHandler(SOCKET clientSocket, fd_set& master, SOCKET listeningSocket)
{
    char buf[4096];
    ZeroMemory(buf, 4096);

    while (true) {
        int bytesIn = recv(clientSocket, buf, 4096, 0);
        if (bytesIn <= 0)
        {
            // Ngắt kết nối với client
            closesocket(clientSocket);
            FD_CLR(clientSocket, &master);
            break;
        }
        else
        {
            // Gửi tin nhắn đến tất cả các client khác
            for (int i = 0; i < master.fd_count; i++)
            {
                SOCKET outSock = master.fd_array[i];
                if (outSock != listeningSocket && outSock != clientSocket)
                {
                    ostringstream ss;
                    ss << "SOCKET #" << clientSocket << ": " << buf << "\r\n";
                    string strOut = ss.str();

                    send(outSock, strOut.c_str(), strOut.size() + 1, 0);
                }
            }
        }
    }
}

int main()
{
    // Initalize winsock
    WSADATA wsData;
    WORD ver = MAKEWORD(2, 2);
    int wsOk = WSAStartup(ver, &wsData);
    if (wsOk != 0)
    {
        cerr << "Can't Initialize winsock! Quitting" << endl;
        return 1;
    }

    // Create listener socket
    SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
    if (listening == INVALID_SOCKET)
    {
        cerr << "Can't create a socket! Quitting" << endl;
        WSACleanup();
        return 1;
    }

    // Assign Ip and port
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(8080); // chọn port 8080
    hint.sin_addr.S_un.S_addr = INADDR_ANY;
    bind(listening, (sockaddr*)&hint, sizeof(hint));

    // Tell Winsock the socket is for listening 
    listen(listening, SOMAXCONN);

    // Create the master file descriptor set and zero it
    fd_set master;
    FD_ZERO(&master);

    // Add our first socket that we're interested in interacting with; the listening socket!
    // It's important that this socket is added for our server or else we won't 'hear' incoming
    // connections 
    FD_SET(listening, &master);

    //// this will be changed by the \quit command (see below, bonus not in video!)
    //bool running = true;
    while (true)
    {
        fd_set copy = master;

        // Kiểm tra các socket đã sẵn sàng để giao tiếp
        int socketCount = select(0, &copy, nullptr, nullptr, nullptr);

        // Duyệt qua các socket sẵn sàng
        for (int i = 0; i < socketCount; i++)
        {
            SOCKET sock = copy.fd_array[i];

            // Kiểm tra xem có kết nối mới đến hay không
            if (sock == listening)
            {
                // Chấp nhận kết nối mới
                SOCKET client = accept(listening, nullptr, nullptr);

                // Thêm socket kết nối mới vào tập hợp master
                FD_SET(client, &master);

                // Gửi tin nhắn chào mừng tới client vừa kết nối
                string welcomeMsg = "Welcome to the Awesome Chat Server!\r\n";
                send(client, welcomeMsg.c_str(), welcomeMsg.size() + 1, 0);

                // Tạo một luồng riêng để xử lý tin nhắn từ client này
                thread clientThread(ClientHandler, client, ref(master), listening);
                clientThread.detach();
            }
        }
    }

    // close socket 
    FD_CLR(listening, &master);
    closesocket(listening);
    WSACleanup();

    return 0;
}
