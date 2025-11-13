#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <cstdint>
#include <iomanip> 
#include "protocol.h"

#define SERV_PORT 3000

using namespace std;
//debug function
void print_buffer(const char* title, const uint8_t* buffer, int len) {
    cout << title << " (" << len << " bytes):\n";
    for (int i = 0; i < len; ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') 
             << static_cast<int>(buffer[i]) << " ";
    }
    cout << "\n\n";

    // reset lại decimal để không ảnh hưởng các cout sau
    cout << dec;
}

int main(int argc, char** argv) {
    string myAppID, myPassword;
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int packet_len;
    uint32_t token;

    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <server IP address>" << endl;
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 2;
    }

    sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0) {
        cerr << "Invalid address: " << argv[1] << endl;
        return 3;
    }

    if (connect(sockfd, (sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        return 4;
    }
    cout << "Connected to server " << argv[1] << ":" << SERV_PORT << endl;
    while(true){
        cout << "Enter your AppID: ";
        cin >> myAppID;
        cout << "Enter your password: ";
        cin >> myPassword;

        packet_len = serialize_connect_request(myAppID.c_str(), myPassword.c_str(), send_buffer);
        print_buffer("Client send: Connect Request", send_buffer, packet_len);
        send(sockfd, send_buffer, packet_len, 0);
        memset(send_buffer, 0, sizeof(send_buffer));


        packet_len = recv(sockfd, recv_buffer, MAX_BUFFER_SIZE, 0);
        print_buffer("Client receive: Connect Response", recv_buffer, packet_len);
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
            if (packet.type == MSG_TYPE_CONNECT_SERVER) {
                token = packet.data.connect_res.token;
                cout << "Token:" << token << endl;
            }
        }
        memset(recv_buffer, 0, sizeof(recv_buffer));
    }
    

    close(sockfd);
    return 0;
}
