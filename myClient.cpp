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

void print_status_message(uint8_t status_code) {
    switch (status_code) {
        case STATUS_OK:
            cout << "[STATUS_OK] Success\n";
            break;

        case STATUS_ERR_FAILED:
            cout << "[STATUS_ERR_FAILED] General error, unspecified failure\n";
            break;

        case STATUS_ERR_INVALID_TOKEN:
            cout << "[STATUS_ERR_INVALID_TOKEN] Invalid or expired token\n";
            break;

        case STATUS_ERR_INVALID_DEVICE:
            cout << "[STATUS_ERR_INVALID_DEVICE] Device ID not found or offline\n";
            break;

        case STATUS_ERR_INVALID_PARAM:
            cout << "[STATUS_ERR_INVALID_PARAM] Invalid parameter ID or value\n";
            break;

        case STATUS_ERR_INVALID_SLOT:
            cout << "[STATUS_ERR_INVALID_SLOT] Invalid schedule slot ID\n";
            break;

        case STATUS_ERR_WRONG_PASSWORD:
            cout << "[STATUS_ERR_WRONG_PASSWORD] Incorrect password\n";
            break;

        case STATUS_ERR_MALFORMED:
            cout << "[STATUS_ERR_MALFORMED] Malformed packet sent by client\n";
            break;

        case STATUS_ERR_INVALID_GARDEN:
            cout << "[STATUS_ERR_INVALID_GARDEN] Garden ID does not exist or duplicate\n";
            break;

        case STATUS_ERR_UNKNOW:
            cout << "[STATUS_ERR_UNKNOWN] Unknown packet type\n";
            break;

        default:
            cout << "[UNKNOWN_STATUS] Unrecognized status code: "
                 << static_cast<int>(status_code) << "\n";
            break;
    }
}

bool client_scan(int sockfd, uint32_t token) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // --- Gửi Scan Request ---
    packet_len = serialize_scan_request(token, send_buffer);
    print_buffer("Client send: Scan Request", send_buffer, packet_len);
    if (send(sockfd, send_buffer, packet_len, 0) <= 0) {
        cerr << "Failed to send Scan Request.\n";
        return false;
    }

    // --- Nhận Scan Response ---
    packet_len = recv(sockfd, recv_buffer, MAX_BUFFER_SIZE, 0);
    if (packet_len <= 0) {
        cerr << "Server disconnected.\n";
        return false;
    }

    print_buffer("Client receive: Scan Response", recv_buffer, packet_len);

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) != 0) {
        cerr << "Failed to deserialize Scan Response.\n";
        return false;
    }

    switch (packet.type) {
        case MSG_TYPE_SCAN_SERVER: {
            cout << "Scan successful. Devices found: "
                 << (int)packet.data.scan_res.num_devices << "\n";
            for (int i = 0; i < packet.data.scan_res.num_devices; ++i) {
                cout << "Device ID: " << static_cast<int>(packet.data.scan_res.device_ids[i]) << "\n";
            }
            cout << endl;
            break;
        }
        case MSG_TYPE_CMD_RESPONSE: {
            cout << "Scan failed. Server returned status: ";
            print_status_message(packet.data.cmd_response.status_code);
            break;
        }
        default: {
            cout << "Unexpected packet type: " << (int)packet.type << endl;
            break;
        }
    }

    return true;
}

bool client_login(int sockfd, uint32_t& token) {
    string myAppID, myPassword;
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    while (true) {
        cout << "Enter your AppID: ";
        cin >> myAppID;
        cout << "Enter your password: ";
        cin >> myPassword;

        // --- Gửi Connect Request ---
        packet_len = serialize_connect_request(myAppID.c_str(), myPassword.c_str(), send_buffer);
        print_buffer("Client send: Connect Request", send_buffer, packet_len);
        send(sockfd, send_buffer, packet_len, 0);
        memset(send_buffer, 0, sizeof(send_buffer));

        // --- Nhận Connect Response ---
        packet_len = recv(sockfd, recv_buffer, MAX_BUFFER_SIZE, 0);
        if (packet_len <= 0) {
            cerr << "Server disconnected.\n";
            return false;
        }

        print_buffer("Client receive: Connect Response", recv_buffer, packet_len);

        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) != 0) {
            cerr << "Failed to deserialize packet.\n";
            memset(recv_buffer, 0, sizeof(recv_buffer));
            continue;
        }

        cout << "Packet type received: " << (int)packet.type << endl;

        switch (packet.type) {
            case MSG_TYPE_CONNECT_SERVER: {
                token = packet.data.connect_res.token;
                cout << "Login successful! Received Token: " << token << "\n\n";
                return true;
            }

            case MSG_TYPE_CMD_RESPONSE: {
                cout << "Login failed. Server returned status: ";
                print_status_message(packet.data.cmd_response.status_code);
                cout << "\n";
                break; // cho phép nhập lại
            }

            default: {
                cout << "Unexpected packet type: " << (int)packet.type << endl;
                break;
            }
        }

        memset(recv_buffer, 0, sizeof(recv_buffer));
    }
}


int main(int argc, char** argv) {
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
        while(!client_login(sockfd, token)){
            // lặp cho đến khi login thành công
        }

        // Scan devices sau khi login
        client_scan(sockfd, token);
    }
    close(sockfd);
    return 0;
}
