#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <iomanip> 
#include <algorithm>
#include "protocol.h"

#define SERV_PORT 3000

using namespace std;

vector<string> data_logs;
vector<string> alert_logs;
vector<uint8_t> current_gardens;
vector<uint8_t> available_devices;
vector<uint8_t> current_devices;


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
            available_devices.clear();
            for (int i = 0; i < packet.data.scan_res.num_devices; ++i) {
                cout << "Device ID: " << static_cast<int>(packet.data.scan_res.device_ids[i]) << "\n";
                available_devices.push_back(packet.data.scan_res.device_ids[i]);
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

bool client_info(int sockfd, uint32_t token) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // --- Gửi Info Request ---
    packet_len = serialize_info_request(token, send_buffer);
    print_buffer("Client send: Info Request", send_buffer, packet_len);

    if (send(sockfd, send_buffer, packet_len, 0) <= 0) {
        cerr << "Failed to send Info Request.\n";
        return false;
    }

    // --- Nhận Info Response ---
    packet_len = recv(sockfd, recv_buffer, MAX_BUFFER_SIZE, 0);
    if (packet_len <= 0) {
        cerr << "Server disconnected.\n";
        return false;
    }

    print_buffer("Client receive: Info Response", recv_buffer, packet_len);

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) != 0) {
        cerr << "Failed to deserialize Info Response.\n";
        return false;
    }

    switch (packet.type) {
        case MSG_TYPE_INFO_SERVER: {
            InfoResponse& info = packet.data.info_res;

            cout << "INFO RESPONSE: Found " << (int)info.num_gardens << " garden(s)\n";
            current_gardens.clear();
            for (int i = 0; i < info.num_gardens; ++i) {
                const GardenInfo& g = info.gardens[i];
                current_gardens.push_back(info.gardens[i].garden_id);
                cout << "\nGarden ID: " << (int)g.garden_id
                     << " | Devices: " << (int)g.num_devices << "\n";

                for (int d = 0; d < g.num_devices; ++d) {
                    cout << "  - Device ID: "
                         << (int)g.devices[d].device_id << "\n";
                }
            }

            cout << endl;
            break;
        }

        case MSG_TYPE_CMD_RESPONSE: {
            cout << "Info request failed. Server returned status: ";
            print_status_message(packet.data.cmd_response.status_code);
            break;
        }

        default:
            cout << "Unexpected packet type: " << (int)packet.type << endl;
            break;
    }

    return true;
}

bool client_add_garden(int sockfd, uint32_t token) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    if (current_gardens.empty()) {
        cout << "No Gardens available.\n";
    }
    else{
        cout << "Current Gardens: ";
        for (auto gid : current_gardens) cout << (int)gid << " ";
        cout << "\n";
    }

    uint32_t garden_id;
    cout << "Enter new Garden ID(or '0' to cancel) : ";
    cin >> garden_id;
    if(garden_id == 0){
        cout << "Cancelled adding Garden.\n";
        return false;
    }
    cin.ignore(); // bỏ ký tự newline

    packet_len = serialize_garden_add(token, static_cast<uint8_t>(garden_id), send_buffer);
    send(sockfd, send_buffer, packet_len, 0);
    print_buffer("Client send: Garden Add Request", send_buffer, packet_len);

    // nhận response
    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0) {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Garden Add Response", recv_buffer, packet_len);

    if (packet_len > 0) {
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
            if (packet.type == MSG_TYPE_CMD_RESPONSE) {
                int status_code = packet.data.cmd_response.status_code;
                print_status_message(status_code);
                if(status_code == STATUS_OK){
                    current_gardens.push_back(garden_id);
                }
            } else {
                cout << "Unexpected response type.\n";
            }
        }
    }
    return true;
}

bool client_add_device(int sockfd, uint32_t token) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    if (current_gardens.empty()) {
        cout << "No Gardens available. Please add a Garden first.\n";
        return false;
    }

    cout << "Available Gardens: ";
    for (auto gid : current_gardens) cout << (int)gid << " ";
    cout << "\n";

    uint8_t garden_id, dev_id;
    int g, d;
    cout << "Enter Garden ID to add device to(or '0' to cancel) : ";
    cin >> g; 
    if(g == 0){
        cout << "Cancelled adding Device.\n";
        return false;
    }
    garden_id = static_cast<uint8_t>(g);

    if (available_devices.empty()) {
        cout << "No Devices available.\n";
        return false;
    }

    cout << "Available Devices: ";
    for (auto devid : available_devices) cout << (int)devid << " ";
    cout << "\n";

    cout << "Enter new Device ID(or '0' to cancel) : ";
    cin >> d; 
    if(d == 0){
        cout << "Cancelled adding Device.\n";
        return false;
    }
    dev_id = static_cast<uint8_t>(d);
    cin.ignore();

    packet_len = serialize_device_add(token, garden_id, dev_id, send_buffer);
    send(sockfd, send_buffer, packet_len, 0);
    print_buffer("Client send: Device Add Request", send_buffer, packet_len);

    // Nhận response
    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0) {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Device Add Response", recv_buffer, packet_len);
    if (packet_len > 0) {
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
            if (packet.type == MSG_TYPE_CMD_RESPONSE) {
                int status_code = packet.data.cmd_response.status_code;
                print_status_message(status_code);
                if(status_code == STATUS_OK){
                    current_gardens.push_back(garden_id);
                    find(available_devices.begin(), available_devices.end(), dev_id);
                }
            } else {
                cout << "Unexpected response type.\n";
            }
        }
    }
    return true;
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
    // ===============================================
    // 1. Đăng nhập trước, không vào menu nếu chưa login
    // ==============================================

    cout << "Logging in...\n";
    while (!client_login(sockfd, token)) {
        cout << "Login failed. Retrying...\n";
        sleep(1);
    }

    cout << "Login success! Token = " << token << endl;

    // ===============================================
    // 2. Tự động scan và info 1 lần ngay sau khi login
    // ===============================================

    cout << "Performing initial scan...\n";
    // Sau khi login, tự động scan
    client_scan(sockfd, token);

    // Lấy danh sách Garden hiện tại
    client_info(sockfd, token);
    // ===============================================
    // 3. Bắt đầu UI shell + select()
    // ===============================================
    fd_set readfds;
    int maxfd = max(sockfd, STDIN_FILENO);

    while (true) {
        cout << "\n==== MENU ====\n";
        cout << "1. Scan devices\n";
        cout << "2. Get info\n";
        cout << "3. Exit\n";
        cout << "4. View DATA logs\n";
        cout << "5. View ALERT logs\n";
        cout << "6. Add Garden\n";
        cout << "7. Add Device\n";
        cout << "Your choice: ";
        cout.flush();

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);  // đọc input từ user
        FD_SET(sockfd, &readfds);        // đọc dữ liệu server trả về

        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0) {
            perror("select");
            break;
        }

        // =============================
        // 4. Nhận INPUT từ người dùng
        // =============================
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            int cmd;
            cin >> cmd;

            switch (cmd) {
                case 1:
                    client_scan(sockfd, token);
                    break;
                case 2:
                    client_info(sockfd, token);
                    break;
                case 3:{
                    cout << "Bye!\n";
                    return 0;
                }
                case 4:
                    cout << "\n===== DATA LOGS =====\n";
                    for (auto& s : data_logs) cout << s << "\n";
                    cout << "===== END DATA LOGS =====\n";
                    break;
                case 5:
                    cout << "\n===== ALERT LOGS =====\n";
                    for (auto& s : alert_logs) cout << s << "\n";
                    cout << "===== END ALERT LOGS =====\n";
                    break;
                case 6:
                    if (!client_add_garden(sockfd, token))
                        continue;
                    break;
                case 7:
                    if (!client_add_device(sockfd, token))
                        continue;
                    break;
                default:
                    cout << "Invalid command.\n";
                    break;
            }
        }

        // =============================
        // 5. Nhận PACKET từ server
        // =============================
        if (FD_ISSET(sockfd, &readfds)) {
            uint8_t recv_buffer[MAX_BUFFER_SIZE];
            int packet_len;
            memset(recv_buffer, 0, sizeof(recv_buffer));
            packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);

            if (packet_len <= 0) {
                cout << "Server disconnected.\n";
                break;
            }

            ParsedPacket packet; 
            if (deserialize_packet(recv_buffer, packet_len, &packet) == 0){
                switch (packet.type) {
                    case MSG_TYPE_DATA: {
                        string msg = "[DATA] received data packet";
                        cout << "\n" << msg << "\n";
                        data_logs.push_back(msg);
                        break;
                    }

                    case MSG_TYPE_ALERT: {
                        string msg = "[ALERT] alert triggered";
                        cout << "\n" << msg << "\n";
                        alert_logs.push_back(msg);
                        break;
                    }

                    default:
                        break;
            }
            }
            
        }
    }
    close(sockfd);
    return 0;
}
