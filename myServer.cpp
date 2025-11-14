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
#include "protocol.h"
#define SERV_PORT 3000
#define MAX_CLIENTS 5
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

struct App{
    string appID;
    uint32_t token;
};

vector<App> apps;
mutex apps_mutex;

map<string, string> app_credentials;
mutex credentials_mutex;
App* findAppByToken(uint32_t token) {
    lock_guard<mutex> lock(apps_mutex);
    for (int i = 0; i < apps.size(); i++) {
        if (apps[i].token == token)
            return &apps[i];
    }
    return nullptr;
}

App* findAppByAppID(const string& appID){
    lock_guard<mutex> lock(apps_mutex);
    for (int i = 0; i < apps.size(); i++) {
        if (apps[i].appID == appID)
            return &apps[i];
    }
    return nullptr;
}

uint32_t random_token() {
    uint32_t t = 0;
    t |= (rand() & 0xFF) << 24;
    t |= (rand() & 0xFF) << 16;
    t |= (rand() & 0xFF) << 8;
    t |= (rand() & 0xFF);
    return t;
}

uint32_t generate_unique_token() {
    uint32_t token;
    do {
        token = random_token();
    } while (findAppByToken(token) != nullptr);
    return token;
}

bool authenticate_app(const string& appID, const string& password) {
    lock_guard<mutex> lock(credentials_mutex);
    auto it = app_credentials.find(appID);
    if (it == app_credentials.end()) return false;
    return it->second == password;
}

void handle_connect_request(int client_fd, const ConnectRequest& req, uint8_t* send_buffer, const uint8_t* recv_buffer, int& packet_len, uint32_t& token) {
    print_buffer("Server receive: Connect Request", recv_buffer, sizeof(recv_buffer));
    cout << "Client " << client_fd << " request\n";
    cout << "AppID: " << req.appID << endl;
    cout << "Password: " << req.password << "\n\n";

    if (authenticate_app(req.appID, req.password)) {
        App newApp;
        newApp.appID = req.appID;
        token = generate_unique_token();
        newApp.token = token;

        cout << "Assigned token: " << token << endl;

        {
            lock_guard<mutex> lock(apps_mutex);
            apps.push_back(newApp);
        }

        packet_len = serialize_connect_response(token, send_buffer);
        print_buffer("Server send: Connect Response", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);

    } else {
        // Sai mật khẩu → gửi CMD_RESPONSE
        packet_len = serialize_cmd_response(STATUS_ERR_WRONG_PASSWORD, send_buffer);
        print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
    }

    memset(send_buffer, 0, sizeof(send_buffer));
}

void handle_unknown_packet(int client_fd, uint8_t type, uint8_t* send_buffer, int& packet_len) {
    packet_len = serialize_cmd_response(STATUS_ERR_UNKNOW, send_buffer);
    print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);

    memset(send_buffer, 0, sizeof(send_buffer));
    cout << "Unknown type: " << (int)type << endl;
}


void client_handler(int client_fd) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int packet_len;
    uint32_t token = 30;

    while ((packet_len = recv(client_fd, recv_buffer, MAX_BUFFER_SIZE, 0)) > 0) {
    ParsedPacket packet;

        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
            switch (packet.type) {
                case MSG_TYPE_CONNECT_CLIENT:
                    handle_connect_request(client_fd, packet.data.connect_req, send_buffer,recv_buffer, packet_len, token);
                    break;

                default:
                    handle_unknown_packet(client_fd, packet.type, send_buffer, packet_len);
                    break;
            }
        } else {
            // Deserialize thất bại → gửi CMD_RESPONSE lỗi
            packet_len = serialize_cmd_response(STATUS_ERR_MALFORMED, send_buffer);
            print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
            send(client_fd, send_buffer, packet_len, 0);
            memset(send_buffer, 0, sizeof(send_buffer));
        }

        memset(recv_buffer, 0, sizeof(recv_buffer));
    }

    {
        lock_guard<mutex> lock(apps_mutex);
        App* app = findAppByToken(token);
        if (app)
            app->token = 0; 
    }

    close(client_fd);
}


void seed(){
    ifstream infile("apps.txt"); 

    if (!infile) {
        cerr << "Cannot open file!" << endl;
        return;
    }

    string line;
    while (getline(infile, line)) {
        istringstream iss(line);
        string appID, password;
        if (iss >> appID >> password) {
            cout << "AppID: " << appID << ", Password: " << password << endl;
        }
        app_credentials[appID] = password;
    }

    infile.close(); // đóng file

}

int main() {
    srand(time(nullptr));
    seed();
    int listenfd, connfd;
    socklen_t clilen;
    struct sockaddr_in servaddr{}, cliaddr{};

    // tạo socket
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Problem in creating the socket");
        exit(2);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERV_PORT);

    bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    listen(listenfd, MAX_CLIENTS);

    cout << "Server running...waiting for connections." << endl;

    while (true) {
        clilen = sizeof(cliaddr);
        connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &clilen);
        if (connfd < 0) {
            perror("Accept failed");
            continue;
        }

        cout << "SERVER -> New connection attempt on FD: " << connfd << endl;
        thread t(client_handler, connfd);
        t.detach();
    }

    close(listenfd);
}
