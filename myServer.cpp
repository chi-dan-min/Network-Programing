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

// --- Data structures ---
vector<App> apps;
mutex apps_mutex;

map<string, string> app_credentials;          // AppID -> password
mutex credentials_mutex;

map<string, vector<uint8_t>> gardens;         // AppID -> list of GardenID
mutex gardens_mutex;

map<uint8_t, uint8_t> device_to_garden;       // DeviceID -> GardenID
mutex devices_mutex;

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

vector<uint8_t> get_unassigned_devices_string() {
    vector<uint8_t> unassigned;

    {
        lock_guard<mutex> lock(devices_mutex);
        for (const auto& [deviceID, gardenID] : device_to_garden) {
            if (gardenID == 0) { // 0 nghĩa là chưa thuộc garden nào
                unassigned.push_back(deviceID);
            }
        }
    }

    return unassigned;
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

void handle_scan_request(int client_fd, const ScanRequest& req,
                         uint8_t* send_buffer, const uint8_t* recv_buffer,
                         int& packet_len){
    cout << "Handling scan request from token: " << req.token << endl;
    print_buffer("Server receive: Scan Request", recv_buffer, sizeof(recv_buffer));

    App* app = findAppByToken(req.token);
    if (!app) {
        packet_len = serialize_cmd_response(STATUS_ERR_INVALID_TOKEN, send_buffer);
        send(client_fd, send_buffer, packet_len, 0);
        return;
    }

    vector<uint8_t> unassigned = get_unassigned_devices_string();

    packet_len = serialize_scan_response(
        unassigned.size(), // số lượng device
        unassigned.data(), // con trỏ const uint8_t*
        send_buffer
    );

    print_buffer("Server send: Scan Response", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);

    memset(send_buffer, 0, sizeof(send_buffer));
}

void handle_info_request(int client_fd, const InfoRequest& req,
                         uint8_t* send_buffer, const uint8_t* recv_buffer,
                         int& packet_len){
    cout << "Handling info request from token: " << req.token << endl;
    print_buffer("Server receive: Info Request", recv_buffer, sizeof(recv_buffer));

    // --- 1. Kiểm tra token ---
    App* app = findAppByToken(req.token);
    if (!app) {
        packet_len = serialize_cmd_response(STATUS_ERR_INVALID_TOKEN, send_buffer);
        print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
        memset(send_buffer, 0, sizeof(send_buffer));
        return;
    }

    string appID = app->appID;

    // --- 2. Lấy danh sách garden của App ---
    vector<uint8_t> gardenList;
    {
        lock_guard<mutex> lock(gardens_mutex);
        if (gardens.find(appID) != gardens.end()) {
            gardenList = gardens[appID];
        }
    }

    uint8_t numGardens = gardenList.size();
    if (numGardens > MAX_GARDENS) numGardens = MAX_GARDENS;

    // Tạo InfoResponse theo đúng struct
    InfoResponse resp;
    resp.num_gardens = numGardens;

    // --- 3. Lấy device thuộc mỗi garden ---
    for (int i = 0; i < numGardens; i++) {
        uint8_t gid = gardenList[i];
        resp.gardens[i].garden_id = gid;

        vector<uint8_t> devices;

        {
            lock_guard<mutex> lock(devices_mutex);
            for (auto& [deviceID, gardenID] : device_to_garden) {
                if (gardenID == gid) {
                    devices.push_back(deviceID);
                }
            }
        }

        uint8_t ndev = devices.size();
        if (ndev > MAX_DEVICES_PER_GARDEN) 
            ndev = MAX_DEVICES_PER_GARDEN;

        resp.gardens[i].num_devices = ndev;

        for (int d = 0; d < ndev; d++) {
            resp.gardens[i].devices[d].device_id = devices[d];
        }
    }

    // --- 4. Serialize và gửi cho client ---
    packet_len = serialize_info_response(&resp, send_buffer);

    print_buffer("Server send: Info Response", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);

    memset(send_buffer, 0, sizeof(send_buffer));
}

void handle_garden_add_request(int client_fd, const GardenAdd& req,
                               uint8_t* send_buffer, const uint8_t* recv_buffer, int& packet_len){
    cout << "Handling info request from token: " << req.token << endl;
    print_buffer("Server receive: Garden Add Request", recv_buffer, sizeof(recv_buffer));

    App* app = findAppByToken(req.token);
    if (!app) {
        packet_len = serialize_cmd_response(STATUS_ERR_INVALID_TOKEN, send_buffer);
        print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
        return;
    }

    string appID = app->appID;
    uint8_t garden_id = req.garden_id;

    {
        lock_guard<mutex> lock(gardens_mutex);
        vector<uint8_t>& appGardens = gardens[appID];

        // kiểm tra xem garden đã tồn tại chưa
        if (find(appGardens.begin(), appGardens.end(), garden_id) != appGardens.end()) {
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_GARDEN, send_buffer);
        } else {
            appGardens.push_back(garden_id);
            packet_len = serialize_cmd_response(STATUS_OK, send_buffer);
            cout << "Garden added: AppID=" << appID << ", GardenID=" << (int)garden_id << endl;
        }
    }

    print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);
}

void handle_device_add_request(int client_fd, const DeviceAdd& req,
                               uint8_t* send_buffer, const uint8_t* recv_buffer, int& packet_len){
    cout << "Handling info request from token: " << req.token << endl;
    print_buffer("Server receive: Device Add Request", recv_buffer, sizeof(recv_buffer));
    App* app = findAppByToken(req.token);
    if (!app) {
        packet_len = serialize_cmd_response(STATUS_ERR_INVALID_TOKEN, send_buffer);
        print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
        return;
    }

    string appID = app->appID;
    uint8_t garden_id = req.garden_id;
    uint8_t device_id = req.dev_id;

    {
        lock_guard<mutex> lock(gardens_mutex);
        if (gardens.find(appID) == gardens.end() ||
            find(gardens[appID].begin(), gardens[appID].end(), garden_id) == gardens[appID].end()) 
        {
            // garden chưa tồn tại
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_GARDEN, send_buffer);
            print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
            send(client_fd, send_buffer, packet_len, 0);
            return;
        }
    }

    {
        lock_guard<mutex> lock(devices_mutex);
        // Kiểm tra device đã tồn tại chưa
        if (device_to_garden.find(device_id) != device_to_garden.end() &&
            device_to_garden[device_id] != 0)
        {
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_DEVICE, send_buffer);
        } else {
            device_to_garden[device_id] = garden_id;
            packet_len = serialize_cmd_response(STATUS_OK, send_buffer);
            cout << "Device added: DeviceID=" << (int)device_id 
                 << " -> GardenID=" << (int)garden_id << endl;
        }
    }

    print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);
}

void handle_garden_delete_request(int client_fd, const GardenDel& req,
                                  uint8_t* send_buffer, const uint8_t* recv_buffer, int& packet_len){
    cout << "Handling garden delete request from token: " << req.token << endl;
    print_buffer("Server receive: Garden Delete Request", recv_buffer, sizeof(recv_buffer));

    App* app = findAppByToken(req.token);
    if (!app) {
        packet_len = serialize_cmd_response(STATUS_ERR_INVALID_TOKEN, send_buffer);
        print_buffer("Server send: CMD_RESPONSE (Invalid Token)", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
        return;
    }

    string appID = app->appID;
    uint8_t garden_id = req.garden_id;

    // Kiểm tra xem garden có rỗng không
    bool is_empty = true;
    {
        lock_guard<mutex> lock(devices_mutex);
        // Duyệt qua tất cả device xem có cái nào đang thuộc garden này không
        for (auto const& [dev_id, gid] : device_to_garden) {
            if (gid == garden_id) {
                is_empty = false;
                break; // Tìm thấy một device, không cần tìm nữa
            }
        }
    } 

    // Nếu không rỗng, trả về lỗi
    if (!is_empty) {
        cout << "Attempt to delete non-empty garden: AppID=" << appID 
             << ", GardenID=" << (int)garden_id << endl;
        packet_len = serialize_cmd_response(STATUS_ERR_GARDEN_NOT_EMPTY, send_buffer);
        print_buffer("Server send: CMD_RESPONSE (Garden Not Empty)", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
        return;
    }

    // Garden đã rỗng
    {
        lock_guard<mutex> lock(gardens_mutex);
        if (gardens.find(appID) == gardens.end()) {
            //App tồn tại nhưng chưa có entry nào trong `gardens`
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_GARDEN, send_buffer);
        } else {
            vector<uint8_t>& appGardens = gardens[appID];
            
            // Tìm garden trong vector của app
            auto it = find(appGardens.begin(), appGardens.end(), garden_id);

            if (it == appGardens.end()) {
                packet_len = serialize_cmd_response(STATUS_ERR_INVALID_GARDEN, send_buffer);
            } else {
                appGardens.erase(it);
                packet_len = serialize_cmd_response(STATUS_OK, send_buffer);
                cout << "Garden deleted: AppID=" << appID << ", GardenID=" << (int)garden_id << endl;
            }
        }
    }

    print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);
}

void handle_device_delete_request(int client_fd, const DeviceDel& req,
                                  uint8_t* send_buffer, const uint8_t* recv_buffer, int& packet_len){
    cout << "Handling device delete request from token: " << req.token << endl;
    print_buffer("Server receive: Device Delete Request", recv_buffer, sizeof(recv_buffer));

    App* app = findAppByToken(req.token);
    if (!app) {
        packet_len = serialize_cmd_response(STATUS_ERR_INVALID_TOKEN, send_buffer);
        print_buffer("Server send: CMD_RESPONSE (Invalid Token)", send_buffer, packet_len);
        send(client_fd, send_buffer, packet_len, 0);
        return;
    }

    string appID = app->appID;
    uint8_t garden_id = req.garden_id;
    uint8_t device_id = req.dev_id;

    //Kiểm tra xem garden này có thuộc app này không 
    {
        lock_guard<mutex> lock(gardens_mutex);
        if (gardens.find(appID) == gardens.end() ||
            find(gardens[appID].begin(), gardens[appID].end(), garden_id) == gardens[appID].end()) 
        {
            // garden chưa tồn tại (hoặc không thuộc app này)
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_GARDEN, send_buffer);
            print_buffer("Server send: CMD_RESPONSE (Invalid Garden)", send_buffer, packet_len);
            send(client_fd, send_buffer, packet_len, 0);
            return;
        }
    }

    // Xóa device (gán về 0)
    {
        lock_guard<mutex> lock(devices_mutex);
        
        // Kiểm tra xem device có tồn tại và đang được gán không
        if (device_to_garden.find(device_id) == device_to_garden.end() ||
            device_to_garden[device_id] == 0)
        {
            // Device không tồn tại, hoặc đã được tự do
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_DEVICE, send_buffer);
        }
        // Kiểm tra xem device có ĐÚNG là thuộc garden này không
        else if (device_to_garden[device_id] != garden_id)
        {
            // Lỗi: Client cố xóa device khỏi garden nó không thuộc về
            cout << "Device " << (int)device_id << " is in garden " << (int)device_to_garden[device_id]  
                << ", not in " << (int)garden_id << endl;
            packet_len = serialize_cmd_response(STATUS_ERR_INVALID_DEVICE, send_buffer);
        }
        else 
        {
            // Device tồn tại và đúng là thuộc garden này.
            // "Xóa" nó bằng cách gán về 0 (unassigned)
            device_to_garden[device_id] = 0; 
            packet_len = serialize_cmd_response(STATUS_OK, send_buffer);
            cout << "Device deleted: DeviceID=" << (int)device_id 
                 << " removed from GardenID=" << (int)garden_id << endl;
        }
    }

    print_buffer("Server send: CMD_RESPONSE", send_buffer, packet_len);
    send(client_fd, send_buffer, packet_len, 0);
}

void client_handler(int client_fd) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int packet_len;
    uint32_t token = 0;

    while (true) {
        packet_len = recv(client_fd, recv_buffer, MAX_BUFFER_SIZE, 0);
        if (packet_len > 0) {
            ParsedPacket packet;
            cout << "Client " << client_fd << " request\n";
            if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
                switch (packet.type) {
                    case MSG_TYPE_CONNECT_CLIENT:
                        handle_connect_request(client_fd, packet.data.connect_req, send_buffer,recv_buffer, packet_len, token);
                        break;
                    case MSG_TYPE_SCAN_CLIENT: 
                        handle_scan_request(client_fd, packet.data.scan_req, send_buffer,recv_buffer, packet_len);
                        break;
                    case MSG_TYPE_INFO_CLIENT:
                        handle_info_request(client_fd, packet.data.info_req, send_buffer, recv_buffer, packet_len);
                        break;
                    case MSG_TYPE_GARDEN_ADD:
                        handle_garden_add_request(client_fd, packet.data.garden_add, send_buffer, recv_buffer, packet_len);
                        break;
                    case MSG_TYPE_DEVICE_ADD:
                        handle_device_add_request(client_fd, packet.data.device_add, send_buffer, recv_buffer, packet_len);
                        break;
                    case MSG_TYPE_GARDEN_DEL:
                        handle_garden_delete_request(client_fd, packet.data.garden_del, send_buffer, recv_buffer, packet_len);
                        break;
                    case MSG_TYPE_DEVICE_DEL:
                        handle_device_delete_request(client_fd, packet.data.device_del, send_buffer, recv_buffer, packet_len);
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
                
        }else if (packet_len == 0) {
            //CLIENT NGẮT KẾT NỐI (GRACEFUL)
            cout << "Client " << client_fd << " disconnected gracefully.\n";
            break; 

        } else { // packet_len < 0
            if (errno == ECONNRESET) {
                cout << "Client " << client_fd << " connection reset by peer.\n";
            } else {
                perror("recv failed");
            }
            break; 
        }
    } 
    
    if (token != 0) { 
        App* app = findAppByToken(token);
        if (app)
            app->token = 0; 
    }
    cout << "Client " << client_fd << " exit\n";

    close(client_fd);
}

void seed() {
    // --- 1. Read apps.txt ---
    ifstream apps_file("apps.txt");
    if (!apps_file) {
        cerr << "Cannot open apps.txt!" << endl;
    } else {
        string line;
        while (getline(apps_file, line)) {
            if (line.empty()) continue;
            istringstream iss(line);
            string appID, password;
            if (iss >> appID >> password) {
                lock_guard<mutex> lock(credentials_mutex);
                app_credentials[appID] = password;
                cout << "App loaded: " << appID << ", Password: " << password << endl;
            }
        }
        apps_file.close();
    }

    // --- 2. Read garden.txt ---
    ifstream garden_file("garden.txt");
    if (!garden_file) {
        cerr << "Cannot open garden.txt!" << endl;
    } else {
        string line;
        while (getline(garden_file, line)) {
            if (line.empty()) continue;
            istringstream iss(line);
            string appID;
            uint32_t gardenID;
            if (iss >> appID >> gardenID) {
                lock_guard<mutex> lock(gardens_mutex);
                gardens[appID].push_back(static_cast<uint8_t>(gardenID));
                cout << "Garden loaded: AppID=" << appID << ", GardenID=" << gardenID << endl;
            }
        }
        garden_file.close();
    }

    // --- 3. Read device.txt ---
    ifstream device_file("device.txt");
    if (!device_file) {
        cerr << "Cannot open device.txt!" << endl;
    } else {
        string line;
        while (getline(device_file, line)) {
            if (line.empty()) continue;
            istringstream iss(line);
            uint32_t deviceID, gardenID;
            if (iss >> deviceID >> gardenID) {
                lock_guard<mutex> lock(devices_mutex);
                device_to_garden[static_cast<uint8_t>(deviceID)] = static_cast<uint8_t>(gardenID);
                cout << "Device loaded: DeviceID=" << deviceID << ", GardenID=" << gardenID << endl;
            }
        }
        device_file.close();
    }
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
