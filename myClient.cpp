#include "myClient.h"

// Singleton logic is in header (static instance)

ClientManager::ClientManager() {}

ClientManager::~ClientManager() {
    disconnect();
}

void ClientManager::disconnect() {
    running = false;
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    if (recv_thread.joinable()) {
        recv_thread.join(); // This might hang if thread is blocked on recv
        // In real app, shutdown(sockfd, SHUT_RDWR) usually unblocks recv
    }
    connected = false;
}

bool ClientManager::connectToServer(const char* ip) {
    if (connected) return true;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return false; }

    sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
        cerr << "Invalid address: " << ip << endl;
        return false;
    }

    if (connect(sockfd, (sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        return false;
    }

    connected = true;
    running = true;
    recv_thread = thread(&ClientManager::recvThreadFunc, this);
    return true;
}

void ClientManager::recvThreadFunc() {
    uint8_t buffer[MAX_BUF];
    while (running && sockfd >= 0) {
        memset(buffer, 0, sizeof(buffer));
        int len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (len <= 0) {
            cout << "\nServer disconnected.\n";
            connected = false;
            running = false;
            // Need to notify main thread?
            break;
        }

        ParsedPacket packet;
        if (deserialize_packet(buffer, len, &packet) == 0) {
            if (packet.type == MSG_TYPE_DATA || packet.type == MSG_TYPE_ALERT) {
                handleAsyncPacket(packet);
            } else {
                print_buffer("Client receive", buffer, len);
                lock_guard<mutex> lock(response_mutex);
                shared_packet = packet;
                has_response = true;
            }
        } else {
            cerr << "Deserialize failed!\n";
        }
    }
}

void ClientManager::handleAsyncPacket(const ParsedPacket &packet) {
    lock_guard<mutex> lock(log_mutex);
    if (packet.type == MSG_TYPE_DATA) {
        IntervalData data = packet.data.interval_data;
        ostringstream oss;
        oss << format_timestamp(data.timestamp); // Just timestamp for column 1? No, we store full string
        // We'll store: "Dev: <id> | Soil: <h>% | N: <n> | P: <p> | K: <k>"
        oss << " Dev:" << (int)data.dev_id 
            << " | Soil:" << (int)data.humidity << "%"
            << " | N:" << (int)data.n_level
            << " | P:" << (int)data.p_level
            << " | K:" << (int)data.k_level;
            
        data_logs.push_back(oss.str());
        cout << "[DATA] " << oss.str() << "\n"; 
    } else if (packet.type == MSG_TYPE_ALERT) {
        Alert alert = packet.data.alert;
        ostringstream oss;
        // Decode Alert Code
        string msg;
        switch(alert.alert_code) {
            case ALERT_WATERING_START: msg = "Watering Started"; break;
            case ALERT_WATERING_END:   msg = "Watering Ended"; break;
            case ALERT_FERTILIZE_START: msg = "Fertilizing Started"; break;
            case ALERT_FERTILIZE_END:   msg = "Fertilizing Ended"; break;
            case ALERT_LIGHTS_ON:      msg = "Lights Turned ON"; break;
            case ALERT_LIGHTS_OFF:     msg = "Lights Turned OFF"; break;
            default: msg = "Unknown Alert Code: " + to_string(alert.alert_code); break;
        }
        
        oss << format_timestamp(alert.timestamp) << " Dev:" << (int)alert.dev_id << " - " << msg;
        alert_logs.push_back(oss.str());
        cout << "[ALERT] " << oss.str() << "\n";
    }
}

bool ClientManager::waitForResponse(ParsedPacket &out_packet) {
    for (int i = 0; i < 300; i++) { // 3 seconds timeout
        {
            lock_guard<mutex> lock(response_mutex);
            if (has_response) {
                out_packet = shared_packet;
                has_response = false;
                return true;
            }
        }
        usleep(10000);
    }
    return false;
}

bool ClientManager::sendRequest(uint8_t* buffer, int len, const char* actionName) {
    lock_guard<mutex> lock(socket_mutex);
    if (send(sockfd, buffer, len, 0) < 0) {
        perror("Send failed");
        return false;
    }
    string title = "Client send: ";
    title += actionName;
    print_buffer(title.c_str(), buffer, len);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_CMD_RESPONSE) {
        int status = packet.data.cmd_response.status_code;
        print_status_message(status);
        return (status == STATUS_OK);
    }
    
    // Some commands might expect other responses (like Info/Scan) handled in their specific functions
    // But this generic helper is best for simple CMD_RESPONSEs.
    // Use overloading or check type in caller.
    return false; 
}


bool ClientManager::login(const string& appID, const string& password) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_connect_request(appID.c_str(), password.c_str(), buffer);
    
    lock_guard<mutex> lock(socket_mutex);
    print_buffer("Client send: Connect Request", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_CONNECT_SERVER) {
        this->token = packet.data.connect_res.token;
        cout << "Login successful! Token: " << token << "\n";
        return true;
    } else if (packet.type == MSG_TYPE_CMD_RESPONSE) {
        print_status_message(packet.data.cmd_response.status_code);
    }
    return false;
}

bool ClientManager::scan(bool log) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_scan_request(token, buffer);

    lock_guard<mutex> lock(socket_mutex);
    if(log) print_buffer("Client send: Scan", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_SCAN_SERVER) {
        if(log) cout << "Scan Found " << (int)packet.data.scan_res.num_devices << " devices.\n";
        available_devices.clear();
        for (int i = 0; i < packet.data.scan_res.num_devices; ++i) {
            available_devices.push_back(packet.data.scan_res.device_ids[i]);
            if(log) cout << " - ID: " << (int)packet.data.scan_res.device_ids[i] << "\n";
        }
        return true;
    }
    return false;
}

bool ClientManager::getInfo(bool log) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_info_request(token, buffer);
    
    lock_guard<mutex> lock(socket_mutex);
    if(log) print_buffer("Client send: Info", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_INFO_SERVER) {
         lastInfo = packet.data.info_res; // Cache it
         InfoResponse &info = lastInfo;
         if(log) {
             cout << "INFO: Found " << (int)info.num_gardens << " garden(s)\n";
             for (int i = 0; i < info.num_gardens; ++i) {
                 const GardenInfo &g = info.gardens[i];
                 cout << " Garden " << (int)g.garden_id << " Devices: " << (int)g.num_devices << "\n";
                 for(int j=0; j<g.num_devices; j++) cout << "   - DevID: " << (int)g.devices[j].device_id << "\n";
             }
         }
         return true;
    }
    return false;
}

bool ClientManager::addGarden(uint32_t gardenID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_garden_add(token, (uint8_t)gardenID, buffer);
    return sendRequest(buffer, len, "Add Garden");
}

bool ClientManager::deleteGarden(uint32_t gardenID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_garden_del(token, (uint8_t)gardenID, buffer);
    return sendRequest(buffer, len, "Delete Garden");
}

bool ClientManager::addDevice(uint8_t gardenID, uint8_t deviceID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_device_add(token, gardenID, deviceID, buffer);
    return sendRequest(buffer, len, "Add Device");
}

bool ClientManager::deleteDevice(uint8_t gardenID, uint8_t deviceID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_device_del(token, gardenID, deviceID, buffer);
    bool ok = sendRequest(buffer, len, "Delete Device");
    if (ok) {
        available_devices.push_back(deviceID); // Return to pool implicitly?
    }
    return ok;
}

bool ClientManager::setDirectPump(uint8_t deviceID, bool turnOn) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_set_direct_pump(token, deviceID, turnOn, buffer);
    return sendRequest(buffer, len, "Set Direct Pump");
}

bool ClientManager::setDirectLight(uint8_t deviceID, bool turnOn) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_set_direct_light(token, deviceID, turnOn, buffer);
    return sendRequest(buffer, len, "Set Direct Light");
}

bool ClientManager::setDirectFert(uint8_t deviceID, bool turnOn) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_set_direct_fert(token, deviceID, turnOn, buffer);
    return sendRequest(buffer, len, "Set Direct Fert");
}

bool ClientManager::setPumpSchedule(uint8_t deviceID, const vector<uint32_t>& timestamps) {
    uint8_t buffer[MAX_BUF];
    int count = timestamps.size();
    if(count > MAX_TIME_STAMP) count = MAX_TIME_STAMP;
    
    // cast vector to array
    uint32_t arr[MAX_TIME_STAMP];
    for(int i=0; i<count; i++) arr[i] = timestamps[i];

    int len = serialize_set_pump_schedule(token, deviceID, (uint8_t)count, arr, buffer);
    return sendRequest(buffer, len, "Set Pump Schedule");
}

bool ClientManager::setLightSchedule(uint8_t deviceID, const vector<uint32_t>& timestamps) {
    uint8_t buffer[MAX_BUF];
    int count = timestamps.size(); // This is total timestamps (ON+OFF pairs)
    if(count > MAX_TIME_STAMP) count = MAX_TIME_STAMP;

    uint32_t arr[MAX_TIME_STAMP];
    for(int i=0; i<count; i++) arr[i] = timestamps[i];

    int len = serialize_set_light_schedule(token, deviceID, (uint8_t)count, arr, buffer);
    return sendRequest(buffer, len, "Set Light Schedule");
}

bool ClientManager::setParameter(uint8_t gardenID, uint8_t deviceID, uint8_t paramID, uint8_t value) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_set_parameter(token, gardenID, deviceID, paramID, value, buffer);
    return sendRequest(buffer, len, "Set Parameter");
}

bool ClientManager::changePassword(const string& appID, const string& oldPass, const string& newPass) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_change_password(token, appID.c_str(), 
                                        (uint8_t)oldPass.length(), oldPass.c_str(), 
                                        newPass.c_str(), buffer);
    return sendRequest(buffer, len, "Change Password");
}

bool ClientManager::getDeviceStatus(uint8_t deviceID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_get_status_request(token, deviceID, buffer);

    lock_guard<mutex> lock(socket_mutex);
    print_buffer("Client send: Get Status", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_STATUS_RESPONSE) {
        lastStatus = packet.data.status_res;
        cout << " [Status Dev " << (int)deviceID << "]\n"
             << "  Pump:  " << (lastStatus.pump_status ? "ON" : "OFF") << "\n"
             << "  Light: " << (lastStatus.light_status ? "ON" : "OFF") << "\n"
             << "  Fert:  " << (lastStatus.fert_status ? "ON" : "OFF") << "\n";
        return true;
    }
    return false;
}

bool ClientManager::getPumpSchedule(uint8_t deviceID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_get_sched_request(token, deviceID, MSG_TYPE_GET_SCHED_PUMP, buffer);

    lock_guard<mutex> lock(socket_mutex);
    print_buffer("Client send: Get Pump Sched", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_SCHED_PUMP_RESPONSE) {
        vector<uint32_t> ts;
        for(int i=0; i<packet.data.set_pump_schedule.quantity_time; i++) {
            ts.push_back(packet.data.set_pump_schedule.time[i]);
        }
        cachedPumpSchedules[deviceID] = ts;
        cout << " [Received Pump Schedule] Count: " << ts.size() << "\n";
        return true;
    }
    return false;
}

bool ClientManager::getLightSchedule(uint8_t deviceID) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_get_sched_request(token, deviceID, MSG_TYPE_GET_SCHED_LIGHT, buffer);

    lock_guard<mutex> lock(socket_mutex);
    print_buffer("Client send: Get Light Sched", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_SCHED_LIGHT_RESPONSE) {
        vector<uint32_t> ts;
        for(int i=0; i<packet.data.set_light_schedule.quantity_time; i++) {
            ts.push_back(packet.data.set_light_schedule.time[i]);
        }
        cachedLightSchedules[deviceID] = ts;
        cout << " [Received Light Schedule] Count: " << ts.size() << "\n";
        return true;
    }
    return false;
}

bool ClientManager::getDeviceParams(uint8_t deviceID, bool log) {
    uint8_t buffer[MAX_BUF];
    int len = serialize_settings_request(token, deviceID, buffer);
    
    lock_guard<mutex> lock(socket_mutex);
    if(log) print_buffer("Client send: Settings Req", buffer, len);
    send(sockfd, buffer, len, 0);

    ParsedPacket packet;
    if (!waitForResponse(packet)) return false;

    if (packet.type == MSG_TYPE_SETTINGS_SERVER) {
        lastSettings = packet.data.setting_response; // Cache it
        SettingsResponse* s = &packet.data.setting_response;
        if (log) {
            cout << " [Settings Dev " << (int)deviceID << "]\n"
                 << "  Power: " << (int)s->power << "%\n"
                 << "  Hmin-Hmax: " << (int)s->Hmin << "-" << (int)s->Hmax << "\n";
        }
        return true;
    }
    return false;
}

const vector<string>& ClientManager::getDataLogs() {
    lock_guard<mutex> lock(log_mutex);
    return data_logs;
}
const vector<string>& ClientManager::getAlertLogs() {
    lock_guard<mutex> lock(log_mutex);
    return alert_logs;
}
const vector<int>& ClientManager::getAvailableDevices() {
    return available_devices;
}

// =============================================================
// Helper implementations
// =============================================================
void print_buffer(const char *title, const uint8_t *buffer, int len) {
    cout << title << " (" << len << " bytes): ";
    for (int i = 0; i < len; ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << static_cast<int>(buffer[i]) << " ";
    }
    cout << dec << "\n";
}

void print_status_message(uint8_t status_code) {
    cout << "Status Code: " << (int)status_code << "\n";
}

string format_timestamp(uint32_t ts) {
    time_t raw = ts;
    struct tm *timeinfo = localtime(&raw);
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", timeinfo);
    return string(buffer);
}

uint32_t convert_hhmm_to_timestamp(uint32_t input_val) {
    uint32_t hour = input_val / 100;
    uint32_t min = input_val % 100;
    time_t now = time(nullptr);
    struct tm tm_info = *localtime(&now);
    tm_info.tm_hour = hour;
    tm_info.tm_min = min;
    tm_info.tm_sec = 0;
    return (uint32_t)mktime(&tm_info);
}

// =============================================================
// CLI MAIN (Renamed or wrapped)
// =============================================================
// Since we want to support both CLI and Qt, we will put the Main Menu CLI loop 
// into a function, and `main` can call it if not in Qt mode.
// BUT the request implies simultaneous.
// The Qt GUI `main` will likely run the Qt Event Loop (`app.exec()`).
// Integrating a CLI loop `cin` with Qt loop is hard (blocking).
// We'll assume the USER runs either CLI or GUI, OR the GUI has a console window.
// However, the prompt says "tôi muốn qt gui cho client luôn do tôi muốn nó in ra cli đồng thời"
// "I want Qt GUI ... so I want it to print to CLI simultaneously"
// This just means logs like `cout << "Sent packet"` should appear in the terminal where I launched the GUI.
// It DOES NOT necessarily mean I need to interpret `cin` while the GUI is running.
// So I will make `main` launch the Qt App.
// The `cin` menu logic effectively becomes obsolete or secondary.
// I will comment out the old `main` and replace it with the Qt `main` in `main.cpp` (or `main_qt.cpp`).
// The file `myClient.cpp` effectively becomes the implementation of `ClientManager`.
// I will REMOVE `main` from `myClient.cpp` so it can be linked by the Qt app.
