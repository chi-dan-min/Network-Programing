#include "myClient.h"

vector<string> data_logs;
vector<string> alert_logs;
vector<uint8_t> available_devices;

// debug function
void print_buffer(const char *title, const uint8_t *buffer, int len)
{
    cout << title << " (" << len << " bytes):\n";
    for (int i = 0; i < len; ++i)
    {
        cout << hex << uppercase << setw(2) << setfill('0')
             << static_cast<int>(buffer[i]) << " ";
    }
    cout << "\n\n";

    // reset lại decimal để không ảnh hưởng các cout sau
    cout << dec;
}

void print_status_message(uint8_t status_code)
{
    switch (status_code)
    {
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

    case STATUS_ERR_GARDEN_NOT_EMPTY:
        cout << "[STATUS_ERR_GARDEN_NOT_EMPTY] Cannot delete garden\n";
        break;

    default:
        cout << "[UNKNOWN_STATUS] Unrecognized status code: "
             << static_cast<int>(status_code) << "\n";
        break;
    }
}

bool client_login(int sockfd, uint32_t &token)
{
    string myAppID, myPassword;
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    while (true)
    {
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
        if (packet_len <= 0)
        {
            cerr << "Server disconnected.\n";
            return false;
        }

        print_buffer("Client receive: Connect Response", recv_buffer, packet_len);

        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) != 0)
        {
            cerr << "Failed to deserialize packet.\n";
            memset(recv_buffer, 0, sizeof(recv_buffer));
            continue;
        }

        switch (packet.type)
        {
        case MSG_TYPE_CONNECT_SERVER:
        {
            token = packet.data.connect_res.token;
            cout << "Login successful! Received Token: " << token << "\n\n";
            return true;
        }

        case MSG_TYPE_CMD_RESPONSE:
        {
            cout << "Login failed. Server returned status: ";
            print_status_message(packet.data.cmd_response.status_code);
            cout << "\n";
            break; // cho phép nhập lại
        }

        default:
        {
            cout << "Unexpected packet type: " << (int)packet.type << endl;
            break;
        }
        }

        memset(recv_buffer, 0, sizeof(recv_buffer));
    }
}

bool client_scan(int sockfd, uint32_t token, bool log)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // --- Gửi Scan Request ---
    packet_len = serialize_scan_request(token, send_buffer);
    if(log)
        print_buffer("Client send: Scan Request", send_buffer, packet_len);
    if (send(sockfd, send_buffer, packet_len, 0) <= 0)
    {
        cerr << "Failed to send Scan Request.\n";
        return false;
    }

    // --- Nhận Scan Response ---
    packet_len = recv(sockfd, recv_buffer, MAX_BUFFER_SIZE, 0);
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    if(log)
        print_buffer("Client receive: Scan Response", recv_buffer, packet_len);

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) != 0)
    {
        cerr << "Failed to deserialize Scan Response.\n";
        return false;
    }

    switch (packet.type)
    {
    case MSG_TYPE_SCAN_SERVER:
    {
        if(log)
            cout << "Scan successful. Devices found: "
                  << (int)packet.data.scan_res.num_devices << "\n";
        available_devices.clear();
        for (int i = 0; i < packet.data.scan_res.num_devices; ++i)
        {
            if(log)
                cout << "Device ID: " << static_cast<int>(packet.data.scan_res.device_ids[i]) << "\n";
            available_devices.push_back(packet.data.scan_res.device_ids[i]);
        }
        cout << endl;
        break;
    }
    case MSG_TYPE_CMD_RESPONSE:
    {
        cout << "Scan failed. Server returned status: ";
        print_status_message(packet.data.cmd_response.status_code);
        break;
    }
    default:
    {
        cout << "Unexpected packet type: " << (int)packet.type << endl;
        break;
    }
    }

    return true;
}

bool client_info(int sockfd, uint32_t token, bool log)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // --- Gửi Info Request ---
    packet_len = serialize_info_request(token, send_buffer);
    if(log)    
        print_buffer("Client send: Info Request", send_buffer, packet_len);

    if (send(sockfd, send_buffer, packet_len, 0) <= 0)
    {
        cerr << "Failed to send Info Request.\n";
        return false;
    }

    // --- Nhận Info Response ---
    packet_len = recv(sockfd, recv_buffer, MAX_BUFFER_SIZE, 0);
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    if(log) 
        print_buffer("Client receive: Info Response", recv_buffer, packet_len);

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) != 0)
    {
        cerr << "Failed to deserialize Info Response.\n";
        return false;
    }

    switch (packet.type)
    {
    case MSG_TYPE_INFO_SERVER:
    {
        InfoResponse &info = packet.data.info_res;
        if(log) 
            cout << "INFO RESPONSE: Found " << (int)info.num_gardens << " garden(s)\n";
        // --- In danh sách Garden và Devices trực tiếp từ packet ---
        for (int i = 0; i < info.num_gardens; ++i)
        {
            const GardenInfo &g = info.gardens[i];
            cout << "\nGarden ID: " << (int)g.garden_id
                 << " | Devices: " << (int)g.num_devices << "\n";

            for (int d = 0; d < g.num_devices; ++d)
            {
                cout << "  - Device ID: " << (int)g.devices[d].device_id << "\n";
            }
        }

        cout << endl;
        break;
    }

    case MSG_TYPE_CMD_RESPONSE:
    {
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

bool client_add_garden(int sockfd, uint32_t token)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    client_info(sockfd, token, false);

    uint32_t garden_id;
    cout << "Enter new Garden ID(or '0' to cancel) : ";
    cin >> garden_id;
    if (garden_id == 0)
    {
        cout << "Cancelled adding Garden.\n";
        return false;
    }
    cin.ignore(); // bỏ ký tự newline

    packet_len = serialize_garden_add(token, static_cast<uint8_t>(garden_id), send_buffer);
    send(sockfd, send_buffer, packet_len, 0);
    print_buffer("Client send: Garden Add Request", send_buffer, packet_len);

    // nhận response
    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Garden Add Response", recv_buffer, packet_len);

    if (packet_len > 0)
    {
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0)
        {
            if (packet.type == MSG_TYPE_CMD_RESPONSE)
            {
                int status_code = packet.data.cmd_response.status_code;
                print_status_message(status_code);
            }
            else
            {
                cout << "Unexpected response type.\n";
            }
        }
    }
    return true;
}

bool client_add_device(int sockfd, uint32_t token)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    client_info(sockfd, token, false);

    uint8_t garden_id, dev_id;
    int g, d;
    cout << "Enter Garden ID to add device to(or '0' to cancel) : ";
    cin >> g;
    if (g == 0)
    {
        cout << "Cancelled adding Device.\n";
        return false;
    }
    garden_id = static_cast<uint8_t>(g);

    client_scan(sockfd, token, false);
    
    if (available_devices.empty())
    {
        cout << "No Devices available.\n";
        return false;
    }

    cout << "Available Devices: ";
    for (auto devid : available_devices)
        cout << (int)devid << " ";
    cout << "\n";

    cout << "Enter Device ID(or '0' to cancel) : ";
    cin >> d;
    if (d == 0)
    {
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
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Device Add Response", recv_buffer, packet_len);
    if (packet_len > 0)
    {
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0)
        {
            if (packet.type == MSG_TYPE_CMD_RESPONSE)
            {
                int status_code = packet.data.cmd_response.status_code;
                print_status_message(status_code);
            }
            else
            {
                cout << "Unexpected response type.\n";
            }
        }
    }
    return true;
}

bool client_delete_garden(int sockfd, uint32_t token)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    client_info(sockfd, token, false);

    uint32_t garden_id_to_delete;
    cout << "Enter the Garden ID to delete (0 = Cancel): ";
    cin >> garden_id_to_delete;

    if (garden_id_to_delete == 0)
    {
        cout << "Deletion cancelled.\n";
        return false;
    }
    cin.ignore();

    packet_len = serialize_garden_del(token, static_cast<uint8_t>(garden_id_to_delete), send_buffer);
    send(sockfd, send_buffer, packet_len, 0);
    print_buffer("Client send: Garden Delete Request", send_buffer, packet_len);

    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Garden Delete Response", recv_buffer, packet_len);

    if (packet_len > 0)
    {
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0)
        {
            if (packet.type == MSG_TYPE_CMD_RESPONSE)
            {
                int status_code = packet.data.cmd_response.status_code;
                print_status_message(status_code);
            }
            else
            {
                cout << "Unexpected response type.\n";
            }
        }
    }
    return true;
}

bool client_delete_device(int sockfd, uint32_t token)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    client_info(sockfd, token, false);

    uint8_t garden_id, dev_id;
    int g, d;

    cout << "Enter the Garden ID where the device is located (0 = Cancel): ";
    cin >> g;
    if (g == 0)
    {
        cout << "Deletion cancelled.\n";
        return false;
    }
    garden_id = static_cast<uint8_t>(g);

    cout << "Enter the Device ID to delete (0 = Cancel): ";
    cin >> d;
    if (d == 0)
    {
        cout << "Deletion cancelled.\n";
        return false;
    }
    dev_id = static_cast<uint8_t>(d);
    cin.ignore();

    packet_len = serialize_device_del(token, garden_id, dev_id, send_buffer);
    send(sockfd, send_buffer, packet_len, 0);
    print_buffer("Client send: Device Delete Request", send_buffer, packet_len);

    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Device Delete Response", recv_buffer, packet_len);

    if (packet_len > 0)
    {
        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0)
        {
            if (packet.type == MSG_TYPE_CMD_RESPONSE)
            {
                int status_code = packet.data.cmd_response.status_code;
                print_status_message(status_code);
                if (status_code == STATUS_OK)
                {
                    available_devices.push_back(dev_id);
                    cout << "Device " << (int)dev_id << " restored to available device list.\n";
                }
            }
            else
            {
                cout << "Unexpected response type.\n";
            }
        }
    }
    return true;
}
bool client_set_parameter(int sockfd, uint32_t token)
{
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // Lấy danh sách garden + device hiện tại
    client_info(sockfd, token, false);

    int g, d;
    uint8_t garden_id, dev_id;

    cout << "Enter Garden ID where device is located (0 = Cancel): ";
    cin >> g;
    if (g == 0)
    {
        cout << "Cancelled setting parameter.\n";
        return false;
    }
    garden_id = static_cast<uint8_t>(g);

    cout << "Enter Device ID to set parameter (0 = Cancel): ";
    cin >> d;
    if (d == 0)
    {
        cout << "Cancelled setting parameter.\n";
        return false;
    }

    
    dev_id = static_cast<uint8_t>(d);
    if(!client_get_device_params(sockfd, token, dev_id)){
        cout << "Invalid Device ID\n";
        return false;
    }

    // --- Chọn parameter cần set ---
    cout << "Select parameter to set(1-9):";
    int param_option;
    cin >> param_option;

    uint8_t param_id;
    switch (param_option)
    {
    case 1: param_id = PARAM_ID_T_DELAY; break;
    case 2: param_id = PARAM_ID_H_MIN;   break;
    case 3: param_id = PARAM_ID_H_MAX;   break;
    case 4: param_id = PARAM_ID_N_MIN;   break;
    case 5: param_id = PARAM_ID_P_MIN;   break;
    case 6: param_id = PARAM_ID_K_MIN;   break;
    case 7: param_id = PARAM_ID_POWER;   break;
    case 8: param_id = PARAM_ID_FERT_C;  break;
    case 9: param_id = PARAM_ID_FERT_V;  break;
    default:
        cout << "Invalid parameter option.\n";
        return false;
    }

    cout << "Enter new value for parameter: ";
    int val;
    cin >> val;
    uint8_t param_value = static_cast<uint8_t>(val);

    // --- Gửi Set Parameter Request ---
    packet_len = serialize_set_parameter(token, garden_id, dev_id, param_id, param_value, send_buffer);
    send(sockfd, send_buffer, packet_len, 0);
    print_buffer("Client send: Set Parameter Request", send_buffer, packet_len);

    // --- Nhận Response ---
    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0)
    {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Set Parameter Response", recv_buffer, packet_len);

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) == 0)
    {
        if (packet.type == MSG_TYPE_CMD_RESPONSE)
        {
            int status_code = packet.data.cmd_response.status_code;
            print_status_message(status_code);
            return status_code == STATUS_OK;
        }
        else
        {
            cout << "Unexpected response type.\n";
            return false;
        }
    }

    cerr << "Failed to deserialize Set Parameter Response.\n";
    return false;
}
bool client_get_device_params(int sockfd, uint32_t token, uint8_t device_id, bool log) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));


    packet_len = serialize_settings_request(token, device_id, send_buffer);

    if (send(sockfd, send_buffer, packet_len, 0) < 0) {
        perror("Send failed");
        return false;
    }
    if(log)
        print_buffer("Client send: Settings Request", send_buffer, packet_len);

    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0) {
        cerr << "Server disconnected or error.\n";
        return false;
    }
    if(log)
        print_buffer("Client receive: Settings Response", recv_buffer, packet_len);


    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
                if (packet.type == MSG_TYPE_SETTINGS_SERVER) {
            SettingsResponse* s = &packet.data.setting_response;
            
            cout << "\n========================================\n";
            cout << "   SETTINGS FOR DEVICE ID: " << (int)device_id << "\n";
            cout << "========================================\n";
            cout << " [Power]      Mode: " << (int)s->power << "%\n";
            cout << " [Timer]      Interval T: " << (int)s->T << " minutes\n";
            cout << " [Fertilizer] Concentration: " << (int)s->fert_C << " g/L\n";
            cout << "              Volume: " << (int)s->fert_V << " L\n";
            cout << " [Thresholds] Humidity: " << (int)s->Hmin << "% - " << (int)s->Hmax << "%\n";
            cout << "              N-P-K Min: " << (int)s->Nmin << " - " 
                                               << (int)s->Pmin << " - " 
                                               << (int)s->Kmin << "\n";
            cout << "========================================\n\n";
            return true;
        } 
        else if (packet.type == MSG_TYPE_CMD_RESPONSE) {
            int status = packet.data.cmd_response.status_code;
            if(log)
                cout << "Error receiving settings. Status Code: " << status << "\n";
            if(log)
                print_status_message(status); // Hàm in lỗi helper của bạn
            return false;
        } 
        else {
            if(log)
                cout << "Unexpected packet type received: " << (int)packet.type << "\n";
        }
    } else {
        cerr << "Failed to deserialize packet.\n";
    }

    return false;
}

bool client_change_password(int sockfd, uint32_t token) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;

    string appID_str, oldPass_str, newPass_str;

    cout << "\n=== CHANGE PASSWORD ===\n";
    cout << "Enter App ID: ";
    cin >> appID_str;
    
    cout << "Enter Old Password: ";
    cin >> oldPass_str;

    cout << "Enter New Password: ";
    cin >> newPass_str;

    if (oldPass_str.length() > 50 || newPass_str.length() > 50) { // Giới hạn an toàn
         cout << "Error: Password too long.\n";
         return false;
    }

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));

    packet_len = serialize_change_password(token, appID_str.c_str(), 
                                           (uint8_t)oldPass_str.length(), 
                                           oldPass_str.c_str(), 
                                           newPass_str.c_str(), 
                                           send_buffer);

    if (send(sockfd, send_buffer, packet_len, 0) < 0) {
        perror("Send failed");
        return false;
    }
    print_buffer("Client send: Change Password Request", send_buffer, packet_len);

    packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    if (packet_len <= 0) {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer("Client receive: Change Password Response", recv_buffer, packet_len);

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
        if (packet.type == MSG_TYPE_CMD_RESPONSE) {
            int status = packet.data.cmd_response.status_code;
            if(status == STATUS_OK){
                cout << "SUCCESS: Password changed successfully!\n";
            }
            else if (status == STATUS_ERR_WRONG_PASSWORD) {
                cout << "FAILED: Incorrect old password.\n";
            } else {
                cout << "FAILED: Error code " << status << "\n";
                print_status_message(status);
            }
            return false;
        }
        else {
            cout << "Unexpected response type: " << (int)packet.type << "\n";
        }
    }

    return false;
}

bool send_simple_request(int sockfd, uint8_t* buffer, int len, const char* action_name) {
    if (send(sockfd, buffer, len, 0) < 0) {
        perror("Send failed");
        return false;
    }
    print_buffer((string("Client send: ") + action_name).c_str(), buffer, len);

    uint8_t recv_buf[MAX_BUFFER_SIZE];
    int rlen = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
    if (rlen <= 0) {
        cerr << "Server disconnected.\n";
        return false;
    }
    print_buffer((string("Client receive: ") + action_name + " Response").c_str(), recv_buf, rlen);

    ParsedPacket packet;
    if (deserialize_packet(recv_buf, rlen, &packet) == 0) {
        if (packet.type == MSG_TYPE_CMD_RESPONSE) {
            int status = packet.data.cmd_response.status_code;
            print_status_message(status);
            return (status == STATUS_OK);
        }
    }
    return false;
}

bool client_set_pump_schedule(int sockfd, uint32_t token) {
    int d_id, count;
    cout << "\n--- SET PUMP SCHEDULE ---\n";
    client_info(sockfd, token, false);

    cout << "Enter Device ID (0 to cancel): ";
    if (!(cin >> d_id) || d_id == 0) return false;

    cout << "Enter number of slots: ";
    cin >> count;
    if (count <= 0 || count > MAX_TIME_STAMP) return false;

    vector<uint32_t> timestamps;
    cout << "Enter times (Format HHMM e.g., 830):\n";

    for (int i = 0; i < count; i++) {
        uint32_t hhmm;
        cout << "  Slot " << i + 1 << ": ";
        cin >> hhmm;
        timestamps.push_back(convert_hhmm_to_timestamp(hhmm));
    }

    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_pump_schedule(token, (uint8_t)d_id, (uint8_t)count,
                                          timestamps.data(), buffer);

    return send_simple_request(sockfd, buffer, len, "Set Pump Schedule");
}

bool client_set_light_schedule(int sockfd, uint32_t token) {
    int d_id, count;
    cout << "\n--- SET LIGHT SCHEDULE ---\n";
    client_info(sockfd, token, false);

    cout << "Enter Device ID (0 to cancel): ";
    if (!(cin >> d_id) || d_id == 0) return false;

    cout << "Enter number of time pairs (ON/OFF): ";
    cin >> count;
    if (count <= 0 || count > MAX_TIME_STAMP) return false;

    vector<uint32_t> timestamps;
    cout << "Enter ON/OFF pairs (Format HHMM):\n";

    for (int i = 0; i < count; i++) {
        uint32_t on_hhmm, off_hhmm;
        cout << "  Pair " << i + 1 << " ON : "; cin >> on_hhmm;
        cout << "            OFF: "; cin >> off_hhmm;

        timestamps.push_back(convert_hhmm_to_timestamp(on_hhmm));
        timestamps.push_back(convert_hhmm_to_timestamp(off_hhmm));
    }

    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_light_schedule(token, (uint8_t)d_id,
                                           (uint8_t)(count * 2),
                                           timestamps.data(), buffer);
    return send_simple_request(sockfd, buffer, len, "Set Light Schedule");
}


bool client_set_direct_pump(int sockfd, uint32_t token) {
    int d_id, state;
    cout << "\n--- DIRECT CONTROL: PUMP ---\n";
    client_info(sockfd, token, false);
    cout << "Enter Device ID (0 to cancel): ";
    if (!(cin >> d_id)) { cin.clear(); cin.ignore(1000, '\n'); return false; }
    if (d_id == 0) { cout << "Cancelled.\n"; return false; }

    cout << "Action (1: ON, 0: OFF): "; cin >> state;

    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_direct_pump(token, (uint8_t)d_id, state != 0, buffer);
    return send_simple_request(sockfd, buffer, len, "Set Direct Pump");
}

bool client_set_direct_light(int sockfd, uint32_t token) {
    int d_id, state;
    cout << "\n--- DIRECT CONTROL: LIGHT ---\n";
    client_info(sockfd, token, false);
    cout << "Enter Device ID (0 to cancel): ";
    if (!(cin >> d_id)) { cin.clear(); cin.ignore(1000, '\n'); return false; }
    if (d_id == 0) { cout << "Cancelled.\n"; return false; }

    cout << "Action (1: ON, 0: OFF): "; cin >> state;

    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_direct_light(token, (uint8_t)d_id, state != 0, buffer);
    return send_simple_request(sockfd, buffer, len, "Set Direct Light");
}

bool client_set_direct_fert(int sockfd, uint32_t token) {
    int d_id, state;
    cout << "\n--- DIRECT CONTROL: FERTILIZER ---\n";
    client_info(sockfd, token, false);
    cout << "Enter Device ID (0 to cancel): ";
    if (!(cin >> d_id)) { cin.clear(); cin.ignore(1000, '\n'); return false; }
    if (d_id == 0) { cout << "Cancelled.\n"; return false; }

    cout << "Action (1: ON, 0: OFF): "; cin >> state;

    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_direct_fert(token, (uint8_t)d_id, state != 0, buffer);
    return send_simple_request(sockfd, buffer, len, "Set Direct Fert");
}
// --- MENU QUẢN LÝ (Add/Delete) ---
void show_main_menu()
{
    cout << "\n========== MAIN MENU ==========\n";
    cout << "1.  Monitoring (Scan & Info)\n";
    cout << "2.  Logs (Data & Alerts)\n";
    cout << "3.  Manager (Garden & Device)\n";
    cout << "4.  Control & Schedule\n";
    cout << "5.  Settings & Config\n";
    cout << "9.  Show menu again\n";
    cout << "0.  Exit\n";
    cout << "===============================\n";
    cout << "Select option: ";
    cout.flush();
}
void menu_manager(int sockfd, uint32_t token) {
    int cmd;
    while (true) {
        auto show_ctrl_menu = [](){
            cout << "\n--- MANAGER MENU ---\n";
            cout << "1. Add Garden\n";
            cout << "2. Delete Garden\n";
            cout << "3. Add Device\n";
            cout << "4. Delete Device\n";
            cout << "9. Show menu again\n";
            cout << "0. Back to Main Menu\n";
            cout << "Choice: ";
        };

        show_ctrl_menu();
        
        if (!(cin >> cmd)) { cin.clear(); cin.ignore(1000, '\n'); continue; }

        if (cmd == 0) break;
        switch (cmd) {
            case 1: client_add_garden(sockfd, token); break;
            case 2: client_delete_garden(sockfd, token); break;
            case 3: client_add_device(sockfd, token); break;
            case 4: client_delete_device(sockfd, token); break;
            case 9: show_ctrl_menu(); break;
            default: cout << "Invalid option.\n"; break;
        }
    }
}

void menu_control(int sockfd, uint32_t token) {
    int cmd;
    while (true) {
        auto show_ctrl_menu = [](){
            cout << "\n--- CONTROL & SCHEDULE ---\n";
            cout << "1. Set Pump Schedule\n";
            cout << "2. Set Light Schedule\n";
            cout << "3. Direct Control: Pump\n";
            cout << "4. Direct Control: Light\n";
            cout << "5. Direct Control: Fertilizer\n";
            cout << "9. Show menu again\n";
            cout << "0. Back to Main Menu\n";
            cout << "Choice: ";
        };
        show_ctrl_menu();

        if (!(cin >> cmd)) { cin.clear(); cin.ignore(1000, '\n'); continue; }

        if (cmd == 0) break;

        // Các biến dùng chung cho switch
        int d_id, p_id, count, state;
        
        switch (cmd) {
            case 1: // Pump Schedule
                client_set_pump_schedule(sockfd, token);
                break;
            case 2: // Light Schedule
                client_set_light_schedule(sockfd, token);
                break;
            case 3: // Direct Pump
                client_set_direct_pump(sockfd, token);
                break;
            case 4: // Direct Light
                client_set_direct_light(sockfd, token);
                break;
            case 5: // Direct Fert
                client_set_direct_fert(sockfd, token);
                break;
            case 9: show_ctrl_menu(); break;
            default: cout << "Invalid option.\n"; break;
        }
    }
}

void menu_logs() {
    int cmd;
    while(true) {
        auto show_ctrl_menu = [](){
            cout << "\n--- LOGS VIEWER ---\n";
            cout << "1. View Data Logs\n";
            cout << "2. View Alert Logs\n";
            cout << "9. Show menu again\n";
            cout << "0. Back\n";
            cout << "Choice: ";
        };
        show_ctrl_menu();
        if (!(cin >> cmd)) { cin.clear(); cin.ignore(1000, '\n'); continue; }
        
        if (cmd == 0) break;
        if (cmd == 1) {
            cout << "\n[DATA LOGS]\n";
            for(const auto &s : data_logs) cout << s << "\n";
            cout << "[END]\n";
        } else if (cmd == 2) {
            cout << "\n[ALERT LOGS]\n";
            for(const auto &s : alert_logs) cout << s << "\n";
            cout << "[END]\n";
        }else if(cmd == 9){
            show_ctrl_menu();
        }
    }
}

void menu_settings(int sockfd, uint32_t token) {
    int cmd;
    while(true) {
        auto show_ctrl_menu = [](){
            cout << "\n--- SETTINGS ---\n";
            cout << "1. Set Parameter (Thresholds)\n";
            cout << "2. Get Device Config\n";
            cout << "3. Change Password\n";
            cout << "9. Show menu again\n"; 
            cout << "0. Back\n";
            cout << "Choice: ";
        };
        show_ctrl_menu();
        if (!(cin >> cmd)) { cin.clear(); cin.ignore(1000, '\n'); continue; }

        if (cmd == 0) break;
        switch(cmd) {
            case 1: client_set_parameter(sockfd, token); break;
            case 2: {
                int d_id; cout << "Device ID: "; cin >> d_id;
                client_get_device_params(sockfd, token, (uint8_t)d_id);
                break;
            }
            case 3: client_change_password(sockfd, token); break;
            case 9: show_ctrl_menu(); break;
            default: cout << "Invalid option.\n"; break;
        }
    }
}

string format_timestamp(uint32_t ts)
{
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
void handle_packet(const ParsedPacket &packet)
{
    switch (packet.type)
    {
        case MSG_TYPE_DATA:
        {
            IntervalData data = packet.data.interval_data;
            ostringstream oss;
            oss << "[DATA] " << format_timestamp(data.timestamp)
                << ", deviceID=" << (int)data.dev_id
                << ", soil=" << (int)data.humidity
                << ", N=" << (int)data.n_level
                << ", P=" << (int)data.p_level
                << ", K=" << (int)data.k_level;
            data_logs.push_back(oss.str());
            break;
        }
        case MSG_TYPE_ALERT:
        {
            Alert alert = packet.data.alert;
            string alert_str;
            switch (alert.alert_code)
            {
                case ALERT_WATERING_START:  alert_str = "Watering START"; break;
                case ALERT_WATERING_END:    alert_str = "Watering END"; break;
                case ALERT_FERTILIZE_START: alert_str = "Fertilize START"; break;
                case ALERT_FERTILIZE_END:   alert_str = "Fertilize END"; break;
                case ALERT_LIGHTS_ON:       alert_str = "Light ON"; break;
                case ALERT_LIGHTS_OFF:      alert_str = "Light OFF"; break;
                default:                    alert_str = "Unknown"; break;
            }
            ostringstream oss;
            oss << "[ALERT] " << format_timestamp(alert.timestamp)
                << ", deviceID=" << (int)alert.dev_id
                << ", code=" << alert_str;
            alert_logs.push_back(oss.str());
            break;
        }
        default:
            break;
    }
}

void recv_thread_func(int sockfd)
{
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    while (true)
    {
        memset(recv_buffer, 0, sizeof(recv_buffer));
        int packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
        if (packet_len <= 0)
        {
            cout << "Server disconnected.\n";
            exit(1);
        }

        ParsedPacket packet;
        if (deserialize_packet(recv_buffer, packet_len, &packet) == 0)
        {
            handle_packet(packet);
        }
    }
}
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        cerr << "Usage: " << argv[0] << " <server IP address>\n";
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 2; }

    sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
    {
        cerr << "Invalid address: " << argv[1] << endl;
        return 3;
    }

    if (connect(sockfd, (sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect");
        return 4;
    }

    // =========================
    // 1. Login
    // =========================
    uint32_t token;
    cout << "Logging in...\n";
    while (!client_login(sockfd, token))
    {
        cout << "Login failed. Retrying...\n";
        sleep(1);
    }
    cout << "Login success! Token = " << token << endl;

    // =========================
    // 2. Scan & Info 1 lần
    // =========================
    cout << "Performing initial scan...\n";
    client_scan(sockfd, token);
    client_info(sockfd, token);

    // =========================
    // 3. Thread nhận dữ liệu server
    // =========================
    thread recv_thread(recv_thread_func, sockfd);
    recv_thread.detach(); // chạy nền

    // =========================
    // 4. Main UI menu loop
    // =========================
    show_main_menu();
    int cmd;
    while (true)
    {
        if (!(cin >> cmd)) { cin.clear(); cin.ignore(1000, '\n'); continue; }

        switch (cmd)
        {
            case 0: cout << "Exiting...\n"; close(sockfd); return 0;
            case 1: cout << "\n[1] Scanning Devices...\n"; client_scan(sockfd, token);
                    cout << "\n[2] Getting Info...\n"; client_info(sockfd, token); break;
            case 2: menu_logs(); break;
            case 3: menu_manager(sockfd, token); break;
            case 4: menu_control(sockfd, token); break;
            case 5: menu_settings(sockfd, token); break;
            case 9: show_main_menu(); break;
            default: cout << "Invalid command.\n"; break;
        }
    }
}