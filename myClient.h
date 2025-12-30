#ifndef MYCLIENT_H
#define MYCLIENT_H
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <algorithm>
#include <ctime>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "protocol.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <string>
#include <map>

#define SERV_PORT 3000

using namespace std;

// Forward declaration

class ClientManager {
public:
    static ClientManager& instance() {
        static ClientManager instance;
        return instance;
    }

    // Connection
    bool connectToServer(const char* ip);
    void disconnect();
    bool login(const string& appID, const string& password);
    
    // Core Features
    bool scan(bool log = true);
    bool getInfo(bool log = true);
    
    // Garden/Device Management
    bool addGarden(uint32_t gardenID);
    bool deleteGarden(uint32_t gardenID);
    bool addDevice(uint8_t gardenID, uint8_t deviceID);
    bool deleteDevice(uint8_t gardenID, uint8_t deviceID);
    
    // Controls
    bool setPumpSchedule(uint8_t deviceID, const vector<uint32_t>& timestamps);
    bool setLightSchedule(uint8_t deviceID, const vector<uint32_t>& timestamps);
    bool setDirectPump(uint8_t deviceID, bool turnOn);
    bool setDirectLight(uint8_t deviceID, bool turnOn);
    bool setDirectFert(uint8_t deviceID, bool turnOn);
    
    // Status & Schedule Retrieval
    bool getDeviceStatus(uint8_t deviceID);
    bool getPumpSchedule(uint8_t deviceID);
    bool getLightSchedule(uint8_t deviceID);
    
    // Settings
    bool setParameter(uint8_t gardenID, uint8_t deviceID, uint8_t paramID, uint8_t value);
    bool getDeviceParams(uint8_t deviceID, bool log = true);
    bool changePassword(const string& appID, const string& oldPass, const string& newPass);

    // Getters for UI
    const vector<string>& getDataLogs();
    const vector<string>& getAlertLogs();
    const vector<int>& getAvailableDevices();
    const InfoResponse& getLastInfo() const { return lastInfo; }
    const SettingsResponse& getLastSettings() const { return lastSettings; }
    const StatusResponse& getLastStatus() const { return lastStatus; }

    bool isConnected() const { return connected; }
    uint32_t getToken() const { return token; }

    // Constants
    static const int MAX_BUF = 1024;

    // Cache
    map<int, vector<uint32_t>> cachedPumpSchedules;
    map<int, vector<uint32_t>> cachedLightSchedules;

private:
    ClientManager();
    ~ClientManager();
    ClientManager(const ClientManager&) = delete;
    ClientManager& operator=(const ClientManager&) = delete;

    int sockfd = -1;
    uint32_t token = 0;
    bool connected = false;
    
    // Cached Data
    InfoResponse lastInfo;
    SettingsResponse lastSettings;
    StatusResponse lastStatus;
    
    // Logs
    vector<string> data_logs;
    vector<string> alert_logs;
    mutex log_mutex;
    
    // State
    vector<int> available_devices;
    
    // Threading
    thread recv_thread;
    bool running = false;
    void recvThreadFunc();
    
    // Packet handling
    mutex socket_mutex; // Protect send calls
    mutex response_mutex;
    ParsedPacket shared_packet;
    bool has_response = false;
    
    bool waitForResponse(ParsedPacket &out_packet);
    bool sendRequest(uint8_t* buffer, int len, const char* actionName);
    void handleAsyncPacket(const ParsedPacket &packet);
};

// Formatting helpers (keep global or static)
string format_timestamp(uint32_t ts);
uint32_t convert_hhmm_to_timestamp(uint32_t input_val);
void print_buffer(const char *title, const uint8_t *buffer, int len);
void print_status_message(uint8_t status_code);

#endif // MYCLIENT_H
