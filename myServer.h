#ifndef SERVER_H
#define SERVER_H

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
#include <ctime>

#include "protocol.h"

#define SERV_PORT 3000
#define MAX_CLIENTS 5

using namespace std;

// Debug Function
void print_buffer(const char *title, const uint8_t *buffer, int len);

// --- Data Structures ---
struct App
{
    string appID;
    uint32_t token;
    uint32_t sockfd;
};

struct DeviceSensor
{
    // Sensor values
    uint8_t soil_moisture;
    uint8_t N, P, K;
    uint8_t fert_C, fert_V; // nồng độ C gam/lít, lượng nước V lít
    uint8_t decay_rate;
    uint8_t power; // 0 -> 100% công suất đèn

    // Inteval Time
    uint8_t T; // minute
    // Thresholds
    uint8_t Hmin, Hmax;
    uint8_t Nmin, Pmin, Kmin;

    // AUTO SCHEDULES
    vector<uint32_t> watering_times_hmax; // tưới hàng ngày
    vector<uint32_t> watering_times_hmin;
    vector<pair<uint32_t, uint32_t>> lighting_times; // bật đèn hàng ngày

    // DIRECT CONTROL — hoạt động độc lập
    uint8_t pump_on;  // 1 = bật bơm
    uint8_t fert_on;  // 1 = bón phân
    uint8_t light_on; // 1 = bật đèn

    uint32_t pump_timeout;
    uint32_t fert_timeout;
    uint32_t light_timeout;

    uint8_t time_count; // Thời gian đếm để gửi Interval Data
};

// Global Data
extern vector<App> apps;
extern mutex apps_mutex;

extern map<string, string> app_credentials;
extern mutex credentials_mutex;

extern map<string, vector<uint8_t>> gardens;
extern mutex gardens_mutex;

extern map<uint8_t, uint8_t> device_to_garden;
extern mutex devices_mutex;

extern map<uint8_t, DeviceSensor> sensor_devices;
extern mutex sensor_devices_mutex;

// Utility
void print_device_status(const DeviceSensor &, uint8_t deviceID, uint8_t gardenID);
uint32_t random_token();
uint32_t generate_unique_token();
App *findAppByToken(uint32_t token);
App *findAppByAppID(const string &appID);
App *findAppByDeviceID(const uint8_t &deviceID);
vector<uint8_t> get_unassigned_devices_string();
bool authenticate_app(const string &appID, const string &password);

// Auto Threads
void auto_decay_loop();
void send_interval_data(int client_fd, const IntervalData &data);
void auto_send_interval();

// Handlers
void handle_connect_request(int client_fd, const ConnectRequest &req,
                            uint8_t *send_buffer, const uint8_t *recv_buffer,
                            int &packet_len, uint32_t &token);

void handle_scan_request(int client_fd, const ScanRequest &req,
                         uint8_t *send_buffer, const uint8_t *recv_buffer,
                         int &packet_len);

void handle_info_request(int client_fd, const InfoRequest &req,
                         uint8_t *send_buffer, const uint8_t *recv_buffer,
                         int &packet_len);

void handle_unknown_packet(int client_fd, uint8_t type,
                           uint8_t *send_buffer, int &packet_len);

void handle_garden_add_request(int client_fd, const GardenAdd &req,
                               uint8_t *send_buffer, const uint8_t *recv_buffer,
                               int &packet_len);

void handle_device_add_request(int client_fd, const DeviceAdd &req,
                               uint8_t *send_buffer, const uint8_t *recv_buffer,
                               int &packet_len);

void handle_garden_delete_request(int client_fd, const GardenDel &req,
                                  uint8_t *send_buffer, const uint8_t *recv_buffer,
                                  int &packet_len);

void handle_set_parameter(int client_fd, const SetParameter &req,
                          uint8_t *send_buffer, const uint8_t *recv_buffer,
                          int &packet_len);

void handle_set_pump_schedule(int client_fd, const SetPumpSchedule &req,
                              uint8_t *send_buffer, const uint8_t *recv_buffer,
                              int &packet_len);
void handle_set_light_schedule(int client_fd, const SetLightSchedule &req,
                               uint8_t *send_buffer, const uint8_t *recv_buffer,
                               int &packet_len);
void handle_set_direct_pump(int client_fd, const SetDirectPump &req,
                            uint8_t *send_buffer, const uint8_t *recv_buffer,
                            int &packet_len);
void handle_set_direct_light(int client_fd, const SetDirectLight &req,
                             uint8_t *send_buffer, const uint8_t *recv_buffer,
                             int &packet_len);
void handle_set_direct_fert(int client_fd, const SetDirectFert &req,
                            uint8_t *send_buffer, const uint8_t *recv_buffer,
                            int &packet_len);
void handle_change_password(int client_fd, const ChangePassword &req,
                            uint8_t *send_buffer, const uint8_t *recv_buffer,
                            int &packet_len);
#endif // SERVER_H
