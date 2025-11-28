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

#define SERV_PORT 3000

using namespace std;
// =====================
// Global variables
// =====================
extern std::vector<std::string> data_logs;
extern std::vector<std::string> alert_logs;
extern std::vector<uint8_t> current_gardens;
extern std::vector<uint8_t> available_devices;
extern std::vector<uint8_t> current_devices;

// =====================
// Debug functions
// =====================
void print_buffer(const char *title, const uint8_t *buffer, int len);
void print_status_message(uint8_t status_code);

// =====================
// Client actions
// =====================
bool send_simple_request(int sockfd, uint8_t* buffer, int len, const char* action_name);
bool client_login(int sockfd, uint32_t &token);
bool client_scan(int sockfd, uint32_t token, bool log = true);
bool client_info(int sockfd, uint32_t token, bool log = true);
bool client_add_garden(int sockfd, uint32_t token);
bool client_delete_garden(int sockfd, uint32_t token);
bool client_add_device(int sockfd, uint32_t token);
bool client_delete_device(int sockfd, uint32_t token);
bool client_set_parameter(int sockfd, uint32_t token);
bool client_get_device_params(int sockfd, uint32_t token, uint8_t device_id, bool log = true);
bool client_change_password(int sockfd, uint32_t token);
bool client_set_pump_schedule(int sockfd, uint32_t token);
bool client_set_light_schedule(int sockfd, uint32_t token);
bool client_set_direct_pump(int sockfd, uint32_t token);
bool client_set_direct_light(int sockfd, uint32_t token);
bool client_set_direct_fert(int sockfd, uint32_t token);

// =====================
// UI helpers
// =====================
void show_main_menu();
std::string format_timestamp(uint32_t ts);
uint32_t convert_hhmm_to_timestamp(uint32_t input_val);
#endif // MYCLIENT_H
