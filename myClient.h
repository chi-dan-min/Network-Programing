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
bool client_login(int sockfd, uint32_t &token);
bool client_scan(int sockfd, uint32_t token);
bool client_info(int sockfd, uint32_t token);
bool client_add_garden(int sockfd, uint32_t token);
bool client_delete_garden(int sockfd, uint32_t token);
bool client_add_device(int sockfd, uint32_t token);
bool client_delete_device(int sockfd, uint32_t token);

// =====================
// UI helpers
// =====================
void show_menu();
std::string format_timestamp(uint32_t ts);

#endif // MYCLIENT_H
