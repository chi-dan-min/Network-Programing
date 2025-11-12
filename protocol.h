#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h> 
#include <string.h> 
#include <stdlib.h> 

// Kích thước buffer tối đa, bạn có thể thay đổi
#define MAX_BUFFER_SIZE 256
#define MAX_DEVICES 50
#define MAX_GARDENS 10

// --- Cấu trúc cho dữ liệu đã giải gói tin ---

// 1. Connect
typedef struct {
    char password[MAX_BUFFER_SIZE - 2]; // Buffer để chứa mật khẩu
    uint8_t pass_len;
} ConnectRequest;

typedef struct {
    uint32_t token; // Giả sử token là 4 bytes (uint32_t)
} ConnectResponse;

// 2. Scan
typedef struct {
    uint32_t token;
} ScanRequest; // Giống InfoRequest

typedef struct {
    uint8_t num_devices;
    uint8_t device_ids[MAX_DEVICES];
} ScanResponse;

// 3. Info
typedef struct {
    uint32_t token;
} InfoRequest; // Giống ScanRequest

typedef struct {
    uint8_t device_id;
} DeviceInfo;

typedef struct {
    uint8_t garden_id;
    uint8_t num_devices;
    DeviceInfo devices[MAX_DEVICES];
} GardenInfo;

typedef struct {
    uint8_t num_gardens;
    GardenInfo gardens[MAX_GARDENS];
} InfoResponse;

// Cấu trúc packet tổng quát sau khi giải gói tin
typedef struct {
    uint8_t type;
    uint8_t length;
    union {
        ConnectRequest connect_req;
        ConnectResponse connect_res;
        ScanRequest scan_req;
        ScanResponse scan_res;
        InfoRequest info_req;
        InfoResponse info_res;
    } data;
} ParsedPacket;

// --- Khai báo các hàm GÓI TIN (Serialization) ---

/**
 * @brief Gói tin Connect Request (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer
 */
int serialize_connect_request(const char* password, uint8_t* out_buffer);

/**
 * @brief Gói tin Connect Response (Server -> Client)
 * @return Tổng số byte đã ghi vào buffer (luôn là 6)
 */
int serialize_connect_response(uint32_t token, uint8_t* out_buffer);

/**
 * @brief Gói tin Scan Request (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer (luôn là 6)
 */
int serialize_scan_request(uint32_t token, uint8_t* out_buffer);

/**
 * @brief Gói tin Scan Response (Server -> Client)
 * @return Tổng số byte đã ghi vào buffer
 */
int serialize_scan_response(uint8_t num_devices, const uint8_t* device_ids, uint8_t* out_buffer);

/**
 * @brief Gói tin Info Request (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer (luôn là 6)
 */
int serialize_info_request(uint32_t token, uint8_t* out_buffer);

/**
 * @brief Gói tin Info Response (Server -> Client)
 * @return Tổng số byte đã ghi vào buffer
 */
int serialize_info_response(const InfoResponse* info_data, uint8_t* out_buffer);


// --- Khai báo hàm GIẢI GÓI TIN (Deserialization) ---

/**
 * @brief Phân tích một buffer thô và điền vào cấu trúc ParsedPacket
 * @param in_buffer Buffer nhận được từ socket
 * @param buffer_len Độ dài của buffer nhận được
 * @param out_packet Cấu trúc để chứa dữ liệu đã phân tích
 * @return 0 nếu thành công, -1 nếu có lỗi (packet không hoàn chỉnh, sai độ dài,...)
 */
int deserialize_packet(const uint8_t* in_buffer, int buffer_len, ParsedPacket* out_packet);

#endif // PROTOCOL_H