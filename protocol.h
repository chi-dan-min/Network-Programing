#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h> 
#include <string.h> 
#include <stdlib.h> 
#include <arpa/inet.h>

// MESSAGE TYPES
#define MSG_TYPE_CONNECT_CLIENT             10          // 0x0A
#define MSG_TYPE_CONNECT_SERVER             11          // 0x0B
#define MSG_TYPE_SCAN_CLIENT                20          // 0x14
#define MSG_TYPE_SCAN_SERVER                21          // 0x15
#define MSG_TYPE_INFO_CLIENT                30          // 0x1E
#define MSG_TYPE_INFO_SERVER                31          // 0x1F
#define MSG_TYPE_DATA                       100         // 0x64
#define MSG_TYPE_ALERT                      200         // 0xC8
#define MSG_TYPE_CMD_RESPONSE               254         // 0xFE
#define MSG_TYPE_GARDEN_ADD                 80          // 0x50 
#define MSG_TYPE_GARDEN_DEL                 81          // 0x51 
#define MSG_TYPE_DEVICE_ADD                 90          // 0x5A 
#define MSG_TYPE_DEVICE_DEL                 91          // 0x5B 
#define MSG_TYPE_SET_PARAMETER              40          // 0x28
#define MSG_TYPE_SET_PUMP_SCHEDULE          50          // 0x32
#define MSG_TYPE_SET_LIGHT_SCHEDULE         51          // 0x33
#define MSG_TYPE_CHANGE_PASSWORD            12          // 0x0C
#define MSG_TYPE_SET_DIRECT_PUMP            60          // 0x3C
#define MSG_TYPE_SET_DIRECT_LIGHT           61          // 0x3D
#define MSG_TYPE_SET_DIRECT_FERT            62          // 0x3E

//CMD_RESPONSE      
#define STATUS_OK                           0x00         // Thành công
#define STATUS_ERR_FAILED                   0x01         // Lỗi chung, không xác định
#define STATUS_ERR_INVALID_TOKEN            0x02         // Token không hợp lệ hoặc hết hạn
#define STATUS_ERR_INVALID_DEVICE           0x03         // Device ID không tồn tại / Offline
#define STATUS_ERR_INVALID_PARAM            0x04         // Param ID hoặc giá trị Param không hợp lệ
#define STATUS_ERR_INVALID_SLOT             0x05         // Schedule Slot ID không hợp lệ
#define STATUS_ERR_WRONG_PASSWORD           0x06         // Sai mật khẩu (cho Type 10)
#define STATUS_ERR_MALFORMED                0x07         // Gói tin Client gửi bị sai cấu trúc
#define STATUS_ERR_INVALID_GARDEN           0x08         // Garden ID không tồn tại / Duplicate
#define STATUS_ERR_UNKNOW                   0x09         // Gói tin có type không xác định
#define STATUS_ERR_GARDEN_NOT_EMPTY         0x0A         // Lỗi xóa Garden khi chưa xóa hết device ID 

//ALERT CODES       
#define ALERT_WATERING_START                0x10         // Bơm bắt đầu tưới
#define ALERT_WATERING_END                  0x11         // Bơm đã tưới xong
#define ALERT_FERTILIZE_START               0x12         // Bắt đầu bón phân
#define ALERT_FERTILIZE_END                 0x13         // Bón phân xong
#define ALERT_LIGHTS_ON                     0x20         // Đèn đã bật
#define ALERT_LIGHTS_OFF                    0x21         // Đèn đã tắt


// Kích thước buffer tối đa
#define MAX_BUFFER_SIZE                     256
#define MAX_DEVICES                         50
#define MAX_DEVICES_PER_GARDEN              10
#define MAX_GARDENS                         10
#define APPID_FIXED_LENGTH                  8
#define MAX_TIME_STAMP                      50

// --- Cấu trúc cho dữ liệu đã giải gói tin ---

// 1. Connect
typedef struct {
    char appID[APPID_FIXED_LENGTH + 1];
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

// 4. DATA 
typedef struct {
    uint8_t  dev_id;
    uint32_t timestamp; // 4 bytes (Cần htonl/ntohl)
    uint8_t  humidity;
    uint8_t  n_level;
    uint8_t  p_level;
    uint8_t  k_level;
} IntervalData;

// 5. ALERT 
typedef struct {
    uint32_t timestamp; // 4 bytes (Cần htonl/ntohl)
    uint8_t  alert_code;
    uint8_t  dev_id;
    uint8_t  alert_value;
} Alert; 

// 6. CMD_RESPONSE 
typedef struct {
    uint8_t status_code;
} CmdResponse; 

// 7. Add Garden
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  garden_id;
} GardenAdd; 

// 8. Delete Garden
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  garden_id;
} GardenDel; 


// 9. Add Device 
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  garden_id;
    uint8_t  dev_id;
} DeviceAdd; 

// 10. Delete Device 
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  garden_id;
    uint8_t  dev_id;
} DeviceDel; 

// 11. Set parameters
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  dev_id;
    uint8_t  param_id;
    uint8_t  param_value;
} SetParameter;

// 12. Set pump schedule
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  dev_id;
    uint8_t  param_id;
    uint8_t  quantity_time; // Số lần tưới trong ngày
    uint32_t time[MAX_TIME_STAMP]; // Giờ bắt đầu (HH:MM)
} SetPumpSchedule;

// 13. Set light schedule
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  dev_id;
    uint8_t  param_id;
    uint8_t  quantity_time; // Số lần bật&tắt trong ngày
    uint32_t time[MAX_TIME_STAMP]; // Giờ bật/tắt (HH:MM)
} SetLightSchedule;

// 14. Change Password
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    char appID[APPID_FIXED_LENGTH + 1];
    char old_password[MAX_BUFFER_SIZE - 10]; // Buffer để chứa mật khẩu cũ
    char     new_password[MAX_BUFFER_SIZE - 6]; // Buffer để chứa mật khẩu mới
    uint8_t  old_pass_len;
} ChangePassword;
// 15. Set direct pump command
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  dev_id;
    uint8_t btn; // bật/tắt
} SetDirectPump;

// 16. Set direct light command
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  dev_id;
    uint8_t btn; // bật/tắt
} SetDirectLight;

//17. Set direct fert command
typedef struct {
    uint32_t token; // 4 bytes (Cần htonl/ntohl)
    uint8_t  dev_id;
    uint8_t btn; // bật/tắt
} SetDirectFert;


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
        IntervalData interval_data;
        Alert alert;
        CmdResponse cmd_response;
        GardenAdd garden_add;
        GardenDel garden_del;
        DeviceAdd device_add;
        DeviceDel device_del; 
        SetParameter set_parameter;
        SetPumpSchedule set_pump_schedule;
        SetLightSchedule set_light_schedule;
        ChangePassword change_password;
        SetDirectPump set_direct_pump;
        SetDirectLight set_direct_light;
        SetDirectFert set_direct_fert;
    } data;
} ParsedPacket;

// --- Khai báo các hàm GÓI TIN (Serialization) ---

/**
 * @brief Gói tin Connect Request (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer
 */
int serialize_connect_request(const char* appID, const char* password, uint8_t* out_buffer);

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

/**
 * @brief Gói tin Interval DATA (Device -> Server)
 * @return Tổng số byte đã ghi vào buffer
 */
int serialize_interval_data(const IntervalData* data, uint8_t* out_buffer);

/**
 * @brief Gói tin ALERT (Device -> Server)
 * @return Tổng số byte đã ghi vào buffer
 */
int serialize_alert(const Alert* alert, uint8_t* out_buffer);

/**
 * @brief Gói tin CMD_RESPONSE (Server -> Client)
 * @return Tổng số byte đã ghi vào buffer (luôn là 3)
 */
int serialize_cmd_response(uint8_t status_code, uint8_t* out_buffer);

/**
 * @brief Gói tin Add Garden (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer (luôn là 7)
 */
int serialize_garden_add(uint32_t token, uint8_t garden_id, uint8_t* out_buffer);

/**
 * @brief Gói tin Delete Garden (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer (luôn là 7)
 */
int serialize_garden_del(uint32_t token, uint8_t garden_id, uint8_t* out_buffer);

/**
 * @brief Gói tin Add Device (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer (luôn là 8)
 */
int serialize_device_add(uint32_t token, uint8_t garden_id, uint8_t dev_id, uint8_t* out_buffer);

/**
 * @brief Gói tin Delete Device (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer (luôn là 8)
 */
int serialize_device_del(uint32_t token, uint8_t garden_id, uint8_t dev_id, uint8_t* out_buffer);

/**
 * @brief Gói tin Set Parameter (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_set_parameter(uint32_t token, uint8_t dev_id, uint8_t param_id, uint8_t param_value, uint8_t* out_buffer);

/**
 * @brief Gói tin Set Pump Schedule (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_set_pump_schedule(uint32_t token, uint8_t dev_id, uint8_t param_id, uint8_t quantity_time, const uint32_t* time_array, uint8_t* out_buffer);

/**
 * @brief Gói tin Set Light Schedule (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_set_light_schedule(uint32_t token, uint8_t dev_id, uint8_t param_id, uint8_t quantity_time, const uint32_t* time_array, uint8_t* out_buffer);

/**
 * @brief Gói tin Change Password (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_change_password(uint32_t token, const char* appID, uint8_t old_password_len, const char* old_password, const char* new_password, uint8_t* out_buffer);

/**
 * @brief Gói tin Set Direct Pump Command (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_set_direct_pump(uint32_t token, uint8_t dev_id, uint8_t btn, uint8_t* out_buffer);

/**
 * @brief Gói tin Set Direct Light Command (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_set_direct_light(uint32_t token, uint8_t dev_id, uint8_t btn, uint8_t* out_buffer);

/**
 * @brief Gói tin Set Direct Fert Command (Client -> Server)
 * @return Tổng số byte đã ghi vào buffer 
 */
int serialize_set_direct_fert(uint32_t token, uint8_t dev_id, uint8_t btn, uint8_t* out_buffer);

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