#ifndef CLIENT_API_H
#define CLIENT_API_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include "protocol.h" // Chứa các định nghĩa TYPE và STATUS_CODE

#ifdef __cplusplus
extern "C" {
#endif

// --- CORE CONNECTION (Trả về sockfd hoặc lỗi âm) ---
int api_connect_server(const char *ip_addr, uint16_t port);
int api_login(int sockfd, const char *appID, const char *password, uint32_t *out_token);
void api_cleanup(int sockfd);

// --- MONITORING & INFO (Trả về kích thước gói tin (dương) hoặc mã lỗi âm (-STATUS_CODE)) ---
/**
 * @brief Yêu cầu quét các thiết bị (Type 20). Nhận lại gói tin SCAN_SERVER (Type 21).
 */
int api_scan(int sockfd, uint32_t token, uint8_t *out_buffer);

/**
 * @brief Yêu cầu thông tin chi tiết Gardens/Devices (Type 30). Nhận lại gói tin INFO_SERVER (Type 31).
 */
int api_info(int sockfd, uint32_t token, uint8_t *out_buffer);

/**
 * @brief Yêu cầu cấu hình thiết bị (Type 70). Nhận lại gói tin SETTINGS_SERVER (Type 71).
 */
int api_get_settings(int sockfd, uint32_t token, uint8_t dev_id, uint8_t *out_buffer);

// --- MANAGEMENT (Trả về STATUS_CODE) ---
int api_add_garden(int sockfd, uint32_t token, uint8_t garden_id);
int api_delete_garden(int sockfd, uint32_t token, uint8_t garden_id);
int api_add_device(int sockfd, uint32_t token, uint8_t garden_id, uint8_t dev_id);
int api_delete_device(int sockfd, uint32_t token, uint8_t garden_id, uint8_t dev_id);

// --- SETTINGS (Trả về STATUS_CODE) ---
int api_set_parameter(int sockfd, uint32_t token, uint8_t garden_id, uint8_t dev_id, uint8_t param_id, uint8_t param_value);
int api_change_password(int sockfd, uint32_t token, const char *appID, const char *old_password, const char *new_password);

// --- CONTROL & SCHEDULE (Trả về STATUS_CODE) ---
int api_set_pump_schedule(int sockfd, uint32_t token, uint8_t dev_id, uint8_t quantity_time, const uint32_t *time_array);
int api_set_light_schedule(int sockfd, uint32_t token, uint8_t dev_id, uint8_t quantity_time_pairs, const uint32_t *time_array);
int api_set_direct_pump(int sockfd, uint32_t token, uint8_t dev_id, bool state);
int api_set_direct_light(int sockfd, uint32_t token, uint8_t dev_id, bool state);
int api_set_direct_fert(int sockfd, uint32_t token, uint8_t dev_id, bool state);


#ifdef __cplusplus
}
#endif

#endif // CLIENT_API_H