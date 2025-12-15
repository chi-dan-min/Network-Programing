#include "client_api.h"
#include "protocol.c" // Tận dụng các hàm serialization/deserialization
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>

#define MAX_RECV_SIZE 512 

extern "C" {

// ------------------------------------
// Utility Functions
// ------------------------------------

/**
 * @brief Gửi gói tin và nhận CMD_RESPONSE (Type 254).
 * @return STATUS_CODE nếu nhận được, hoặc STATUS_ERR_FAILED/STATUS_ERR_MALFORMED
 */
static int send_request_and_get_status(int sockfd, const uint8_t *send_buffer, int send_len) {
    uint8_t recv_buffer[MAX_RECV_SIZE];
    
    if (send(sockfd, send_buffer, send_len, 0) <= 0) {
        return STATUS_ERR_FAILED;
    }

    int recv_len = recv(sockfd, recv_buffer, MAX_RECV_SIZE, 0);
    if (recv_len <= 0) {
        return STATUS_ERR_FAILED;
    }

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, recv_len, &packet) != 0) {
        return STATUS_ERR_MALFORMED;
    }

    if (packet.type == MSG_TYPE_CMD_RESPONSE) {
        return packet.data.cmd_response.status_code;
    }
    
    if (packet.type == MSG_TYPE_CONNECT_SERVER) {
         return STATUS_OK; // Xử lý trường hợp đổi pass thành công
    }

    return STATUS_ERR_UNKNOW;
}

/**
 * @brief Gửi gói tin và nhận phản hồi phức tạp (SCAN, INFO, SETTINGS).
 * @return Kích thước gói tin nhận được (dương) hoặc mã lỗi âm (-STATUS_CODE).
 */
static int send_request_and_get_complex_response(int sockfd, const uint8_t *send_buffer, int send_len, uint8_t expected_type, uint8_t *out_buffer) {
    if (send(sockfd, send_buffer, send_len, 0) <= 0) {
        return -(int)STATUS_ERR_FAILED;
    }

    int recv_len = recv(sockfd, out_buffer, MAX_RECV_SIZE, 0);
    if (recv_len <= 0) {
        return -(int)STATUS_ERR_FAILED;
    }

    if (out_buffer[0] == MSG_TYPE_CMD_RESPONSE) { 
        // Xử lý CMD_RESPONSE (Type 254)
        ParsedPacket p;
        if(deserialize_packet(out_buffer, recv_len, &p) == 0)
            return -(int)p.data.cmd_response.status_code;
        return -(int)STATUS_ERR_MALFORMED;
    }
    
    if (out_buffer[0] == expected_type) { 
        // Gói tin mong muốn (Type 21, 31, 71)
        return recv_len; 
    }

    return -(int)STATUS_ERR_UNKNOW; 
}


// ------------------------------------
// CORE CONNECTION
// ------------------------------------
int api_connect_server(const char *ip_addr, uint16_t port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { return -1; }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr, &servaddr.sin_addr) <= 0) { close(sockfd); return -2; }
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) { close(sockfd); return -3; }
    
    return sockfd;
}

int api_login(int sockfd, const char *appID, const char *password, uint32_t *out_token) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    
    int packet_len = serialize_connect_request(appID, password, send_buffer);
    
    if (send(sockfd, send_buffer, packet_len, 0) <= 0) { return STATUS_ERR_FAILED; }

    int recv_len = recv(sockfd, recv_buffer, MAX_RECV_SIZE, 0);
    if (recv_len <= 0) { return STATUS_ERR_FAILED; }

    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, recv_len, &packet) != 0) { return STATUS_ERR_MALFORMED; }

    if (packet.type == MSG_TYPE_CONNECT_SERVER) { 
        if (out_token) { *out_token = packet.data.connect_res.token; }
        return STATUS_OK;
    } 
    else if (packet.type == MSG_TYPE_CMD_RESPONSE) { 
        return packet.data.cmd_response.status_code; 
    }
    
    return STATUS_ERR_UNKNOW;
}

void api_cleanup(int sockfd) {
    if(sockfd > 0)
        close(sockfd);
}

// ------------------------------------
// MONITORING & INFO
// ------------------------------------
int api_scan(int sockfd, uint32_t token, uint8_t *out_buffer) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_scan_request(token, send_buffer);
    
    return send_request_and_get_complex_response(sockfd, send_buffer, send_len, 
                                                 MSG_TYPE_SCAN_SERVER, out_buffer);
}

int api_info(int sockfd, uint32_t token, uint8_t *out_buffer) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_info_request(token, send_buffer);
    
    return send_request_and_get_complex_response(sockfd, send_buffer, send_len, 
                                                 MSG_TYPE_INFO_SERVER, out_buffer);
}

int api_get_settings(int sockfd, uint32_t token, uint8_t dev_id, uint8_t *out_buffer) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_settings_request(token, dev_id, send_buffer);
    
    return send_request_and_get_complex_response(sockfd, send_buffer, send_len, 
                                                 MSG_TYPE_SETTINGS_SERVER, out_buffer);
}

// ------------------------------------
// MANAGEMENT
// ------------------------------------
int api_add_garden(int sockfd, uint32_t token, uint8_t garden_id) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_garden_add(token, garden_id, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_delete_garden(int sockfd, uint32_t token, uint8_t garden_id) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_garden_del(token, garden_id, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_add_device(int sockfd, uint32_t token, uint8_t garden_id, uint8_t dev_id) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_device_add(token, garden_id, dev_id, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_delete_device(int sockfd, uint32_t token, uint8_t garden_id, uint8_t dev_id) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_device_del(token, garden_id, dev_id, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

// ------------------------------------
// SETTINGS
// ------------------------------------
int api_set_parameter(int sockfd, uint32_t token, uint8_t garden_id, uint8_t dev_id, uint8_t param_id, uint8_t param_value) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_set_parameter(token, garden_id, dev_id, param_id, param_value, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_change_password(int sockfd, uint32_t token, const char *appID, const char *old_password, const char *new_password) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t old_pass_len = (uint8_t)strlen(old_password);

    int send_len = serialize_change_password(token, appID, 
                                           old_pass_len, 
                                           old_password, 
                                           new_password, 
                                           send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

// ------------------------------------
// CONTROL & SCHEDULE
// ------------------------------------
int api_set_pump_schedule(int sockfd, uint32_t token, uint8_t dev_id, uint8_t quantity_time, const uint32_t *time_array) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_set_pump_schedule(token, dev_id, quantity_time, time_array, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_set_light_schedule(int sockfd, uint32_t token, uint8_t dev_id, uint8_t quantity_time_pairs, const uint32_t *time_array) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_set_light_schedule(token, dev_id, quantity_time_pairs, time_array, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_set_direct_pump(int sockfd, uint32_t token, uint8_t dev_id, bool state) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_set_direct_pump(token, dev_id, (uint8_t)state, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_set_direct_light(int sockfd, uint32_t token, uint8_t dev_id, bool state) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_set_direct_light(token, dev_id, (uint8_t)state, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

int api_set_direct_fert(int sockfd, uint32_t token, uint8_t dev_id, bool state) {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    int send_len = serialize_set_direct_fert(token, dev_id, (uint8_t)state, send_buffer);
    
    return send_request_and_get_status(sockfd, send_buffer, send_len);
}

} // extern "C"