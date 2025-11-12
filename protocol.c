#include "protocol.h"
#include <stdio.h> 

//SERIALIZATION

int serialize_connect_request(const char* password, uint8_t* out_buffer) {
    uint8_t pass_len = (uint8_t)strlen(password);
    
    out_buffer[0] = 10; // type
    out_buffer[1] = pass_len; // length
    memcpy(out_buffer + 2, password, pass_len); // payload
    
    return 2 + pass_len; // Tổng kích thước packet
}

int serialize_connect_response(uint32_t token, uint8_t* out_buffer) {
    out_buffer[0] = 11; // type
    out_buffer[1] = 4;  // length
    memcpy(out_buffer + 2, &token, 4); 
    
    return 2 + 4; // 6 bytes
}

int serialize_scan_request(uint32_t token, uint8_t* out_buffer) {
    out_buffer[0] = 20; // type
    out_buffer[1] = 4;  // length
    memcpy(out_buffer + 2, &token, 4); // payload
    
    return 2 + 4; // 6 bytes
}

int serialize_scan_response(uint8_t num_devices, const uint8_t* device_ids, uint8_t* out_buffer) {
    uint8_t payload_len = 1 + num_devices; // n (1 byte) + n device_ids
    
    out_buffer[0] = 21;          // type
    out_buffer[1] = payload_len; // length
    
    // Bắt đầu payload
    out_buffer[2] = num_devices; // n (số lượng thiết bị)
    memcpy(out_buffer + 3, device_ids, num_devices); // danh sách IDs
    
    return 2 + payload_len; // Tổng kích thước
}

int serialize_info_request(uint32_t token, uint8_t* out_buffer) {
    out_buffer[0] = 30; // type
    out_buffer[1] = 4;  // length
    memcpy(out_buffer + 2, &token, 4); // payload
    
    return 2 + 4; // 6 bytes
}

int serialize_info_response(const InfoResponse* info_data, uint8_t* out_buffer) {
    out_buffer[0] = 31; // type
    
    uint8_t* payload_ptr = out_buffer + 2; 
    int payload_len = 0;
    
    // n1 (số lượng vườn)
    *payload_ptr = info_data->num_gardens;
    payload_ptr++;
    payload_len++;
    
    for (int i = 0; i < info_data->num_gardens; i++) {
        // id vườn i
        *payload_ptr = info_data->gardens[i].garden_id;
        payload_ptr++;
        payload_len++;
        
        // số lượng thiết bị trong vườn i
        *payload_ptr = info_data->gardens[i].num_devices;
        payload_ptr++;
        payload_len++;
        
        // danh sách thiết bị
        for (int j = 0; j < info_data->gardens[i].num_devices; j++) {
            *payload_ptr = info_data->gardens[i].devices[j].device_id;
            payload_ptr++;
            payload_len++;
        }
    }
    
    out_buffer[1] = (uint8_t)payload_len; // Ghi lại length
    
    return 2 + payload_len; 
}

//DESERIALIZATION

int deserialize_packet(const uint8_t* in_buffer, int buffer_len, ParsedPacket* out_packet) {
    if (buffer_len < 2) {
        return -1; // Lỗi: Không đủ header
    }
    
    out_packet->type = in_buffer[0];
    out_packet->length = in_buffer[1];
    
    const uint8_t* payload = in_buffer + 2;
    uint8_t payload_len = out_packet->length;
    
    if (buffer_len < 2 + payload_len) {
        return -1; // Lỗi: Packet không hoàn chỉnh
    }
    
    // Xử lý dựa trên type
    switch (out_packet->type) {
        case 10: // Connect Request
            // Truncate nếu mật khẩu quá dài
            out_packet->data.connect_req.pass_len = (payload_len >= sizeof(out_packet->data.connect_req.password)) ? 
                                                    sizeof(out_packet->data.connect_req.password) - 1 : payload_len;
            memcpy(out_packet->data.connect_req.password, payload, out_packet->data.connect_req.pass_len);
            out_packet->data.connect_req.password[out_packet->data.connect_req.pass_len] = '\0'; // null-terminate
            break;
            
        case 11: // Connect Response
            if (payload_len != 4) return -1; // Lỗi: Sai length
            memcpy(&out_packet->data.connect_res.token, payload, 4);
            break;
            
        case 20: // Scan Request
            if (payload_len != 4) return -1; // Lỗi: Sai length
            memcpy(&out_packet->data.scan_req.token, payload, 4);
            break;
            
        case 21: // Scan Response
            if (payload_len < 1) return -1; // Lỗi: Phải có ít nhất 'n'
            out_packet->data.scan_res.num_devices = payload[0]; // n
            if (payload_len != (1 + out_packet->data.scan_res.num_devices)) return -1; // Lỗi: length không khớp
            if (out_packet->data.scan_res.num_devices > MAX_DEVICES) return -1; // Lỗi: Quá nhiều thiết bị
            
            memcpy(out_packet->data.scan_res.device_ids, payload + 1, out_packet->data.scan_res.num_devices);
            break;
            
        case 30: // Info Request
            if (payload_len != 4) return -1; // Lỗi: Sai length
            memcpy(&out_packet->data.info_req.token, payload, 4);
            break;
            
        case 31: // Info Response
            {
                int offset = 0;
                if (payload_len < 1) return -1; // Lỗi: Phải có n1
                
                out_packet->data.info_res.num_gardens = payload[offset]; // n1
                offset++;
                
                if (out_packet->data.info_res.num_gardens > MAX_GARDENS) return -1; // Lỗi: Quá nhiều vườn
                
                for (int i = 0; i < out_packet->data.info_res.num_gardens; i++) {
                    if (offset + 2 > payload_len) return -1; // Lỗi: Thiếu dữ liệu cho id_vườn +
                    
                    GardenInfo* garden = &out_packet->data.info_res.gardens[i];
                    garden->garden_id = payload[offset];
                    offset++;
                    garden->num_devices = payload[offset];
                    offset++;
                    
                    if (garden->num_devices > MAX_DEVICES) return -1; // Lỗi: Quá nhiều thiết bị
                    if (offset + garden->num_devices > payload_len) return -1; // Lỗi: Thiếu dữ liệu
                    
                    for (int j = 0; j < garden->num_devices; j++) {
                        garden->devices[j].device_id = payload[offset];
                        offset++;
                    }
                }
                
                if (offset != payload_len) return -1; 
            }
            break;
            
        default:
            return -1; // Lỗi: Type không xác định
    }
    
    return 0; 
}