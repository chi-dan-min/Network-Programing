#include "protocol.h"
#include <stdio.h> 

//SERIALIZATION

int serialize_connect_request(const char* appID, const char* password, uint8_t* out_buffer) {
    uint8_t pass_len = (uint8_t)strlen(password);
    uint8_t appID_len = (uint8_t)strlen(appID);
    out_buffer[0] = 10; // type
    out_buffer[1] = pass_len; // length
    memset(out_buffer + 2, 0, APPID_FIXED_LENGTH);
    memcpy(out_buffer + 2 + APPID_FIXED_LENGTH - appID_len, appID, appID_len); 
    memcpy(out_buffer + 2 + APPID_FIXED_LENGTH, password, pass_len); // payload
    
    return 2 + APPID_FIXED_LENGTH +pass_len; // Tổng kích thước packet
}

int serialize_connect_response(uint32_t token, uint8_t* out_buffer) {
    out_buffer[0] = 11; // type
    out_buffer[1] = 4;  // length
    uint32_t net_token = htonl(token); // chuyển token sang network byte order
    memcpy(out_buffer + 2, &net_token, 4);
    
    return 2 + 4; // 6 bytes
}

int serialize_scan_request(uint32_t token, uint8_t* out_buffer) {
    out_buffer[0] = 20; // type
    out_buffer[1] = 4;  // length
    uint32_t net_token = htonl(token); // chuyển token sang network byte order
    memcpy(out_buffer + 2, &net_token, 4); // payload
    
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
    uint32_t net_token = htonl(token); // chuyển token sang network byte order
    memcpy(out_buffer + 2, &net_token, 4); // payload
    
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
        return -1; // Không đủ header
    }

    out_packet->type = in_buffer[0];
    out_packet->length = in_buffer[1];

    const uint8_t* payload = in_buffer + 2;
    uint8_t payload_len = out_packet->length;

    if (buffer_len < 2 + payload_len) {
        return -1; // Packet không hoàn chỉnh
    }

    switch (out_packet->type) {

        //------------------------------
        // 10 - Connect Request
        //------------------------------
        case MSG_TYPE_CONNECT_CLIENT: {
            uint8_t pass_len = out_packet->length - APPID_FIXED_LENGTH;
            const uint8_t* appID_ptr = payload;
            const uint8_t* pass_ptr = appID_ptr + APPID_FIXED_LENGTH;

            int first_nonzero = 0;
            while (first_nonzero < APPID_FIXED_LENGTH && appID_ptr[first_nonzero] == 0)
                first_nonzero++;

            int appID_len = APPID_FIXED_LENGTH - first_nonzero;
            memcpy(out_packet->data.connect_req.appID, appID_ptr + first_nonzero, appID_len);
            out_packet->data.connect_req.appID[appID_len] = '\0';

            out_packet->data.connect_req.pass_len =
                (pass_len >= sizeof(out_packet->data.connect_req.password))
                    ? sizeof(out_packet->data.connect_req.password) - 1
                    : pass_len;

            memcpy(out_packet->data.connect_req.password,
                   pass_ptr,
                   out_packet->data.connect_req.pass_len);
            out_packet->data.connect_req.password[out_packet->data.connect_req.pass_len] = '\0';
            break;
        }

        //------------------------------
        // 11 - Connect Response
        //------------------------------
        case MSG_TYPE_CONNECT_SERVER: {
            if (payload_len != 4) return -1;
            memcpy(&out_packet->data.connect_res.token, payload, 4);
            break;
        }

        //------------------------------
        // 20 - Scan Request
        //------------------------------
        case MSG_TYPE_SCAN_CLIENT: {
            if (payload_len != 4) return -1;
            memcpy(&out_packet->data.scan_req.token, payload, 4);
            break;
        }

        //------------------------------
        // 21 - Scan Response
        //------------------------------
        case MSG_TYPE_SCAN_SERVER: {
            if (payload_len < 1) return -1;
            out_packet->data.scan_res.num_devices = payload[0];

            if (out_packet->data.scan_res.num_devices > MAX_DEVICES) return -1;
            if (payload_len != 1 + out_packet->data.scan_res.num_devices) return -1;

            memcpy(out_packet->data.scan_res.device_ids,
                   payload + 1,
                   out_packet->data.scan_res.num_devices);
            break;
        }

        //------------------------------
        // 30 - Info Request
        //------------------------------
        case MSG_TYPE_INFO_CLIENT: {
            if (payload_len != 4) return -1;
            memcpy(&out_packet->data.info_req.token, payload, 4);
            break;
        }

        //------------------------------
        // 31 - Info Response
        //------------------------------
        case MSG_TYPE_INFO_SERVER: {
            int offset = 0;
            if (payload_len < 1) return -1;

            out_packet->data.info_res.num_gardens = payload[offset++];
            if (out_packet->data.info_res.num_gardens > MAX_GARDENS) return -1;

            for (int i = 0; i < out_packet->data.info_res.num_gardens; i++) {
                if (offset + 2 > payload_len) return -1;

                GardenInfo* garden = &out_packet->data.info_res.gardens[i];
                garden->garden_id = payload[offset++];
                garden->num_devices = payload[offset++];

                if (garden->num_devices > MAX_DEVICES) return -1;
                if (offset + garden->num_devices > payload_len) return -1;

                for (int j = 0; j < garden->num_devices; j++) {
                    garden->devices[j].device_id = payload[offset++];
                }
            }

            if (offset != payload_len) return -1;
            break;
        }

        //------------------------------
        // 80 - Garden Add
        //------------------------------
        case MSG_TYPE_GARDEN_ADD: {
            if (payload_len < 1) return -1;
            out_packet->data.garden_add.garden_id = payload[0];
            break;
        }

        //------------------------------
        // 81 - Garden Delete
        //------------------------------
        case MSG_TYPE_GARDEN_DEL: {
            if (payload_len < 1) return -1;
            out_packet->data.garden_del.garden_id = payload[0];
            break;
        }

        //------------------------------
        // 90 - Device Add
        //------------------------------
        case MSG_TYPE_DEVICE_ADD: {
            if (payload_len < 2) return -1;
            out_packet->data.device_add.garden_id = payload[0];
            out_packet->data.device_add.device_id = payload[1];
            break;
        }

        //------------------------------
        // 91 - Device Delete
        //------------------------------
        case MSG_TYPE_DEVICE_DEL: {
            if (payload_len < 2) return -1;
            out_packet->data.device_del.garden_id = payload[0];
            out_packet->data.device_del.device_id = payload[1];
            break;
        }

        //------------------------------
        // 100 - Data 
        //------------------------------
        case MSG_TYPE_DATA: {
            if (payload_len < sizeof(DeviceInfo)) return -1;
            memcpy(&out_packet->data.device_data, payload, sizeof(DeviceInfo));
            break;
        }

        //------------------------------
        // 200 - Alert 
        //------------------------------
        case MSG_TYPE_ALERT: {
            if (payload_len < 2) return -1;
            out_packet->data.alert.device_id = payload[0];
            out_packet->data.alert.code = payload[1];
            break;
        }

        //------------------------------
        // 254 - Command Response
        //------------------------------
        case MSG_TYPE_CMD_RESPONSE: {
            if (payload_len < 2) return -1;
            out_packet->data.cmd_res.device_id = payload[0];
            out_packet->data.cmd_res.status = payload[1];
            break;
        }

        //------------------------------
        // Unknown type
        //------------------------------
        default:
            return -1;
    }

    return 0;
}
