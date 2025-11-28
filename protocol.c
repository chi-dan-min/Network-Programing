#include "protocol.h"
#include <stdio.h> 

//SERIALIZATION

int serialize_connect_request(const char* appID, const char* password, uint8_t* out_buffer) {
    uint8_t pass_len = (uint8_t)strlen(password);
    uint8_t appID_len = (uint8_t)strlen(appID);
    out_buffer[0] = MSG_TYPE_CONNECT_CLIENT; // type
    out_buffer[1] = pass_len + appID_len; // length
    memset(out_buffer + 2, 0, APPID_FIXED_LENGTH);
    memcpy(out_buffer + 2 + APPID_FIXED_LENGTH - appID_len, appID, appID_len); 
    memcpy(out_buffer + 2 + APPID_FIXED_LENGTH, password, pass_len); // payload
    
    return 2 + APPID_FIXED_LENGTH +pass_len; // Tổng kích thước packet
}

int serialize_connect_response(uint32_t token, uint8_t* out_buffer) {
    out_buffer[0] = MSG_TYPE_CONNECT_SERVER; // type
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

int serialize_interval_data(const IntervalData* data, uint8_t* out_buffer) {
    if (!data || !out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_DATA;
    out_buffer[1] = 1 + 4 + 4;  // dev_id(1) + timestamp(4) + humidity/n/p/k (4)

    out_buffer[2] = data->dev_id;

    uint32_t ts = htonl(data->timestamp);
    memcpy(&out_buffer[3], &ts, 4);

    out_buffer[7] = data->humidity;
    out_buffer[8] = data->n_level;
    out_buffer[9] = data->p_level;
    out_buffer[10] = data->k_level;

    return 11; // tổng 11 byte
}

int serialize_alert(const Alert* alert, uint8_t* out_buffer) {
    if (!alert || !out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_ALERT;
    out_buffer[1] = 4 + 3;  // timestamp(4) + alert_code + dev_id + alert_value

    uint32_t ts = htonl(alert->timestamp);
    memcpy(&out_buffer[2], &ts, 4);

    out_buffer[6] = alert->alert_code;
    out_buffer[7] = alert->dev_id;
    out_buffer[8] = alert->alert_value;

    return 9;
}

int serialize_cmd_response(uint8_t status_code, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_CMD_RESPONSE;
    out_buffer[1] = 1;  // chỉ có 1 byte status

    out_buffer[2] = status_code;

    return 3;
}


int serialize_garden_add(uint32_t token, uint8_t garden_id, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_GARDEN_ADD;
    out_buffer[1] = 4 + 1;  // token(4) + garden_id(1)

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = garden_id;

    return 7;
}

int serialize_garden_del(uint32_t token, uint8_t garden_id, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_GARDEN_DEL;
    out_buffer[1] = 4 + 1;

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = garden_id;

    return 7;
}

int serialize_device_add(uint32_t token, uint8_t garden_id, uint8_t dev_id, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_DEVICE_ADD;
    out_buffer[1] = 4 + 2;  // token + garden_id + dev_id

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = garden_id;
    out_buffer[7] = dev_id;

    return 8;
}

int serialize_device_del(uint32_t token, uint8_t garden_id, uint8_t dev_id, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_DEVICE_DEL;
    out_buffer[1] = 4 + 2;

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = garden_id;
    out_buffer[7] = dev_id;

    return 8;
}

int serialize_set_parameter(uint32_t token, uint8_t dev_id, uint8_t param_id, uint8_t param_value, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_SET_PARAMETER;
    out_buffer[1] = 4 + 3;  // token(4) + dev_id(1) + param_id(1) + param_value(1)

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = dev_id;
    out_buffer[7] = param_id;
    out_buffer[8] = param_value;

    return 9;
}

int serialize_set_pump_schedule(uint32_t token, uint8_t dev_id, uint8_t param_id, uint8_t quantity_time, const uint32_t* time_array, uint8_t* out_buffer) {
    if (!out_buffer || !time_array) return -1;

    out_buffer[0] = MSG_TYPE_SET_PUMP_SCHEDULE;
    out_buffer[1] = 4 + 3 + (quantity_time * 4);  // token(4) + dev_id(1) + param_id(1) + quantity_time(1) + time_array

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = dev_id;
    out_buffer[7] = param_id;
    out_buffer[8] = quantity_time;

    for (int i = 0; i < quantity_time; i++) {
        uint32_t net_time = htonl(time_array[i]);
        memcpy(&out_buffer[9 + i * 4], &net_time, 4);
    }

    return 9 + (quantity_time * 4);
}
int serialize_set_light_schedule(uint32_t token, uint8_t dev_id, uint8_t param_id, uint8_t quantity_time, const uint32_t* time_array, uint8_t* out_buffer) {
    if (!out_buffer || !time_array) return -1;

    out_buffer[0] = MSG_TYPE_SET_LIGHT_SCHEDULE;
    out_buffer[1] = 4 + 3 + (quantity_time * 4);  // token(4) + dev_id(1) + param_id(1) + quantity_time(1) + time_array

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = dev_id;
    out_buffer[7] = param_id;
    out_buffer[8] = quantity_time;

    for (int i = 0; i < quantity_time; i++) {
        uint32_t net_time = htonl(time_array[i]);
        memcpy(&out_buffer[9 + i * 4], &net_time, 4);
    }

    return 9 + (quantity_time * 4);
}

int serialize_change_password(uint32_t token, const char* appID, uint8_t old_password_len, const char* old_password, const char* new_password, uint8_t* out_buffer) {
    if (!out_buffer || !new_password) return -1;
    uint8_t new_password_len = (uint8_t)strlen(new_password);
    out_buffer[0] = MSG_TYPE_CHANGE_PASSWORD;
    out_buffer[1] = 4 + APPID_FIXED_LENGTH + 1 + old_password_len + new_password_len;  // token(4) + appID + old_pass_len(1) + old_pass + new_pass
    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);
    memcpy(out_buffer + 6, appID, APPID_FIXED_LENGTH);
    out_buffer[6 + APPID_FIXED_LENGTH] = old_password_len;
    memcpy(out_buffer + 7 + APPID_FIXED_LENGTH, old_password, old_password_len);
    memcpy(out_buffer + 7 + APPID_FIXED_LENGTH + old_password_len, new_password, new_password_len);
    return 7 + APPID_FIXED_LENGTH + 1 + old_password_len + new_password_len;
}

int serialize_set_direct_pump(uint32_t token, uint8_t dev_id, uint8_t btn, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_SET_DIRECT_PUMP;
    out_buffer[1] = 4 + 2;  // token(4) + dev_id(1) + btn(1)

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = dev_id;
    out_buffer[7] = btn;

    return 8;
}

int serialize_set_direct_light(uint32_t token, uint8_t dev_id, uint8_t btn, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_SET_DIRECT_LIGHT;
    out_buffer[1] = 4 + 2;  // token(4) + dev_id(1) + btn(1)

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = dev_id;
    out_buffer[7] = btn;

    return 8;
}

int serialize_set_direct_fert(uint32_t token, uint8_t dev_id, uint8_t btn, uint8_t* out_buffer) {
    if (!out_buffer) return -1;

    out_buffer[0] = MSG_TYPE_SET_DIRECT_FERT;
    out_buffer[1] = 4 + 2;  // token(4) + dev_id(1) + btn(1)

    uint32_t t = htonl(token);
    memcpy(&out_buffer[2], &t, 4);

    out_buffer[6] = dev_id;
    out_buffer[7] = btn;

    return 8;
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
            uint32_t net_token;
            memcpy(&net_token, payload, 4);
            out_packet->data.connect_res.token = ntohl(net_token);
            break;
        }

        //------------------------------
        // 20 - Scan Request
        //------------------------------
        case MSG_TYPE_SCAN_CLIENT: {
            if (payload_len != 4) return -1;
            uint32_t net_token;
            memcpy(&net_token, payload, 4);         // copy 4 byte từ mạng
            out_packet->data.scan_req.token = ntohl(net_token); // chuyển sang host byte order
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
            uint32_t net_token;
            memcpy(&net_token, payload, 4);         // copy 4 byte từ mạng
            out_packet->data.info_req.token = ntohl(net_token); // chuyển sang host byte order
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

                if (garden->num_devices > MAX_DEVICES_PER_GARDEN) return -1;
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
            if (payload_len < 5) return -1; // 4 bytes token + 1 byte garden_id
            out_packet->data.garden_add.token = ntohl(*(uint32_t*)payload);
            out_packet->data.garden_add.garden_id = payload[4];
            break;
        }

        //------------------------------
        // 81 - Garden Delete
        //------------------------------
        case MSG_TYPE_GARDEN_DEL: {
            if (payload_len < 5) return -1; // 4 bytes token + 1 byte garden_id
            out_packet->data.garden_del.token = ntohl(*(uint32_t*)payload);
            out_packet->data.garden_del.garden_id = payload[4];
            break;
        }

        //------------------------------
        // 90 - Device Add
        //------------------------------
        case MSG_TYPE_DEVICE_ADD: {
            if (payload_len < 6) return -1; // 4 bytes token + 1 byte garden_id + 1 byte dev_id
            out_packet->data.device_add.token = ntohl(*(uint32_t*)payload);
            out_packet->data.device_add.garden_id = payload[4];
            out_packet->data.device_add.dev_id = payload[5];
            break;
        }

        //------------------------------
        // 91 - Device Delete
        //------------------------------
        case MSG_TYPE_DEVICE_DEL: {
            if (payload_len < 6) return -1; // 4 bytes token + 1 byte garden_id + 1 byte dev_id
            out_packet->data.device_del.token = ntohl(*(uint32_t*)payload);
            out_packet->data.device_del.garden_id = payload[4];
            out_packet->data.device_del.dev_id = payload[5];
            break;
        }

        //------------------------------
        // 100 - Data 
        //------------------------------
        case MSG_TYPE_DATA: {
            if (payload_len < 9) {
                return -1;
            }

            IntervalData* d = &out_packet->data.interval_data;

            d->dev_id = payload[0];

            uint32_t ts_net;
            memcpy(&ts_net, &payload[1], 4);
            d->timestamp = ntohl(ts_net);

            d->humidity = payload[5];
            d->n_level  = payload[6];
            d->p_level  = payload[7];
            d->k_level  = payload[8];

            break;
        }

        //------------------------------
        // 200 - Alert 
        //------------------------------
        case MSG_TYPE_ALERT: {
            if (payload_len < 2) return -1;
            out_packet->data.alert.dev_id = payload[0];
            out_packet->data.alert.alert_code = payload[1];
            break;
        }

        //------------------------------
        // 254 - Command Response
        //------------------------------
        case MSG_TYPE_CMD_RESPONSE: {
            if (payload_len < 1) return -1;
            out_packet->data.cmd_response.status_code = payload[0];
            break;
        }
        //------------------------------
        // 40 - Set Parameter
        //------------------------------
        case MSG_TYPE_SET_PARAMETER: {
            if (payload_len < 6) return -1;
            out_packet->data.set_parameter.token = ntohl(*(uint32_t*)payload);
            out_packet->data.set_parameter.dev_id = payload[4];
            out_packet->data.set_parameter.param_id = payload[5];
            out_packet->data.set_parameter.param_value = payload[6];
            break;
        }
        //------------------------------
        // 50 - Set Pump Schedule
        //------------------------------
        case MSG_TYPE_SET_PUMP_SCHEDULE: {
            if (payload_len < 7) return -1;
            out_packet->data.set_pump_schedule.token = ntohl(*(uint32_t*)payload);
            out_packet->data.set_pump_schedule.dev_id = payload[4];
            out_packet->data.set_pump_schedule.param_id = payload[5];
            out_packet->data.set_pump_schedule.quantity_time = payload[6];
            if (payload_len != 7 + out_packet->data.set_pump_schedule.quantity_time * 4) return -1;
            for (int i = 0; i < out_packet->data.set_pump_schedule.quantity_time; i++) {
                out_packet->data.set_pump_schedule.time_array[i] = ntohl(*(uint32_t*)(payload + 7 + i * 4));
            }
            break;
        }
        //------------------------------
        // 51 - Set Light Schedule
        //------------------------------
        case MSG_TYPE_SET_LIGHT_SCHEDULE: {
            if (payload_len < 7) return -1;
            out_packet->data.set_light_schedule.token = ntohl(*(uint32_t*)payload);
            out_packet->data.set_light_schedule.dev_id = payload[4];
            out_packet->data.set_light_schedule.param_id = payload[5];
            out_packet->data.set_light_schedule.quantity_time = payload[6];
            if (payload_len != 7 + out_packet->data.set_light_schedule.quantity_time * 4) return -1;
            for (int i = 0; i < out_packet->data.set_light_schedule.quantity_time; i++) {
                out_packet->data.set_light_schedule.time_array[i] = ntohl(*(uint32_t*)(payload + 7 + i * 4));
            }
            break;
        }
        //------------------------------
        // 12 - Change Password
        //------------------------------
        case MSG_TYPE_CHANGE_PASSWORD: {
            if (payload_len < 5 + APPID_FIXED_LENGTH) return -1;
            out_packet->data.change_password.token = ntohl(*(uint32_t*)payload);
            memcpy(out_packet->data.change_password.appID, payload + 4, APPID_FIXED_LENGTH);
            out_packet->data.change_password.appID[APPID_FIXED_LENGTH] = '\0';
            uint8_t old_pass_len = payload[4 + APPID_FIXED_LENGTH];
            if (payload_len < 5 + APPID_FIXED_LENGTH + old_pass_len) return -1;
            memcpy(out_packet->data.change_password.old_password, payload + 5 + APPID_FIXED_LENGTH, old_pass_len);
            out_packet->data.change_password.old_password[old_pass_len] = '\0';
            memcpy(out_packet->data.change_password.new_password, payload + 5 + APPID_FIXED_LENGTH + old_pass_len, payload_len - (5 + APPID_FIXED_LENGTH + old_pass_len));
            out_packet->data.change_password.new_password[payload_len - (5 + APPID_FIXED_LENGTH + old_pass_len)] = '\0';
            out_packet->data.change_password.old_pass_len = old_pass_len;
            break;
        }
        //------------------------------
        // 60 - Set Direct Pump
        //------------------------------
        case MSG_TYPE_SET_DIRECT_PUMP: {
            if (payload_len < 6) return -1;
            out_packet->data.set_direct_pump.token = ntohl(*(uint32_t*)payload);
            out_packet->data.set_direct_pump.dev_id = payload[4];
            out_packet->data.set_direct_pump.btn = payload[5];
            break;
        }
        //------------------------------
        // 61 - Set Direct Light
        //------------------------------
        case MSG_TYPE_SET_DIRECT_LIGHT: {
            if (payload_len < 6) return -1;
            out_packet->data.set_direct_light.token = ntohl(*(uint32_t*)payload);
            out_packet->data.set_direct_light.dev_id = payload[4];
            out_packet->data.set_direct_light.btn = payload[5];
            break;
        }
        //------------------------------
        // 62 - Set Direct Fert
        //------------------------------
        case MSG_TYPE_SET_DIRECT_FERT: {
            if (payload_len < 6) return -1;
            out_packet->data.set_direct_fert.token = ntohl(*(uint32_t*)payload);
            out_packet->data.set_direct_fert.dev_id = payload[4];
            out_packet->data.set_direct_fert.btn = payload[5];
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
