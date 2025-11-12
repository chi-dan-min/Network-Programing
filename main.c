#include <stdio.h>
#include "protocol.h"

void print_buffer(const char* title, const uint8_t* buffer, int len) {
    printf("%s (%d bytes):\n", title, len);
    for (int i = 0; i < len; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n\n");
}

int main() {
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    int packet_len;
    
    // --- VÍ DỤ 1: CONNECT ---
    // Client gói tin
    packet_len = serialize_connect_request("chidan", "my_secret_pass", send_buffer);
    print_buffer("Client send: Connect Request", send_buffer, packet_len);
    
    // Server nhận và giải gói tin
    // (Giả sử send_buffer được gửi qua socket và nhận vào recv_buffer)
    memcpy(recv_buffer, send_buffer, packet_len); 
    
    ParsedPacket packet;
    if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
        if (packet.type == 10) {
            printf("Server received: Connect Request\n");
            printf("Password: %s\n\n", packet.data.connect_req.password);
        }
    }
    
    // Server phản hồi
    uint32_t a_token = 12345678; // 0xBC614E
    packet_len = serialize_connect_response(a_token, send_buffer);
    print_buffer("Server send: Connect Response", send_buffer, packet_len);

    // Client nhận và giải gói tin
    memcpy(recv_buffer, send_buffer, packet_len);
    if (deserialize_packet(recv_buffer, packet_len, &packet) == 0 && packet.type == 11) {
        printf("Client received: Connect Response\n");
        printf("Token: %u\n\n", packet.data.connect_res.token);
    }

    // --- VÍ DỤ 2: SCAN SERVER RESPONSE ---
    uint8_t device_list[] = {0x0A, 0x0B, 0x0C}; // 3 thiết bị
    packet_len = serialize_scan_response(3, device_list, send_buffer);
    print_buffer("Server send: Scan Response", send_buffer, packet_len);

    // Client nhận và giải gói tin
    memcpy(recv_buffer, send_buffer, packet_len);
     if (deserialize_packet(recv_buffer, packet_len, &packet) == 0 && packet.type == 21) {
        printf("Client received: Scan Response\n");
        printf("Num devices: %d\n", packet.data.scan_res.num_devices);
        printf("IDs: ");
        for(int i=0; i<packet.data.scan_res.num_devices; i++) {
            printf("0x%02X ", packet.data.scan_res.device_ids[i]);
        }
        printf("\n\n");
    }

    // --- VÍ DỤ 3: INFO SERVER RESPONSE (Phức tạp) ---
    InfoResponse info_data;
    info_data.num_gardens = 2;
    
    // Vườn 1
    info_data.gardens[0].garden_id = 0x01;
    info_data.gardens[0].num_devices = 2;
    info_data.gardens[0].devices[0].device_id = 0xA1;
    info_data.gardens[0].devices[1].device_id = 0xA2;
    
    // Vườn 2
    info_data.gardens[1].garden_id = 0x02;
    info_data.gardens[1].num_devices = 1;
    info_data.gardens[1].devices[0].device_id = 0xB1;

    packet_len = serialize_info_response(&info_data, send_buffer);
    print_buffer("Server send: Info Response", send_buffer, packet_len);
    
    // Client nhận
    memcpy(recv_buffer, send_buffer, packet_len);
    if (deserialize_packet(recv_buffer, packet_len, &packet) == 0 && packet.type == 31) {
        printf("Client received: Info Response\n");
        printf("Num gardens: %d\n", packet.data.info_res.num_gardens);
        for(int i=0; i<packet.data.info_res.num_gardens; i++) {
            GardenInfo* g = &packet.data.info_res.gardens[i];
            printf("  Garden ID: 0x%02X\n", g->garden_id);
            printf("  Num devices: %d\n", g->num_devices);
            printf("  Device IDs: ");
            for(int j=0; j<g->num_devices; j++) {
                printf("0x%02X ", g->devices[j].device_id);
            }
            printf("\n");
        }
    }

    return 0;
}