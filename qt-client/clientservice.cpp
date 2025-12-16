#include "clientservice.h"
#include "myclient.h"
#include <QDateTime>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// RecvThread implementation
RecvThread::RecvThread(int sockfd, QObject* parent)
    : QThread(parent), sockfd(sockfd), running(true) {}

void RecvThread::run() {
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    
    while (running) {
        memset(recv_buffer, 0, sizeof(recv_buffer));
        uint8_t peek_byte = 0;
        int pr = recv(sockfd, &peek_byte, 1, MSG_PEEK);
        
        if (pr <= 0) {
            if (pr == 0) {
                emit connectionLost();
            }
            break;
        }
        
        // Only handle async messages (DATA, ALERT)
        if (peek_byte == MSG_TYPE_DATA || peek_byte == MSG_TYPE_ALERT) {
            int packet_len = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
            if (packet_len <= 0) {
                emit connectionLost();
                break;
            }
            
            ParsedPacket packet;
            if (deserialize_packet(recv_buffer, packet_len, &packet) == 0) {
                if (packet.type == MSG_TYPE_DATA) {
                    emit dataReceived(packet.data.interval_data.dev_id, packet.data.interval_data);
                } else if (packet.type == MSG_TYPE_ALERT) {
                    emit alertReceived(packet.data.alert.dev_id, packet.data.alert);
                }
            }
        } else {
            // Not an async message, sleep to allow main thread to handle
            msleep(10);
        }
    }
}

void RecvThread::stop() {
    running = false;
}

// ClientService implementation
ClientService::ClientService(QObject *parent)
    : QObject(parent), sockfd(-1), token(0), recvThread(nullptr) {
    
    // Setup packet display callback
    packet_display_callback = [this](const char* title, const uint8_t* buffer, int len) {
        QString direction = QString(title).contains("send", Qt::CaseInsensitive) ? "SEND" : "RECV";
        QString hexData = QString::fromStdString(format_packet_buffer(buffer, len));
        QString fullMsg = QString("%1 (%2 bytes):\n%3").arg(title).arg(len).arg(hexData);
        emit packetData(direction, fullMsg);
    };
}

ClientService::~ClientService() {
    disconnect();
}

bool ClientService::connectToServer(const QString& ip, uint16_t port) {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        emit errorMessage("Socket creation failed");
        return false;
    }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip.toStdString().c_str(), &serv.sin_addr);

    if (::connect(sockfd, (sockaddr*)&serv, sizeof(serv)) < 0) {
        emit errorMessage("Connection failed");
        ::close(sockfd);
        sockfd = -1;
        return false;
    }

    emit logMessage("Connected to server at " + ip);
    emit connected();
    return true;
}

bool ClientService::login(const QString& username, const QString& password) {
    if (!client_login(sockfd, token, username.toStdString(), password.toStdString())) {
        emit errorMessage("Login failed");
        return false;
    }
    
    emit logMessage("Login success, token=" + QString::number(token));
    emit loginSuccess(token);
    
    // Start background thread for receiving data
    recvThread = new RecvThread(sockfd, this);
    connect(recvThread, &RecvThread::dataReceived, this, &ClientService::onDataReceived);
    connect(recvThread, &RecvThread::alertReceived, this, &ClientService::onAlertReceived);
    connect(recvThread, &RecvThread::connectionLost, this, &ClientService::onConnectionLost);
    recvThread->start();
    
    return true;
}

void ClientService::disconnect() {
    if (recvThread) {
        recvThread->stop();
        recvThread->wait();
        delete recvThread;
        recvThread = nullptr;
    }
    
    if (sockfd >= 0) {
        ::close(sockfd);
        sockfd = -1;
    }
    
    token = 0;
    emit disconnected();
}

bool ClientService::scan() {
    if (!client_scan(sockfd, token, false)) {
        return false;
    }
    emit logMessage("Scan completed");
    emit devicesUpdated();
    return true;
}

bool ClientService::info() {
    if (!client_info(sockfd, token, false)) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    // Update current_gardens and current_devices from the response
    // This requires parsing the INFO response - for now just signal update
    emit logMessage("Info received");
    emit devicesUpdated();
    emit gardensUpdated();
    return true;
}

bool ClientService::getDeviceParams(uint8_t device_id) {
    return client_get_device_params(sockfd, token, device_id, false);
}

bool ClientService::addGarden(uint8_t garden_id) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_garden_add(token, garden_id, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Add Garden")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    current_gardens.push_back(garden_id);
    emit logMessage(QString("Garden %1 added").arg(garden_id));
    emit gardensUpdated();
    return true;
}

bool ClientService::deleteGarden(uint8_t garden_id) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_garden_del(token, garden_id, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Delete Garden")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    current_gardens.erase(std::remove(current_gardens.begin(), current_gardens.end(), garden_id), 
                          current_gardens.end());
    emit logMessage(QString("Garden %1 deleted").arg(garden_id));
    emit gardensUpdated();
    return true;
}

bool ClientService::addDevice(uint8_t device_id, uint8_t garden_id, const QString& app_id) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_device_add(token, garden_id, device_id, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Add Device")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    current_devices.push_back(device_id);
    emit logMessage(QString("Device %1 added to garden %2").arg(device_id).arg(garden_id));
    emit devicesUpdated();
    return true;
}

bool ClientService::deleteDevice(uint8_t device_id) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    // Note: We need garden_id for deletion, but API doesn't have it. Using 0 as placeholder
    int len = serialize_device_del(token, 0, device_id, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Delete Device")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    current_devices.erase(std::remove(current_devices.begin(), current_devices.end(), device_id),
                          current_devices.end());
    emit logMessage(QString("Device %1 deleted").arg(device_id));
    emit devicesUpdated();
    return true;
}

bool ClientService::setPumpSchedule(uint8_t device_id, const std::vector<uint32_t>& times) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_pump_schedule(token, device_id, (uint8_t)times.size(), times.data(), buffer);
    
    if (!sendSimpleRequest(buffer, len, "Set Pump Schedule")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    schedules_map[device_id].pump_times = times;
    emit logMessage(QString("Pump schedule set for device %1").arg(device_id));
    return true;
}

bool ClientService::setLightSchedule(uint8_t device_id, const std::vector<std::pair<uint32_t, uint32_t>>& pairs) {
    std::vector<uint32_t> timestamps;
    for (const auto& p : pairs) {
        timestamps.push_back(p.first);
        timestamps.push_back(p.second);
    }
    
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_light_schedule(token, device_id, (uint8_t)timestamps.size(), timestamps.data(), buffer);
    
    if (!sendSimpleRequest(buffer, len, "Set Light Schedule")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    schedules_map[device_id].light_pairs = pairs;
    emit logMessage(QString("Light schedule set for device %1").arg(device_id));
    return true;
}

bool ClientService::setDirectPump(uint8_t device_id, bool state) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_direct_pump(token, device_id, state ? 1 : 0, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Set Direct Pump")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    direct_state_map[device_id].pump = state;
    emit logMessage(QString("Pump %1 for device %2").arg(state ? "ON" : "OFF").arg(device_id));
    return true;
}

bool ClientService::setDirectLight(uint8_t device_id, bool state) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_direct_light(token, device_id, state ? 1 : 0, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Set Direct Light")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    direct_state_map[device_id].light = state;
    emit logMessage(QString("Light %1 for device %2").arg(state ? "ON" : "OFF").arg(device_id));
    return true;
}

bool ClientService::setDirectFert(uint8_t device_id, bool state) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_set_direct_fert(token, device_id, state ? 1 : 0, buffer);
    
    if (!sendSimpleRequest(buffer, len, "Set Direct Fert")) {
        return false;
    }
    
    QMutexLocker locker(&dataMutex);
    direct_state_map[device_id].fert = state;
    emit logMessage(QString("Fertilizer %1 for device %2").arg(state ? "ON" : "OFF").arg(device_id));
    return true;
}

bool ClientService::setParameter(uint8_t device_id, uint8_t hmin, uint8_t hmax, 
                                 uint8_t nmin, uint8_t pmin, uint8_t kmin,
                                 uint8_t fert_c, uint8_t fert_v, uint8_t power, uint8_t interval_t) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    uint8_t garden_id = 0; // Placeholder - we don't track garden_id in this context
    
    // Set each parameter individually as protocol only supports one at a time
    int len;    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_H_MIN, hmin, buffer);
    if (!sendSimpleRequest(buffer, len, "Set H_MIN")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_H_MAX, hmax, buffer);
    if (!sendSimpleRequest(buffer, len, "Set H_MAX")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_N_MIN, nmin, buffer);
    if (!sendSimpleRequest(buffer, len, "Set N_MIN")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_P_MIN, pmin, buffer);
    if (!sendSimpleRequest(buffer, len, "Set P_MIN")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_K_MIN, kmin, buffer);
    if (!sendSimpleRequest(buffer, len, "Set K_MIN")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_FERT_C, fert_c, buffer);
    if (!sendSimpleRequest(buffer, len, "Set FERT_C")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_FERT_V, fert_v, buffer);
    if (!sendSimpleRequest(buffer, len, "Set FERT_V")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_POWER, power, buffer);
    if (!sendSimpleRequest(buffer, len, "Set POWER")) return false;
    
    len = serialize_set_parameter(token, garden_id, device_id, PARAM_ID_T_DELAY, interval_t, buffer);
    if (!sendSimpleRequest(buffer, len, "Set T_DELAY")) return false;
    
    emit logMessage(QString("Parameters set for device %1").arg(device_id));
    return true;
}

bool ClientService::changePassword(const QString& app_id, const QString& old_pass, const QString& new_pass) {
    uint8_t buffer[MAX_BUFFER_SIZE];
    int len = serialize_change_password(token, app_id.toStdString().c_str(),
                                       (uint8_t)old_pass.length(), 
                                       old_pass.toStdString().c_str(),
                                       new_pass.toStdString().c_str(), buffer);
    
    if (!sendSimpleRequest(buffer, len, "Change Password")) {
        return false;
    }
    
    emit logMessage("Password changed successfully");
    return true;
}

std::vector<std::string> ClientService::getDataLogs() const {
    QMutexLocker locker(&dataMutex);
    return data_logs;
}

std::vector<std::string> ClientService::getAlertLogs() const {
    QMutexLocker locker(&dataMutex);
    return alert_logs;
}

IntervalData ClientService::getLastIntervalData(uint8_t device_id) const {
    QMutexLocker locker(&dataMutex);
    auto it = last_interval_data.find(device_id);
    if (it != last_interval_data.end()) {
        return it->second;
    }
    return IntervalData{};
}

DeviceSchedules ClientService::getSchedules(uint8_t device_id) const {
    QMutexLocker locker(&dataMutex);
    auto it = schedules_map.find(device_id);
    if (it != schedules_map.end()) {
        return it->second;
    }
    return DeviceSchedules{};
}

DirectState ClientService::getDirectState(uint8_t device_id) const {
    QMutexLocker locker(&dataMutex);
    auto it = direct_state_map.find(device_id);
    if (it != direct_state_map.end()) {
        return it->second;
    }
    return DirectState{};
}

void ClientService::onDataReceived(uint8_t dev_id, IntervalData data) {
    QMutexLocker locker(&dataMutex);
    last_interval_data[dev_id] = data;
    
    std::ostringstream oss;
    oss << "[DATA] " << formatTimestamp(data.timestamp).toStdString()
        << ", deviceID=" << (int)data.dev_id
        << ", soil=" << (int)data.humidity
        << ", N=" << (int)data.n_level
        << ", P=" << (int)data.p_level
        << ", K=" << (int)data.k_level;
    data_logs.push_back(oss.str());
    
    locker.unlock();
    emit deviceDataUpdated(dev_id);
    emit logMessage(QString::fromStdString(oss.str()));
}

void ClientService::onAlertReceived(uint8_t dev_id, Alert alert) {
    QMutexLocker locker(&dataMutex);
    
    // Update direct control state
    DirectState& st = direct_state_map[dev_id];
    QString alert_str;
    
    switch (alert.alert_code) {
        case ALERT_WATERING_START:  
            st.pump = true; 
            alert_str = "Watering START"; 
            break;
        case ALERT_WATERING_END:    
            st.pump = false; 
            alert_str = "Watering END"; 
            break;
        case ALERT_FERTILIZE_START: 
            st.fert = true; 
            alert_str = "Fertilize START"; 
            break;
        case ALERT_FERTILIZE_END:   
            st.fert = false; 
            alert_str = "Fertilize END"; 
            break;
        case ALERT_LIGHTS_ON:       
            st.light = true; 
            alert_str = "Light ON"; 
            break;
        case ALERT_LIGHTS_OFF:      
            st.light = false; 
            alert_str = "Light OFF"; 
            break;
        default:                    
            alert_str = "Unknown"; 
            break;
    }
    
    std::ostringstream oss;
    oss << "[ALERT] " << formatTimestamp(alert.timestamp).toStdString()
        << ", deviceID=" << (int)alert.dev_id
        << ", code=" << alert_str.toStdString();
    alert_logs.push_back(oss.str());
    
    locker.unlock();
    emit deviceAlertReceived(dev_id, alert_str);
    emit logMessage(QString::fromStdString(oss.str()));
}

void ClientService::onConnectionLost() {
    emit errorMessage("Connection lost to server");
    disconnect();
}

bool ClientService::sendSimpleRequest(uint8_t* buffer, int len, const char* action_name) {
    if (send(sockfd, buffer, len, 0) < 0) {
        emit errorMessage(QString("Send failed: %1").arg(action_name));
        return false;
    }
    
    uint8_t recv_buf[MAX_BUFFER_SIZE];
    int rlen = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
    
    if (rlen <= 0) {
        emit errorMessage(QString("Recv failed: %1").arg(action_name));
        return false;
    }
    
    ParsedPacket packet;
    if (deserialize_packet(recv_buf, rlen, &packet) == 0) {
        if (packet.type == MSG_TYPE_CMD_RESPONSE) {
            int status = packet.data.cmd_response.status_code;
            if (status == STATUS_OK) {
                return true;
            } else {
                emit errorMessage(QString("Action failed: %1, status=%2").arg(action_name).arg(status));
                return false;
            }
        }
    }
    
    emit errorMessage(QString("Invalid response: %1").arg(action_name));
    return false;
}

QString ClientService::formatTimestamp(uint32_t ts) const {
    QDateTime dt = QDateTime::fromSecsSinceEpoch(ts);
    return dt.toString("dd/MM/yyyy HH:mm:ss");
}
