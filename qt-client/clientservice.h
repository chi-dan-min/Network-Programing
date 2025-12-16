#ifndef CLIENTSERVICE_H
#define CLIENTSERVICE_H

#include <QObject>
#include <QThread>
#include <QMutex>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include "protocol.h"

// Store schedules set by this client
struct DeviceSchedules {
    std::vector<uint32_t> pump_times;
    std::vector<std::pair<uint32_t, uint32_t>> light_pairs;
};

// Track direct control states per device
struct DirectState {
    bool pump = false;
    bool light = false;
    bool fert = false;
};

class RecvThread : public QThread {
    Q_OBJECT
public:
    RecvThread(int sockfd, QObject* parent = nullptr);
    void run() override;
    void stop();

signals:
    void dataReceived(uint8_t dev_id, IntervalData data);
    void alertReceived(uint8_t dev_id, Alert alert);
    void connectionLost();

private:
    int sockfd;
    bool running;
};

class ClientService : public QObject {
    Q_OBJECT

public:
    explicit ClientService(QObject *parent = nullptr);
    ~ClientService();
    
    // Connection & Authentication
    bool connectToServer(const QString& ip, uint16_t port);
    bool login(const QString& username, const QString& password);
    void disconnect();
    
    // Monitoring
    bool scan();
    bool info();
    bool getDeviceParams(uint8_t device_id);
    
    // Garden Management
    bool addGarden(uint8_t garden_id);
    bool deleteGarden(uint8_t garden_id);
    
    // Device Management
    bool addDevice(uint8_t device_id, uint8_t garden_id, const QString& app_id);
    bool deleteDevice(uint8_t device_id);
    
    // Control
    bool setPumpSchedule(uint8_t device_id, const std::vector<uint32_t>& times);
    bool setLightSchedule(uint8_t device_id, const std::vector<std::pair<uint32_t, uint32_t>>& pairs);
    bool setDirectPump(uint8_t device_id, bool state);
    bool setDirectLight(uint8_t device_id, bool state);
    bool setDirectFert(uint8_t device_id, bool state);
    
    // Settings
    bool setParameter(uint8_t device_id, uint8_t hmin, uint8_t hmax, 
                     uint8_t nmin, uint8_t pmin, uint8_t kmin,
                     uint8_t fert_c, uint8_t fert_v, uint8_t power, uint8_t interval_t);
    bool changePassword(const QString& app_id, const QString& old_pass, const QString& new_pass);
    
    // Data Access
    std::vector<uint8_t> getGardens() const { return current_gardens; }
    std::vector<uint8_t> getDevices() const { return current_devices; }
    std::vector<std::string> getDataLogs() const;
    std::vector<std::string> getAlertLogs() const;
    IntervalData getLastIntervalData(uint8_t device_id) const;
    DeviceSchedules getSchedules(uint8_t device_id) const;
    DirectState getDirectState(uint8_t device_id) const;
    DeviceDetailResponse getDeviceDetail(uint8_t device_id);
    bool isConnected() const { return sockfd >= 0 && token > 0; }
    uint32_t getToken() const { return token; }
    
    // Packet Logging Controls (granular per message type)
    void setPacketLoggingEnabled(uint8_t msg_type, bool enabled);
    bool isPacketLoggingEnabled(uint8_t msg_type) const;
    void enableAllPacketLogging();
    void disableAllPacketLogging();
    void resetPacketLoggingDefaults();

signals:
    void logMessage(QString msg);
    void errorMessage(QString msg);
    void connected();
    void disconnected();
    void loginSuccess(uint32_t token);
    void devicesUpdated();
    void gardensUpdated();
    void deviceDataUpdated(uint8_t dev_id);
    void deviceAlertReceived(uint8_t dev_id, QString alert);
    void deviceParamsReceived(uint8_t dev_id, SettingsResponse settings);
    void packetData(QString direction, QString data); // "SEND" or "RECV"
    void scanInfoResult(QString result); // For displaying scan/info output

private slots:
    void onDataReceived(uint8_t dev_id, IntervalData data);
    void onAlertReceived(uint8_t dev_id, Alert alert);
    void onConnectionLost();

private:
    bool sendSimpleRequest(uint8_t* buffer, int len, const char* action_name);
    QString formatTimestamp(uint32_t ts) const;
    
    int sockfd;
    uint32_t token;
    RecvThread* recvThread;
    
    // State data
    mutable QMutex dataMutex;
    std::vector<uint8_t> current_gardens;
    std::vector<uint8_t> current_devices;
    std::unordered_map<uint8_t, IntervalData> last_interval_data;
    std::unordered_map<uint8_t, DeviceSchedules> schedules_map;
    std::unordered_map<uint8_t, DirectState> direct_state_map;
    std::vector<std::string> data_logs;
    std::vector<std::string> alert_logs;
    
    // Packet logging control - granular per message type
    std::unordered_map<uint8_t, bool> packetLoggingEnabled;
    void initializePacketLogging();
    
    // Control display of interval data and alerts in log
    bool showIntervalData = true;
    bool showAlerts = true;
};

#endif
