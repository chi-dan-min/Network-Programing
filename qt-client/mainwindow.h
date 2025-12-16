#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QComboBox>
#include <QListWidget>
#include <QTimeEdit>
#include "clientservice.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Connection & Login
    void on_btnConnectLogin_clicked();
    
    // Monitoring Tab
    void on_btnRefreshDevices_clicked();
    void on_deviceList_currentRowChanged(int row);
    
    // Control Tab
    void on_btnAddPumpTime_clicked();
    void on_btnRemovePumpTime_clicked();
    void on_btnApplyPumpSchedule_clicked();
    void on_btnAddLightPair_clicked();
    void on_btnRemoveLightPair_clicked();
    void on_btnApplyLightSchedule_clicked();
    void on_btnPumpOn_clicked();
    void on_btnPumpOff_clicked();
    void on_btnLightOn_clicked();
    void on_btnLightOff_clicked();
    void on_btnFertOn_clicked();
    void on_btnFertOff_clicked();
    
    // Management Tab
    void on_btnAddGarden_clicked();
    void on_btnDeleteGarden_clicked();
    void on_btnAddDevice_clicked();
    void on_btnDeleteDevice_clicked();
    
    // Settings Tab
    void on_btnApplyParameters_clicked();
    void on_btnChangePassword_clicked();
    void on_btnViewDeviceConfig_clicked();
    
    // Logs Tab
    void on_btnClearDataLogs_clicked();
    void on_btnClearAlertLogs_clicked();
    
    // ClientService signals
    void onConnected();
    void onLoginSuccess();
    void onDevicesUpdated();
    void onDeviceDataUpdated(uint8_t dev_id);
    void onDeviceAlert(uint8_t dev_id, QString alert);

private:
    void setupSettingsTab();
    void updateDeviceList();
    void updateDeviceDetails(uint8_t device_id);
    void updateControlTabDeviceInfo(uint8_t device_id);
    void updateLogsDisplay();
    uint32_t timeEditToTimestamp(QTimeEdit* timeEdit);
    
    Ui::MainWindow *ui;
    ClientService *client;
    uint8_t currentDeviceId;
};

#endif
