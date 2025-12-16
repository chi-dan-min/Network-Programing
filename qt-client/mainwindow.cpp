#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QDateTime>
#include <QtConcurrent>
#include <QTimer>
#include <QCheckBox>
#include <QGroupBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QScrollArea>
#include <thread>
#include <sstream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      client(new ClientService(this)),
      currentDeviceId(0) {

    ui->setupUi(this);

    // Connect ClientService signals
    connect(client, &ClientService::logMessage, ui->logView, &QTextEdit::append);
    connect(client, &ClientService::errorMessage, this, [this](QString msg) {
        ui->logView->append("<font color='red'>" + msg + "</font>");
        QMessageBox::warning(this, "Error", msg);
    });
    connect(client, &ClientService::connected, this, &MainWindow::onConnected);
    connect(client, &ClientService::loginSuccess, this, &MainWindow::onLoginSuccess);
    connect(client, &ClientService::devicesUpdated, this, &MainWindow::onDevicesUpdated);
    connect(client, &ClientService::deviceDataUpdated, this, &MainWindow::onDeviceDataUpdated);
    connect(client, &ClientService::deviceAlertReceived, this, &MainWindow::onDeviceAlert);
    
    // Connect packet viewer
    connect(client, &ClientService::packetData, this, [this](QString direction, QString data) {
        QString color = (direction == "SEND") ? "blue" : "green";
        ui->packetView->append(QString("<font color='%1'><b>%2:</b></font>").arg(color, direction));
        ui->packetView->append(data);
        ui->packetView->append(""); // Empty line for spacing
    });

    // Connect Control tab device selector
    connect(ui->comboControlDevice, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, [this](int index) {
        if (index >= 0 && client->isConnected()) {
            uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
            updateControlTabDeviceInfo(dev_id);
        }
    });

    // Setup Settings Tab
    setupSettingsTab();

    // Hide main tabs until logged in
    ui->tabWidget->setEnabled(false);
}

MainWindow::~MainWindow() {
    delete ui;
}

// ===== Settings Tab Setup =====
void MainWindow::setupSettingsTab() {
    // Create settings tab widget
    QWidget* settingsTab = new QWidget();
    ui->tabWidget->addTab(settingsTab, "Packet Logging");
    
    // Main scroll area
    QScrollArea* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget* scrollContents = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(scrollContents);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    mainLayout->setSpacing(12);
    
    // === Authentication & Session ===
    QGroupBox* groupAuth = new QGroupBox("Authentication & Session");
    QVBoxLayout* authLayout = new QVBoxLayout();
    
    QCheckBox* chkConnect = new QCheckBox("Connect/Login Messages (0x0A/0x0B)");
    chkConnect->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_CONNECT_CLIENT));
    connect(chkConnect, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_CONNECT_CLIENT, checked);
        client->setPacketLoggingEnabled(MSG_TYPE_CONNECT_SERVER, checked);
    });
    
    QCheckBox* chkPassword = new QCheckBox("Change Password (0x0C)");
    chkPassword->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_CHANGE_PASSWORD));
    connect(chkPassword, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_CHANGE_PASSWORD, checked);
    });
    
    authLayout->addWidget(chkConnect);
    authLayout->addWidget(chkPassword);
    groupAuth->setLayout(authLayout);
    
    // === Device Discovery & Info ===
    QGroupBox* groupInfo = new QGroupBox("Device Discovery & Info");
    QVBoxLayout* infoLayout = new QVBoxLayout();
    
    QCheckBox* chkScan = new QCheckBox("Scan Devices (0x14/0x15)");
    chkScan->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SCAN_CLIENT));
    connect(chkScan, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SCAN_CLIENT, checked);
        client->setPacketLoggingEnabled(MSG_TYPE_SCAN_SERVER, checked);
    });
    
    QCheckBox* chkInfo = new QCheckBox("Info Request/Response (0x1E/0x1F)");
    chkInfo->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_INFO_CLIENT));
    connect(chkInfo, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_INFO_CLIENT, checked);
        client->setPacketLoggingEnabled(MSG_TYPE_INFO_SERVER, checked);
    });
    
    QCheckBox* chkDetail = new QCheckBox("Device Detail (0x20/0x21)");
    chkDetail->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_DEVICE_DETAIL_CLIENT));
    connect(chkDetail, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_DEVICE_DETAIL_CLIENT, checked);
        client->setPacketLoggingEnabled(MSG_TYPE_DEVICE_DETAIL_SERVER, checked);
    });
    
    infoLayout->addWidget(chkScan);
    infoLayout->addWidget(chkInfo);
    infoLayout->addWidget(chkDetail);
    groupInfo->setLayout(infoLayout);
    
    // === Device Control ===
    QGroupBox* groupControl = new QGroupBox("Device Control");
    QVBoxLayout* controlLayout = new QVBoxLayout();
    
    QCheckBox* chkSetParam = new QCheckBox("Set Parameters (0x28)");
    chkSetParam->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SET_PARAMETER));
    connect(chkSetParam, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SET_PARAMETER, checked);
    });
    
    QCheckBox* chkPumpSched = new QCheckBox("Pump Schedule (0x32)");
    chkPumpSched->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SET_PUMP_SCHEDULE));
    connect(chkPumpSched, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SET_PUMP_SCHEDULE, checked);
    });
    
    QCheckBox* chkLightSched = new QCheckBox("Light Schedule (0x33)");
    chkLightSched->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SET_LIGHT_SCHEDULE));
    connect(chkLightSched, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SET_LIGHT_SCHEDULE, checked);
    });
    
    QCheckBox* chkDirectPump = new QCheckBox("Direct Pump Control (0x3C)");
    chkDirectPump->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SET_DIRECT_PUMP));
    connect(chkDirectPump, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SET_DIRECT_PUMP, checked);
    });
    
    QCheckBox* chkDirectLight = new QCheckBox("Direct Light Control (0x3D)");
    chkDirectLight->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SET_DIRECT_LIGHT));
    connect(chkDirectLight, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SET_DIRECT_LIGHT, checked);
    });
    
    QCheckBox* chkDirectFert = new QCheckBox("Direct Fertilizer Control (0x3E)");
    chkDirectFert->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SET_DIRECT_FERT));
    connect(chkDirectFert, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SET_DIRECT_FERT, checked);
    });
    
    QCheckBox* chkSettings = new QCheckBox("Settings Request/Response (0x66/0x67)");
    chkSettings->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_SETTINGS_CLIENT));
    connect(chkSettings, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_SETTINGS_CLIENT, checked);
        client->setPacketLoggingEnabled(MSG_TYPE_SETTINGS_SERVER, checked);
    });
    
    controlLayout->addWidget(chkSetParam);
    controlLayout->addWidget(chkPumpSched);
    controlLayout->addWidget(chkLightSched);
    controlLayout->addWidget(chkDirectPump);
    controlLayout->addWidget(chkDirectLight);
    controlLayout->addWidget(chkDirectFert);
    controlLayout->addWidget(chkSettings);
    groupControl->setLayout(controlLayout);
    
    // === Garden & Device Management ===
    QGroupBox* groupMgmt = new QGroupBox("Garden & Device Management");
    QVBoxLayout* mgmtLayout = new QVBoxLayout();
    
    QCheckBox* chkGardenAdd = new QCheckBox("Add Garden (0x50)");
    chkGardenAdd->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_GARDEN_ADD));
    connect(chkGardenAdd, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_GARDEN_ADD, checked);
    });
    
    QCheckBox* chkGardenDel = new QCheckBox("Delete Garden (0x51)");
    chkGardenDel->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_GARDEN_DEL));
    connect(chkGardenDel, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_GARDEN_DEL, checked);
    });
    
    QCheckBox* chkDeviceAdd = new QCheckBox("Add Device (0x5A)");
    chkDeviceAdd->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_DEVICE_ADD));
    connect(chkDeviceAdd, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_DEVICE_ADD, checked);
    });
    
    QCheckBox* chkDeviceDel = new QCheckBox("Delete Device (0x5B)");
    chkDeviceDel->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_DEVICE_DEL));
    connect(chkDeviceDel, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_DEVICE_DEL, checked);
    });
    
    mgmtLayout->addWidget(chkGardenAdd);
    mgmtLayout->addWidget(chkGardenDel);
    mgmtLayout->addWidget(chkDeviceAdd);
    mgmtLayout->addWidget(chkDeviceDel);
    groupMgmt->setLayout(mgmtLayout);
    
    // === Real-time Data ===
    QGroupBox* groupData = new QGroupBox("Real-time Data");
    QVBoxLayout* dataLayout = new QVBoxLayout();
    
    QCheckBox* chkIntervalData = new QCheckBox("Interval Data (0x64)");
    chkIntervalData->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_DATA));
    connect(chkIntervalData, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_DATA, checked);
    });
    
    QCheckBox* chkAlerts = new QCheckBox("Alerts (0xC8)");
    chkAlerts->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_ALERT));
    connect(chkAlerts, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_ALERT, checked);
    });
    
    dataLayout->addWidget(chkIntervalData);
    dataLayout->addWidget(chkAlerts);
    groupData->setLayout(dataLayout);
    
    // === System Responses ===
    QGroupBox* groupSystem = new QGroupBox("System Responses");
    QVBoxLayout* systemLayout = new QVBoxLayout();
    
    QCheckBox* chkCmdResponse = new QCheckBox("Command Responses (0xFE)");
    chkCmdResponse->setChecked(client->isPacketLoggingEnabled(MSG_TYPE_CMD_RESPONSE));
    connect(chkCmdResponse, &QCheckBox::toggled, [this](bool checked) {
        client->setPacketLoggingEnabled(MSG_TYPE_CMD_RESPONSE, checked);
    });
    
    systemLayout->addWidget(chkCmdResponse);
    groupSystem->setLayout(systemLayout);
    
    // === Quick Actions ===
    QGroupBox* groupActions = new QGroupBox("Quick Actions");
    QHBoxLayout* actionsLayout = new QHBoxLayout();
    
    QPushButton* btnEnableAll = new QPushButton(" Enable All");
    btnEnableAll->setMinimumHeight(35);
    connect(btnEnableAll, &QPushButton::clicked, [this]() {
        client->enableAllPacketLogging();
        ui->logView->append("All packet logging enabled");
        // Note: checkboxes won't auto-update, would need to re-create tab or store refs
    });
    
    QPushButton* btnDisableAll = new QPushButton("Disable All");
    btnDisableAll->setMinimumHeight(35);
    connect(btnDisableAll, &QPushButton::clicked, [this]() {
        client->disableAllPacketLogging();
        ui->logView->append("All packet logging disabled");
    });
    
    QPushButton* btnReset = new QPushButton("Reset Defaults");
    btnReset->setMinimumHeight(35);
    connect(btnReset, &QPushButton::clicked, [this]() {
        client->resetPacketLoggingDefaults();
        ui->logView->append("Packet logging reset to defaults");
    });
    
    QPushButton* btnClearLogs = new QPushButton("Clear Logs");
    btnClearLogs->setMinimumHeight(35);
    connect(btnClearLogs, &QPushButton::clicked, [this]() {
        ui->logView->clear();
        ui->packetView->clear();
        ui->logView->append("All logs cleared");
    });
    
    actionsLayout->addWidget(btnEnableAll);
    actionsLayout->addWidget(btnDisableAll);
    actionsLayout->addWidget(btnReset);
    actionsLayout->addWidget(btnClearLogs);
    groupActions->setLayout(actionsLayout);
    
    // Add all groups to main layout
    mainLayout->addWidget(groupAuth);
    mainLayout->addWidget(groupInfo);
    mainLayout->addWidget(groupControl);
    mainLayout->addWidget(groupMgmt);
    mainLayout->addWidget(groupData);
    mainLayout->addWidget(groupSystem);
    mainLayout->addWidget(groupActions);
    mainLayout->addStretch();
    
    scrollArea->setWidget(scrollContents);
    
    QVBoxLayout* tabLayout = new QVBoxLayout(settingsTab);
    tabLayout->setContentsMargins(0, 0, 0, 0);
    tabLayout->addWidget(scrollArea);
}


// ===== Connection & Login =====
void MainWindow::on_btnConnectLogin_clicked() {
    QString ip = ui->editServerIP->text().trimmed();
    QString username = ui->editUsername->text().trimmed();
    QString password = ui->editPassword->text();

    if (ip.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter server IP address");
        return;
    }

    ui->btnConnectLogin->setEnabled(false);
    ui->logView->append("Connecting to " + ip + "...");

    if (!client->connectToServer(ip, 3000)) {
        ui->btnConnectLogin->setEnabled(true);
        return;
    }

    ui->logView->append("Logging in...");
    if (!client->login(username, password)) {
        ui->btnConnectLogin->setEnabled(true);
        return;
    }

    // Initial scan and info - use std::thread to avoid blocking UI
    std::thread([this]() {
        client->scan();
        client->info();
    }).detach();
}

void MainWindow::onConnected() {
    ui->logView->append("<font color='green'>Connected to server</font>");
}

void MainWindow::onLoginSuccess() {
    ui->logView->append("<font color='green'>Login successful!</font>");
    ui->tabWidget->setEnabled(true);
    ui->btnConnectLogin->setText("Connected");
    updateDeviceList();
}

// ===== Monitoring Tab =====
void MainWindow::on_btnRefreshDevices_clicked() {
    ui->logView->append("Refreshing...");
    ui->btnRefreshDevices->setEnabled(false);
    
    // Use std::thread for TRUE background execution (not on main thread)
    std::thread([this]() {
        client->scan();
        client->info();
        updateDeviceList();
        
        // Update UI on main thread
        QMetaObject::invokeMethod(this, [this]() {
            ui->btnRefreshDevices->setEnabled(true);
            ui->logView->append("Refresh complete");
        }, Qt::QueuedConnection);
    }).detach();
}

void MainWindow::on_deviceList_currentRowChanged(int row) {
    if (row < 0) return;
    
    auto devices = client->getDevices();
    if (row < devices.size()) {
        currentDeviceId = devices[row];
        updateDeviceDetails(currentDeviceId);
        
        // Update control tab device combo
        ui->comboControlDevice->setCurrentIndex(row);
        ui->comboSettingsDevice->setCurrentIndex(row);
    }
}

void MainWindow::updateDeviceList() {
    ui->deviceList->clear();
    ui->comboControlDevice->clear();
    ui->comboSettingsDevice->clear();
    
    auto devices = client->getDevices();
    for (uint8_t dev_id : devices) {
        QString devText = QString("Device %1").arg(dev_id);
        ui->deviceList->addItem(devText);
        ui->comboControlDevice->addItem(devText, dev_id);
        ui->comboSettingsDevice->addItem(devText, dev_id);
    }
    
    if (!devices.empty()) {
        ui->deviceList->setCurrentRow(0);
        
        // Load initial data for first device in Control tab
        uint8_t first_dev = devices[0];
        updateControlTabDeviceInfo(first_dev);
    }
}

void MainWindow::updateDeviceDetails(uint8_t device_id) {
    // Get comprehensive device detail from server
    DeviceDetailResponse detail = client->getDeviceDetail(device_id);
    
    // Update sensor data labels using device detail
    ui->lblHumidity->setText(detail.soil_moisture == SENSOR_NA_VALUE ? 
                                  "N/A" : QString::number(detail.soil_moisture) + "%");
    ui->lblNLevel->setText(detail.npk_n == SENSOR_NA_VALUE ? 
                          "N/A" : QString::number(detail.npk_n));
    ui->lblPLevel->setText(detail.npk_p == SENSOR_NA_VALUE ? 
                          "N/A" : QString::number(detail.npk_p));
    ui->lblKLevel->setText(detail.npk_k == SENSOR_NA_VALUE ? 
                          "N/A" : QString::number(detail.npk_k));
    
    // Update config labels (if you have them in UI)
    // ui->lblFertConc->setText(QString::number(detail.fert_concentration) + " g/L");
    // ui->lblFertVol->setText(QString::number(detail.fert_volume) + " L");
    // ui->lblPowerLamp->setText(QString::number(detail.power_lamp) + "%");
    // ui->lblIntervalTime->setText(QString::number(detail.interval_time) + " mins");
    
    // Update threshold labels (if you have them in UI)
    // ui->lblHumidityRange->setText(QString("%1% - %2%").arg(detail.humidity_min).arg(detail.humidity_max));
    
    // Update direct control status
    ui->lblPumpStatus->setText(detail.direct_pump ? "ON" : "OFF");
    ui->lblLightStatus->setText(detail.direct_light ? "ON" : "OFF");
    ui->lblFertStatus->setText(detail.direct_fert ? "ON" : "OFF");
    
    // Update pump schedule list
    ui->lstPumpSchedule->clear();
    for (int i = 0; i < detail.num_water_times; i++) {
        QDateTime dt = QDateTime::fromSecsSinceEpoch(detail.water_times[i]);
        ui->lstPumpSchedule->addItem(dt.toString("HH:mm"));
    }
    
    // Update light schedule list
    ui->lstLightSchedule->clear();
    for (int i = 0; i < detail.num_light_schedules; i++) {
        QDateTime on = QDateTime::fromSecsSinceEpoch(detail.light_on_times[i]);
        QDateTime off = QDateTime::fromSecsSinceEpoch(detail.light_off_times[i]);
        ui->lstLightSchedule->addItem(QString("ON: %1 | OFF: %2")
                                       .arg(on.toString("HH:mm"))
                                       .arg(off.toString("HH:mm")));
    }
}

void MainWindow::updateControlTabDeviceInfo(uint8_t device_id) {
    // Get device detail from server
    DeviceDetailResponse detail = client->getDeviceDetail(device_id);
    
    // Fill current pump schedule from server into Control tab (for editing)
    ui->lstPumpTimes->clear();
    for (int i = 0; i < detail.num_water_times; i++) {
        QDateTime dt = QDateTime::fromSecsSinceEpoch(detail.water_times[i]);
        ui->lstPumpTimes->addItem(dt.toString("HH:mm"));
    }
    
    // Fill current light schedule from server into Control tab (for editing)
    ui->lstLightPairs->clear();
    for (int i = 0; i < detail.num_light_schedules; i++) {
        QDateTime on = QDateTime::fromSecsSinceEpoch(detail.light_on_times[i]);
        QDateTime off = QDateTime::fromSecsSinceEpoch(detail.light_off_times[i]);
        ui->lstLightPairs->addItem(QString("ON: %1 | OFF: %2")
                                   .arg(on.toString("HH:mm"))
                                   .arg(off.toString("HH:mm")));
    }
    
    // Update direct control button states with highlighting
    // Pump buttons
    if (detail.direct_pump) {
        ui->btnPumpOn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
        ui->btnPumpOff->setStyleSheet("");
    } else {
        ui->btnPumpOn->setStyleSheet("");
        ui->btnPumpOff->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; }");
    }
    
    // Light buttons
    if (detail.direct_light) {
        ui->btnLightOn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
        ui->btnLightOff->setStyleSheet("");
    } else {
        ui->btnLightOn->setStyleSheet("");
        ui->btnLightOff->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; }");
    }
    
    // Fertilizer buttons
    if (detail.direct_fert) {
        ui->btnFertOn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
        ui->btnFertOff->setStyleSheet("");
    } else {
        ui->btnFertOn->setStyleSheet("");
        ui->btnFertOff->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; }");
    }
}



void MainWindow::onDevicesUpdated() {
    updateDeviceList();
}

void MainWindow::onDeviceDataUpdated(uint8_t dev_id) {
    // if (dev_id == currentDeviceId) {
    //     updateDeviceDetails(dev_id);
    // }
    updateLogsDisplay();
}

void MainWindow::onDeviceAlert(uint8_t dev_id, QString alert) {
    // if (dev_id == currentDeviceId) {
    //     updateDeviceDetails(dev_id);
    // }
    updateLogsDisplay();
}

// ===== Control Tab =====
void MainWindow::on_btnAddPumpTime_clicked() {
    QTime time = ui->timePump->time();
    ui->lstPumpTimes->addItem(time.toString("HH:mm"));
}

void MainWindow::on_btnRemovePumpTime_clicked() {
    auto selected = ui->lstPumpTimes-> selectedItems();
    for (auto item : selected) {
        delete item;
    }
}

void MainWindow::on_btnApplyPumpSchedule_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx < 0) {
        QMessageBox::warning(this, "Error", "Please select a device");
        return;
    }
    
    uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
    std::vector<uint32_t> times;
    
    for (int i = 0; i < ui->lstPumpTimes->count(); i++) {
        QString timeStr = ui->lstPumpTimes->item(i)->text();
        QTime time = QTime::fromString(timeStr, "HH:mm");
        
        QDateTime dt = QDateTime::currentDateTime();
        dt.setTime(time);
        times.push_back(dt.toSecsSinceEpoch());
    }
    
    if (client->setPumpSchedule(dev_id, times)) {
        QMessageBox::information(this, "Success", "Pump schedule applied");
        updateDeviceDetails(dev_id);
    }
}

void MainWindow::on_btnAddLightPair_clicked() {
    QTime on = ui->timeLightOn->time();
    QTime off = ui->timeLightOff->time();
    ui->lstLightPairs->addItem(QString("ON: %1 | OFF: %2")
                              .arg(on.toString("HH:mm"))
                              .arg(off.toString("HH:mm")));
}

void MainWindow::on_btnRemoveLightPair_clicked() {
    auto selected = ui->lstLightPairs->selectedItems();
    for (auto item : selected) {
        delete item;
    }
}

void MainWindow::on_btnApplyLightSchedule_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx < 0) {
        QMessageBox::warning(this, "Error", "Please select a device");
        return;
    }
    
    uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
    std::vector<std::pair<uint32_t, uint32_t>> pairs;
    
    for (int i = 0; i < ui->lstLightPairs->count(); i++) {
        QString text = ui->lstLightPairs->item(i)->text();
        QStringList parts = text.split("|");
        if (parts.size() == 2) {
            QTime on = QTime::fromString(parts[0].mid(4).trimmed(), "HH:mm");
            QTime off = QTime::fromString(parts[1].mid(5).trimmed(), "HH:mm");
            
            QDateTime dtOn = QDateTime::currentDateTime();
            dtOn.setTime(on);
            QDateTime dtOff = QDateTime::currentDateTime();
            dtOff.setTime(off);
            
            pairs.emplace_back(dtOn.toSecsSinceEpoch(), dtOff.toSecsSinceEpoch());
        }
    }
    
    if (client->setLightSchedule(dev_id, pairs)) {
        QMessageBox::information(this, "Success", "Light schedule applied");
        updateDeviceDetails(dev_id);
    }
}

void MainWindow::on_btnPumpOn_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        if (client->setDirectPump(dev_id, true)) {
            // Refresh device info to update button highlighting
            QTimer::singleShot(200, [this, dev_id]() {
                updateControlTabDeviceInfo(dev_id);
            });
        }
    }
}

void MainWindow::on_btnPumpOff_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        if (client->setDirectPump(dev_id, false)) {
            // Refresh device info to update button highlighting
            QTimer::singleShot(200, [this, dev_id]() {
                updateControlTabDeviceInfo(dev_id);
            });
        }
    }
}

void MainWindow::on_btnLightOn_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        if (client->setDirectLight(dev_id, true)) {
            // Refresh device info to update button highlighting
            QTimer::singleShot(200, [this, dev_id]() {
                updateControlTabDeviceInfo(dev_id);
            });
        }
    }
}

void MainWindow::on_btnLightOff_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        if (client->setDirectLight(dev_id, false)) {
            // Refresh device info to update button highlighting
            QTimer::singleShot(200, [this, dev_id]() {
                updateControlTabDeviceInfo(dev_id);
            });
        }
    }
}

void MainWindow::on_btnFertOn_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        if (client->setDirectFert(dev_id, true)) {
            // Refresh device info to update button highlighting
            QTimer::singleShot(200, [this, dev_id]() {
                updateControlTabDeviceInfo(dev_id);
            });
        }
    }
}

void MainWindow::on_btnFertOff_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        if (client->setDirectFert(dev_id, false)) {
            // Refresh device info to update button highlighting
            QTimer::singleShot(200, [this, dev_id]() {
                updateControlTabDeviceInfo(dev_id);
            });
        }
    }
}

// ===== Management Tab =====
void MainWindow::on_btnAddGarden_clicked() {
    uint8_t garden_id = ui->spinAddGardenId->value();
    if (client->addGarden(garden_id)) {
        QMessageBox::information(this, "Success", QString("Garden %1 added").arg(garden_id));
    }
}

void MainWindow::on_btnDeleteGarden_clicked() {
    uint8_t garden_id = ui->spinDeleteGardenId->value();
    if (client->deleteGarden(garden_id)) {
        QMessageBox::information(this, "Success", QString("Garden %1 deleted").arg(garden_id));
    }
}

void MainWindow::on_btnAddDevice_clicked() {
    uint8_t device_id = ui->spinAddDeviceId->value();
    uint8_t garden_id = ui->spinAddDeviceGardenId->value();
    QString app_id = ui->editAddDeviceAppId->text();
    
    if (client->addDevice(device_id, garden_id, app_id)) {
        QMessageBox::information(this, "Success", QString("Device %1 added").arg(device_id));
        updateDeviceList();
    }
}

void MainWindow::on_btnDeleteDevice_clicked() {
    uint8_t device_id = ui->spinDeleteDeviceId->value();
    if (client->deleteDevice(device_id)) {
        QMessageBox::information(this, "Success", QString("Device %1 deleted").arg(device_id));
        updateDeviceList();
    }
}

// ===== Settings Tab =====
void MainWindow::on_btnApplyParameters_clicked() {
    int devIdx = ui->comboSettingsDevice->currentIndex();
    if (devIdx < 0) {
        QMessageBox::warning(this, "Error", "Please select a device");
        return;
    }
    
    uint8_t dev_id = ui->comboSettingsDevice->currentData().toUInt();
    uint8_t hmin = ui->spinHmin->value();
    uint8_t hmax = ui->spinHmax->value();
    uint8_t nmin = ui->spinNmin->value();
    uint8_t pmin = ui->spinPmin->value();
    uint8_t kmin = ui->spinKmin->value();
    uint8_t fert_c = ui->spinFertC->value();
    uint8_t fert_v = ui->spinFertV->value();
    uint8_t power = ui->spinPower->value();
    uint8_t interval = ui->spinInterval->value();
    
    // if (client->setParameter(dev_id, hmin, hmax, nmin, pmin, kmin, 
    //                         fert_c, fert_v, power, interval)) {
    //     QMessageBox::information(this, "Success", "Parameters updated");
    // }
}

void MainWindow::on_btnChangePassword_clicked() {
    QString app_id = ui->editPasswordAppId->text();
    QString old_pass = ui->editOldPassword->text();
    QString new_pass = ui->editNewPassword->text();
    
    if (app_id.isEmpty() || old_pass.isEmpty() || new_pass.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "All fields are required");
        return;
    }
    
    if (client->changePassword(app_id, old_pass, new_pass)) {
        QMessageBox::information(this, "Success", "Password changed");
        ui->editOldPassword->clear();
        ui->editNewPassword->clear();
    }
}

void MainWindow::on_btnViewDeviceConfig_clicked() {
    int devIdx = ui->comboSettingsDevice->currentIndex();
    if (devIdx < 0) {
        QMessageBox::warning(this, "Error", "Please select a device");
        return;
    }
    
    uint8_t dev_id = ui->comboSettingsDevice->currentData().toUInt();
    client->getDeviceParams(dev_id);
}

// ===== Logs Tab =====
void MainWindow::updateLogsDisplay() {
    // Update data logs
    ui->tableDataLogs->setRowCount(0);
    auto dataLogs = client->getDataLogs();
    for (const auto& log : dataLogs) {
        int row = ui->tableDataLogs->rowCount();
        ui->tableDataLogs->insertRow(row);
        ui->tableDataLogs->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(log)));
    }
    
    // Update alert logs
    ui->tableAlertLogs->setRowCount(0);
    auto alertLogs = client->getAlertLogs();
    for (const auto& log : alertLogs) {
        int row = ui->tableAlertLogs->rowCount();
        ui->tableAlertLogs->insertRow(row);
        ui->tableAlertLogs->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(log)));
    }
}

void MainWindow::on_btnClearDataLogs_clicked() {
    ui->tableDataLogs->setRowCount(0);
}

void MainWindow::on_btnClearAlertLogs_clicked() {
    ui->tableAlertLogs->setRowCount(0);
}

uint32_t MainWindow::timeEditToTimestamp(QTimeEdit* timeEdit) {
    QDateTime dt = QDateTime::currentDateTime();
    dt.setTime(timeEdit->time());
    return dt.toSecsSinceEpoch();
}
