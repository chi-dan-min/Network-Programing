#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QDateTime>
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

    // Hide main tabs until logged in
    ui->tabWidget->setEnabled(false);
}

MainWindow::~MainWindow() {
    delete ui;
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

    // Initial scan and info
    client->scan();
    client->info();
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
    client->scan();
    client->info();
    updateDeviceList();
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
    }
}

void MainWindow::updateDeviceDetails(uint8_t device_id) {
    IntervalData data = client->getLastIntervalData(device_id);
    DirectState state = client->getDirectState(device_id);
    DeviceSchedules schedules = client->getSchedules(device_id);
    
    // Update sensor data labels
    ui->lblHumidity->setText(QString::number(data.humidity) + "%");
    ui->lblNLevel->setText(QString::number(data.n_level));
    ui->lblPLevel->setText(QString::number(data.p_level));
    ui->lblKLevel->setText(QString::number(data.k_level));
    
    // Update direct control status
    ui->lblPumpStatus->setText(state.pump ? "ON" : "OFF");
    ui->lblLightStatus->setText(state.light ? "ON" : "OFF");
    ui->lblFertStatus->setText(state.fert ? "ON" : "OFF");
    
    // Update schedules display
    ui->lstPumpSchedule->clear();
    for (uint32_t ts : schedules.pump_times) {
        QDateTime dt = QDateTime::fromSecsSinceEpoch(ts);
        ui->lstPumpSchedule->addItem(dt.toString("HH:mm"));
    }
    
    ui->lstLightSchedule->clear();
    for (const auto& pair : schedules.light_pairs) {
        QDateTime on = QDateTime::fromSecsSinceEpoch(pair.first);
        QDateTime off = QDateTime::fromSecsSinceEpoch(pair.second);
        ui->lstLightSchedule->addItem(QString("ON: %1 | OFF: %2")
                                     .arg(on.toString("HH:mm"))
                                     .arg(off.toString("HH:mm")));
    }
}

void MainWindow::onDevicesUpdated() {
    updateDeviceList();
}

void MainWindow::onDeviceDataUpdated(uint8_t dev_id) {
    if (dev_id == currentDeviceId) {
        updateDeviceDetails(dev_id);
    }
    updateLogsDisplay();
}

void MainWindow::onDeviceAlert(uint8_t dev_id, QString alert) {
    if (dev_id == currentDeviceId) {
        updateDeviceDetails(dev_id);
    }
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
        client->setDirectPump(dev_id, true);
    }
}

void MainWindow::on_btnPumpOff_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        client->setDirectPump(dev_id, false);
    }
}

void MainWindow::on_btnLightOn_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        client->setDirectLight(dev_id, true);
    }
}

void MainWindow::on_btnLightOff_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        client->setDirectLight(dev_id, false);
    }
}

void MainWindow::on_btnFertOn_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        client->setDirectFert(dev_id, true);
    }
}

void MainWindow::on_btnFertOff_clicked() {
    int devIdx = ui->comboControlDevice->currentIndex();
    if (devIdx >= 0) {
        uint8_t dev_id = ui->comboControlDevice->currentData().toUInt();
        client->setDirectFert(dev_id, false);
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
    
    if (client->setParameter(dev_id, hmin, hmax, nmin, pmin, kmin, 
                            fert_c, fert_v, power, interval)) {
        QMessageBox::information(this, "Success", "Parameters updated");
    }
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
