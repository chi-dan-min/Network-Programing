#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QMessageBox>
#include <QTabWidget>
#include <QSpinBox>
#include <QGroupBox>
#include <QInputDialog>
#include <QTreeWidget>
#include <QTableWidget>
#include <QHeaderView>
#include <QFormLayout>
#include <QDialog>
#include <QDialogButtonBox>
#include <QRegularExpression>
#include <QComboBox>
#include <QFrame>
#include <QDateTime>
#include <QtCharts/QValueAxis>
#include <QtCharts/QDateTimeAxis>
#include <cfloat>

MainWindow::MainWindow(QWidget *parent) 
    : QMainWindow(parent), client(ClientManager::instance()) 
{
    setupUi();
    resize(1400, 900); // Make GUI bigger
}

MainWindow::~MainWindow() {}

void MainWindow::setupUi() {
    QWidget* central = new QWidget;
    setCentralWidget(central);
    
    // Increase font size for "larger components"
    central->setStyleSheet("QWidget { font-size: 12pt; } QPushButton { padding: 6px; }");
    
    QVBoxLayout* mainLayout = new QVBoxLayout(central);

    // --- CONNECTION BAR ---
    QHBoxLayout* connLayout = new QHBoxLayout;
    connLayout->addWidget(new QLabel("IP:"));
    ipEdit = new QLineEdit("127.0.0.1");
    connLayout->addWidget(ipEdit);
    connectBtn = new QPushButton("Connect");
    connLayout->addWidget(connectBtn);
    
    // Token Label
    tokenLabel = new QLabel("Token: N/A");
    tokenLabel->setStyleSheet("font-weight: bold; color: #555; padding-left: 10px;");
    tokenLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    connLayout->addWidget(tokenLabel);
    
    connLayout->addStretch(); // Push everything to left
    mainLayout->addLayout(connLayout);

    // --- LOGIN BAR ---
    QHBoxLayout* loginLayout = new QHBoxLayout;
    userEdit = new QLineEdit(); userEdit->setPlaceholderText("AppID");
    passEdit = new QLineEdit(); passEdit->setPlaceholderText("Password");
    passEdit->setEchoMode(QLineEdit::Password);
    loginBtn = new QPushButton("Login"); loginBtn->setEnabled(false);
    logoutBtn = new QPushButton("Logout"); logoutBtn->setEnabled(false);
    QPushButton* changePassBtn = new QPushButton("Change Pass");

    loginLayout->addWidget(userEdit);
    loginLayout->addWidget(passEdit);
    loginLayout->addWidget(loginBtn);
    loginLayout->addWidget(logoutBtn);
    loginLayout->addWidget(changePassBtn);
    mainLayout->addLayout(loginLayout);

    // --- DASHBOARD BUTTONS ---
    QHBoxLayout* dashBtns = new QHBoxLayout;
    scanBtn = new QPushButton("Scan For New Devices");
    infoBtn = new QPushButton("Refresh Gardens");
    addGardenBtn = new QPushButton("Add Garden");
    dashBtns->addWidget(scanBtn);
    dashBtns->addWidget(infoBtn);
    dashBtns->addWidget(addGardenBtn);
    mainLayout->addLayout(dashBtns);

    // --- DASHBOARD SCROLL AREA ---
    // Make this the main view
    dashboardScroll = new QScrollArea;
    dashboardScroll->setWidgetResizable(true);
    dashboardContainer = new QWidget;
    dashboardGrid = new QGridLayout(dashboardContainer);
    dashboardGrid->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    dashboardScroll->setWidget(dashboardContainer);
    
    mainLayout->addWidget(dashboardScroll);

    statusLabel = new QLabel("Ready");
    mainLayout->addWidget(statusLabel);

    // SIGNALS
    connect(connectBtn, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    connect(loginBtn, &QPushButton::clicked, this, &MainWindow::onLoginClicked);
    connect(logoutBtn, &QPushButton::clicked, this, &MainWindow::onLogoutClicked);
    connect(changePassBtn, &QPushButton::clicked, this, &MainWindow::onChangePasswordClicked);
    connect(scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);
    connect(infoBtn, &QPushButton::clicked, this, &MainWindow::onInfoClicked);
    connect(addGardenBtn, &QPushButton::clicked, this, &MainWindow::onAddGardenClicked);
}

void MainWindow::onConnectClicked() {
    QString ip = ipEdit->text();
    if (client.connectToServer(ip.toStdString().c_str())) {
        updateStatus("Connected to " + ip);
        connectBtn->setEnabled(false);
        loginBtn->setEnabled(true);
    } else {
        QMessageBox::critical(this, "Error", "Failed to connect to server");
    }
}

void MainWindow::onLoginClicked() {
    QString user = userEdit->text();
    QString pass = passEdit->text();
    if (client.login(user.toStdString(), pass.toStdString())) {
        updateStatus("Login Successful");
        loginBtn->setEnabled(false);
        logoutBtn->setEnabled(true);
        // tabs->setEnabled(true); // Removed
        
        // Show Token
        tokenLabel->setText("Token: " + QString::number(client.getToken()));
        
        onInfoClicked(); 
    } else {
        QMessageBox::critical(this, "Error", "Login Failed");
    }
}

void MainWindow::onLogoutClicked() {
    client.disconnect();
    updateStatus("Logged out (Disconnected)");
    // tabs->setEnabled(false); // Removed
    logoutBtn->setEnabled(false);
    loginBtn->setEnabled(false);
    connectBtn->setEnabled(true);
    passEdit->clear();
    tokenLabel->setText("Token: N/A");
    
    // Clear Dashboard
    QLayoutItem* item;
    while ((item = dashboardGrid->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
}

void MainWindow::onChangePasswordClicked() {
    if (!client.isConnected() || client.getToken() == 0) {
        QMessageBox::warning(this, "Error", "Must be logged in to change password.");
        return;
    }
    
    QDialog dlg(this);
    dlg.setWindowTitle("Change Password");
    QFormLayout* form = new QFormLayout(&dlg);
    
    QLineEdit* oldPass = new QLineEdit; oldPass->setEchoMode(QLineEdit::Password);
    QLineEdit* newPass = new QLineEdit; newPass->setEchoMode(QLineEdit::Password);
    
    form->addRow("Old Password:", oldPass);
    form->addRow("New Password:", newPass);
    
    QDialogButtonBox* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(btns);
    
    dlg.adjustSize();
    if(parentWidget()) dlg.move(parentWidget()->window()->frameGeometry().center() - dlg.rect().center());

    if (dlg.exec() == QDialog::Accepted) {
        QString u = userEdit->text();
        if (client.changePassword(u.toStdString(), oldPass->text().toStdString(), newPass->text().toStdString())) {
            QMessageBox::information(this, "Success", "Password changed successfully.");
        } else {
            QMessageBox::critical(this, "Error", "Failed to change password. check old credentials.");
        }
    }
}

void MainWindow::onScanClicked() {
    if (client.scan()) {
        updateStatus("Scan complete.");
        QString txt = "Found Devices IDs: ";
        for(int id : client.getAvailableDevices()) txt += QString::number(id) + " ";
        QMessageBox::information(this, "Scan Result", txt);
    } else {
        updateStatus("Scan failed");
    }
}

void MainWindow::onInfoClicked() {
    if (client.getInfo(false)) { 
        updateStatus("Refreshed Gardens");
        
        QLayoutItem* item;
        while ((item = dashboardGrid->takeAt(0)) != nullptr) {
            delete item->widget();
            delete item;
        }

        const InfoResponse& info = client.getLastInfo();
        
        int col = 0;
        int row = 0;
        int maxCols = 2; 

        for (int i = 0; i < info.num_gardens; ++i) {
            createGardenCard(info.gardens[i], row, col);
            col++;
            if(col >= maxCols) { col=0; row++; }
        }
    }
}

void MainWindow::onDevSettingsClick(int gId, int devId) {
    if (!client.getDeviceParams(devId, false)) {
        QMessageBox::warning(this, "Error", "Could not fetch device settings");
        return;
    }
    const SettingsResponse& s = client.getLastSettings();

    QDialog dlg(this);
    dlg.setWindowTitle(QString("Config Device %1 (Garden %2)").arg(devId).arg(gId));
    
    QFormLayout* form = new QFormLayout(&dlg);
    
    QSpinBox* spinHmin = new QSpinBox; spinHmin->setRange(0, 100); spinHmin->setValue(s.Hmin);
    QSpinBox* spinHmax = new QSpinBox; spinHmax->setRange(0, 100); spinHmax->setValue(s.Hmax);
    QSpinBox* spinN = new QSpinBox; spinN->setRange(0, 255); spinN->setValue(s.Nmin);
    QSpinBox* spinP = new QSpinBox; spinP->setRange(0, 255); spinP->setValue(s.Pmin);
    QSpinBox* spinK = new QSpinBox; spinK->setRange(0, 255); spinK->setValue(s.Kmin);
    QSpinBox* spinFertC = new QSpinBox; spinFertC->setRange(0, 255); spinFertC->setValue(s.fert_C);
    QSpinBox* spinFertV = new QSpinBox; spinFertV->setRange(0, 255); spinFertV->setValue(s.fert_V);
    
    form->addRow("Humidity Min (%):", spinHmin);
    form->addRow("Humidity Max (%):", spinHmax);
    form->addRow("N Min:", spinN);
    form->addRow("P Min:", spinP);
    form->addRow("K Min:", spinK);
    form->addRow("Fert Conc (g/L):", spinFertC);
    form->addRow("Fert Vol (L):", spinFertV);
    
    QDialogButtonBox* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(btns);
    
    if (dlg.exec() == QDialog::Accepted) {
        client.setParameter(gId, devId, PARAM_ID_H_MIN, spinHmin->value());
        client.setParameter(gId, devId, PARAM_ID_H_MAX, spinHmax->value());
        client.setParameter(gId, devId, PARAM_ID_N_MIN, spinN->value());
        client.setParameter(gId, devId, PARAM_ID_P_MIN, spinP->value());
        client.setParameter(gId, devId, PARAM_ID_K_MIN, spinK->value());
        client.setParameter(gId, devId, PARAM_ID_FERT_C, spinFertC->value());
        client.setParameter(gId, devId, PARAM_ID_FERT_V, spinFertV->value());
        QMessageBox::information(this, "Success", "Settings sent to device.");
    }
}

void MainWindow::onDevScheduleClick(int devId) {
    // Refresh schedules first
    client.getPumpSchedule(devId);
    client.getLightSchedule(devId);
    
    QDialog dlg(this);
    dlg.setWindowTitle(QString("Set Schedule - Device %1").arg(devId));
    QVBoxLayout* layout = new QVBoxLayout(&dlg);
    
    QGroupBox* grpPump = new QGroupBox("Pump Schedule (Timestamps)");
    QVBoxLayout* layPump = new QVBoxLayout(grpPump);
    QTextEdit* txtPump = new QTextEdit;
    txtPump->setPlaceholderText("Enter HHMM separated by space (e.g. 0800 1230)");
    
    QString currentPumpStr = "None";
    if (client.cachedPumpSchedules.count(devId)) {
        QStringList strList;
        for (uint32_t ts : client.cachedPumpSchedules[devId]) {
            time_t raw = (time_t)ts;
            struct tm * t = localtime(&raw);
            strList << QString("%1%2").arg(t->tm_hour, 2, 10, QChar('0')).arg(t->tm_min, 2, 10, QChar('0'));
        }
        currentPumpStr = strList.join(" ");
        txtPump->setText(currentPumpStr); 
    }
    layPump->addWidget(new QLabel("Current: " + currentPumpStr));
    layPump->addWidget(txtPump);
    layout->addWidget(grpPump);
    
    QGroupBox* grpLight = new QGroupBox("Light Schedule (ON OFF pairs)");
    QVBoxLayout* layLight = new QVBoxLayout(grpLight);
    QTextEdit* txtLight = new QTextEdit;
    txtLight->setPlaceholderText("Enter HHMM pairs (e.g. 1800 2200 0600 0700)");
    
    QString currentLightStr = "None";
    if (client.cachedLightSchedules.count(devId)) {
        QStringList strList;
        for (uint32_t ts : client.cachedLightSchedules[devId]) {
             time_t raw = (time_t)ts;
            struct tm * t = localtime(&raw);
            strList << QString("%1%2").arg(t->tm_hour, 2, 10, QChar('0')).arg(t->tm_min, 2, 10, QChar('0'));
        }
        currentLightStr = strList.join(" ");
        txtLight->setText(currentLightStr); 
    }
    layLight->addWidget(new QLabel("Current: " + currentLightStr));
    layLight->addWidget(txtLight);
    layout->addWidget(grpLight);
    
    QDialogButtonBox* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    layout->addWidget(btns);
    
    if (dlg.exec() == QDialog::Accepted) {
        QString pumpStr = txtPump->toPlainText();
        if(!pumpStr.trimmed().isEmpty()) {
            QStringList tokens = pumpStr.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            vector<uint32_t> ts;
            for(const QString& t : tokens) {
                ts.push_back(convert_hhmm_to_timestamp(t.toUInt()));
            }
            if(!ts.empty()) client.setPumpSchedule(devId, ts);
        }
        QString lightStr = txtLight->toPlainText();
        if(!lightStr.trimmed().isEmpty()) {
            QStringList tokens = lightStr.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            vector<uint32_t> ts;
            for(const QString& t : tokens) {
                ts.push_back(convert_hhmm_to_timestamp(t.toUInt()));
            }
            if(!ts.empty() && ts.size() % 2 == 0) client.setLightSchedule(devId, ts);
        }
    }
}

void MainWindow::onDevPumpClick(int devId, bool checked) {
    client.setDirectPump(devId, checked);
}
void MainWindow::onDevLightClick(int devId, bool checked) {
    client.setDirectLight(devId, checked);
}
void MainWindow::onDevFertClick(int devId, bool checked) {
    client.setDirectFert(devId, checked);
}
void MainWindow::onDevDeleteClick(int gId, int devId) {
    auto reply = QMessageBox::question(this, "Confirm Delete", 
        QString("Are you sure you want to delete Device %1 from Garden %2?").arg(devId).arg(gId),
        QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        if (client.deleteDevice(gId, devId)) {
            updateStatus(QString("Deleted Device %1").arg(devId));
            onInfoClicked(); 
        } else {
            QMessageBox::warning(this, "Error", "Failed to delete device.");
        }
    }
}
void MainWindow::onGardenDeleteClick(int gId) {
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Confirm Delete Garden");
    msgBox.setText(QString("Are you sure you want to delete Garden %1?\nThis will remove all devices inside!").arg(gId));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    QPoint center = this->geometry().center();
    msgBox.adjustSize();
    QPoint boxCenter = msgBox.rect().center();
    msgBox.move(center - boxCenter);

    if (msgBox.exec() == QMessageBox::Yes) {
        if (client.deleteGarden(gId)) {
            updateStatus(QString("Deleted Garden %1").arg(gId));
            onInfoClicked(); 
        } else {
            QMessageBox::warning(this, "Error", "Failed to delete garden.");
        }
    }
}

void MainWindow::onGardenAddDeviceClick(int gId) {
    const vector<int>& devices = client.getAvailableDevices();
    if (devices.empty()) {
        QMessageBox msgBox(this);
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.setWindowTitle("No Devices");
        msgBox.setText("No scanned devices available. Please click 'Scan For New Devices' first.");
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.adjustSize();
        if (this->window()) {
            QPoint center = this->window()->geometry().center();
            msgBox.move(center - msgBox.rect().center());
        }
        msgBox.exec();
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(QString("Add Device to Garden %1").arg(gId));
    QVBoxLayout* layout = new QVBoxLayout(&dlg);
    QLabel* lbl = new QLabel("Select a Device ID to add:");
    layout->addWidget(lbl);
    QComboBox* combo = new QComboBox;
    for(int id : devices) {
        combo->addItem(QString::number(id), id);
    }
    layout->addWidget(combo);
    QDialogButtonBox* btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    layout->addWidget(btns);
    dlg.adjustSize();
    if(parentWidget()) {
       dlg.move(parentWidget()->window()->frameGeometry().center() - dlg.rect().center());
    }
    if (dlg.exec() == QDialog::Accepted) {
        int devId = combo->currentData().toInt();
        if (client.addDevice(gId, devId)) {
            updateStatus(QString("Added Device %1 to Garden %2").arg(devId).arg(gId));
            onInfoClicked(); // Refresh
        } else {
            QMessageBox::warning(this, "Error", "Failed to add device to garden.");
        }
    }
}

void MainWindow::onAddGardenClicked() {
    bool ok;
    int id = QInputDialog::getInt(this, "Add Garden", "Enter Garden ID:", 1, 1, 255, 1, &ok);
    if (ok) {
        if (client.addGarden(id)) {
            updateStatus(QString("Added Garden %1").arg(id));
            onInfoClicked(); 
        } else {
            QMessageBox::warning(this, "Failure", "Failed to add garden");
        }
    }
}

// --- LOGS DIAGLOG ---
void MainWindow::onDevLogsClick(int devId){
    QDialog dlg(this);
    dlg.setWindowTitle(QString("Logs & Stats - Device %1").arg(devId));
    dlg.resize(1000, 700);

    QVBoxLayout* layout = new QVBoxLayout(&dlg);

    // ================== CHART ==================
    QChart* chart = new QChart();
    chart->setTitle("Sensor History (Real-time)");
    chart->legend()->setVisible(true);
    chart->legend()->setAlignment(Qt::AlignBottom);

    QChartView* chartView = new QChartView(chart);
    chartView->setRenderHint(QPainter::Antialiasing);
    layout->addWidget(chartView, 3);

    QLineSeries* soil = new QLineSeries(); soil->setName("Soil Moisture (%)");
    QLineSeries* n    = new QLineSeries(); n->setName("Nitrogen (N)");
    QLineSeries* p    = new QLineSeries(); p->setName("Phosphorus (P)");
    QLineSeries* k    = new QLineSeries(); k->setName("Potassium (K)");

    chart->addSeries(soil);
    chart->addSeries(n);
    chart->addSeries(p);
    chart->addSeries(k);

    // ================== REGEX ==================
    static QRegularExpression reg(
        R"((\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+Dev:(\d+)\s*\|\s*Soil:(\d+)%\s*\|\s*N:(\d+)\s*\|\s*P:(\d+)\s*\|\s*K:(\d+))"
    );


    qint64 minTime = LLONG_MAX;
    qint64 maxTime = 0;
    double minY = DBL_MAX;
    double maxY = -DBL_MAX;

    const auto& logs = client.getDataLogs();

    for (const auto& s : logs)
    {
        QString qs = QString::fromStdString(s);
        auto m = reg.match(qs);
        if (!m.hasMatch()) continue;
        if (m.captured(2).toInt() != devId) continue;

        QDateTime dt = QDateTime::fromString(
            m.captured(1),
            "dd/MM/yyyy hh:mm:ss"
        );
        if (!dt.isValid()) continue;

        qint64 t = dt.toMSecsSinceEpoch();

        double vSoil = m.captured(3).toDouble();
        double vN    = m.captured(4).toDouble();
        double vP    = m.captured(5).toDouble();
        double vK    = m.captured(6).toDouble();
        
        soil->append(t, vSoil);
        n->append(t, vN);
        p->append(t, vP);
        k->append(t, vK);

        minTime = qMin(minTime, t);
        maxTime = qMax(maxTime, t);

        minY = qMin(minY, std::min({vSoil, vN, vP, vK}));
        maxY = qMax(maxY, std::max({vSoil, vN, vP, vK}));
    }

    // ================== AXES ==================
    QDateTimeAxis* axisX = new QDateTimeAxis();
    axisX->setFormat("hh:mm:ss");
    axisX->setTitleText("Time");

    QValueAxis* axisY = new QValueAxis();
    axisY->setTitleText("Values");

    if (minTime < maxTime) {
        axisX->setRange(
            QDateTime::fromMSecsSinceEpoch(minTime),
            QDateTime::fromMSecsSinceEpoch(maxTime)
        );
        axisY->setRange(minY - 5, maxY + 5);
    } else {
        axisY->setRange(0, 100);
    }

    chart->addAxis(axisX, Qt::AlignBottom);
    chart->addAxis(axisY, Qt::AlignLeft);

    soil->attachAxis(axisX); soil->attachAxis(axisY);
    n->attachAxis(axisX);    n->attachAxis(axisY);
    p->attachAxis(axisX);    p->attachAxis(axisY);
    k->attachAxis(axisX);    k->attachAxis(axisY);

    // ================== ALERT TABLE ==================
    QGroupBox* grpAlert = new QGroupBox("Alerts / Events");
    QVBoxLayout* layAlert = new QVBoxLayout(grpAlert);

    QTableWidget* table = new QTableWidget();
    table->setColumnCount(1);
    table->setHorizontalHeaderLabels({"Message"});
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

    layAlert->addWidget(table);
    layout->addWidget(grpAlert, 2);

    const auto& alerts = client.getAlertLogs();
    for (const auto& s : alerts)
    {
        QString qs = QString::fromStdString(s);
        if (!qs.contains(QString(" Dev:%1 -").arg(devId))) continue;

        int row = table->rowCount();
        table->insertRow(row);

        QTableWidgetItem* item = new QTableWidgetItem(qs);
        if (qs.contains("Error") || qs.contains("Alert Code"))
            item->setBackground(QColor(255, 200, 200));
        else if (qs.contains("Start"))
            item->setBackground(QColor(255, 255, 200));
        else
            item->setBackground(QColor(200, 255, 200));

        table->setItem(row, 0, item);
    }

    // ================== CLOSE BUTTON ==================
    QDialogButtonBox* btn = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(btn, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    layout->addWidget(btn);

    dlg.exec();
}

void MainWindow::updateStatus(const QString &msg) {
    statusLabel->setText(msg);
}

void MainWindow::createGardenCard(const GardenInfo& g, int row, int col) {
    QFrame* card = new QFrame;
    card->setFrameStyle(QFrame::StyledPanel | QFrame::Raised);
    card->setStyleSheet("QFrame { background-color: #f9f9f9; border-radius: 8px; margin: 5px; }");
    
    QVBoxLayout* cardLayout = new QVBoxLayout(card);
    
    // Header
    QHBoxLayout* header = new QHBoxLayout;
    QLabel* title = new QLabel(QString("Garden %1").arg(g.garden_id)); // User request: No Emoji
    title->setStyleSheet("font-weight: bold; font-size: 14pt; color: #2c3e50; border: none;");
    
    QPushButton* btnDelGarden = new QPushButton("Delete");
    btnDelGarden->setCursor(Qt::PointingHandCursor);
    btnDelGarden->setStyleSheet("QPushButton { color: #e74c3c; border: 1px solid #e74c3c; border-radius: 4px; padding: 4px; background: transparent; } QPushButton:hover { background-color: #e74c3c; color: white; }");
    
    connect(btnDelGarden, &QPushButton::clicked, [this, g]() {
        onGardenDeleteClick(g.garden_id);
    });
    
    QPushButton* btnAddDev = new QPushButton("Add Device");
    connect(btnAddDev, &QPushButton::clicked, [this, g]() {
        onGardenAddDeviceClick(g.garden_id);
    });

    header->addWidget(title);
    header->addStretch();
    header->addWidget(btnAddDev);
    header->addWidget(btnDelGarden);
    
    cardLayout->addLayout(header);
    
    // Status Summary
    QLabel* status = new QLabel(QString("Devices: %1").arg(g.num_devices));
    status->setStyleSheet("color: #7f8c8d; font-size: 10pt; border: none;");
    cardLayout->addWidget(status);
    
    // Separator
    QFrame* line = new QFrame();
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    cardLayout->addWidget(line);
    
    // Devices List
    QGridLayout* devGrid = new QGridLayout;
    devGrid->setSpacing(5);
    
    int dRow = 0;
    for(int i=0; i<g.num_devices; ++i) {
        devGrid->addWidget(createDeviceRow(g.garden_id, g.devices[i]), dRow, 0);
        dRow++;
    }
    cardLayout->addLayout(devGrid);
    cardLayout->addStretch(); 
    
    dashboardGrid->addWidget(card, row, col);
}

QWidget* MainWindow::createDeviceRow(int gId, const DeviceInfo& dev) {
    QWidget* w = new QWidget;
    w->setStyleSheet("background: transparent; border: none;"); 
    QHBoxLayout* l = new QHBoxLayout(w);
    l->setContentsMargins(0, 2, 0, 2);
    
    QLabel* name = new QLabel(QString("Device %1").arg(dev.device_id));
    name->setStyleSheet("font-weight: bold;");
    l->addWidget(name);
    
    l->addStretch();
    
    // Actions: Using TEXT buttons for compatibility
    QPushButton* btnLogs = new QPushButton("Logs");
    QPushButton* btnSet = new QPushButton("Config");
    QPushButton* btnSch = new QPushButton("Sched");
    QPushButton* btnPump = new QPushButton("Pump"); btnPump->setCheckable(true);
    QPushButton* btnLight = new QPushButton("Light"); btnLight->setCheckable(true);
    QPushButton* btnFert = new QPushButton("Fert"); btnFert->setCheckable(true);
    QPushButton* btnDel = new QPushButton("Del");
    
    // Style
    QString baseBtnStyle = "QPushButton { padding: 4px; font-size: 10pt; min-width: 40px; margin-right: 2px; }";
    btnLogs->setStyleSheet(baseBtnStyle + "QPushButton { background-color: #ecf0f1; border: 1px solid #bdc3c7; border-radius: 4px; }");
    btnSet->setStyleSheet(baseBtnStyle);
    btnSch->setStyleSheet(baseBtnStyle);
    btnDel->setStyleSheet(baseBtnStyle + "QPushButton { color: red; font-weight: bold; }");
    
    // Toggle Style
    QString toggleStyle = baseBtnStyle + "QPushButton:checked { background-color: #3498db; color: white; border-radius: 4px; } QPushButton:!checked { background-color: #ecf0f1; }";
    btnPump->setStyleSheet(toggleStyle);
    btnLight->setStyleSheet(toggleStyle);
    btnFert->setStyleSheet(toggleStyle);

    l->addWidget(btnLogs);
    l->addWidget(btnSet);
    l->addWidget(btnSch);
    l->addWidget(btnPump);
    l->addWidget(btnLight);
    l->addWidget(btnFert);
    l->addWidget(btnDel);

    // Signals
    int devId = dev.device_id;
    connect(btnLogs, &QPushButton::clicked, [this, devId](){ onDevLogsClick(devId); });
    connect(btnSet, &QPushButton::clicked, [this, gId, devId](){ onDevSettingsClick(gId, devId); });
    connect(btnSch, &QPushButton::clicked, [this, devId](){ onDevScheduleClick(devId); });
    connect(btnPump, &QPushButton::toggled, [this, devId](bool c){ onDevPumpClick(devId, c); });
    connect(btnLight, &QPushButton::toggled, [this, devId](bool c){ onDevLightClick(devId, c); });
    connect(btnFert, &QPushButton::toggled, [this, devId](bool c){ onDevFertClick(devId, c); });
    connect(btnDel, &QPushButton::clicked, [this, gId, devId](){ onDevDeleteClick(gId, devId); });

    // Sync Status
    if (client.getDeviceStatus(devId)) {
        const StatusResponse& s = client.getLastStatus();
        btnPump->blockSignals(true); btnPump->setChecked(s.pump_status); btnPump->blockSignals(false);
        btnLight->blockSignals(true); btnLight->setChecked(s.light_status); btnLight->blockSignals(false);
        btnFert->blockSignals(true); btnFert->setChecked(s.fert_status); btnFert->blockSignals(false);
    }

    return w;
}
