/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.4.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTimeEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QGroupBox *groupConnection;
    QHBoxLayout *connectionLayout;
    QLabel *labelServerIP;
    QLineEdit *editServerIP;
    QLabel *labelUsername;
    QLineEdit *editUsername;
    QLabel *labelPassword;
    QLineEdit *editPassword;
    QPushButton *btnConnectLogin;
    QTabWidget *tabWidget;
    QWidget *tabMonitoring;
    QHBoxLayout *monitoringLayout;
    QGroupBox *groupDeviceList;
    QVBoxLayout *vboxLayout;
    QListWidget *deviceList;
    QPushButton *btnRefreshDevices;
    QGroupBox *groupDeviceDetails;
    QVBoxLayout *vboxLayout1;
    QGroupBox *groupSensorData;
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *lblHumidity;
    QLabel *label1;
    QLabel *lblNLevel;
    QLabel *label2;
    QLabel *lblPLevel;
    QLabel *label3;
    QLabel *lblKLevel;
    QGroupBox *groupDirectStatus;
    QFormLayout *formLayout1;
    QLabel *label4;
    QLabel *lblPumpStatus;
    QLabel *label5;
    QLabel *lblLightStatus;
    QLabel *label6;
    QLabel *lblFertStatus;
    QGroupBox *groupSchedules;
    QHBoxLayout *hboxLayout;
    QVBoxLayout *vboxLayout2;
    QLabel *label7;
    QListWidget *lstPumpSchedule;
    QVBoxLayout *vboxLayout3;
    QLabel *label8;
    QListWidget *lstLightSchedule;
    QWidget *tabControl;
    QVBoxLayout *vboxLayout4;
    QHBoxLayout *hboxLayout1;
    QLabel *label9;
    QComboBox *comboControlDevice;
    QGroupBox *groupPumpSchedule;
    QHBoxLayout *hboxLayout2;
    QListWidget *lstPumpTimes;
    QVBoxLayout *vboxLayout5;
    QTimeEdit *timePump;
    QPushButton *btnAddPumpTime;
    QPushButton *btnRemovePumpTime;
    QPushButton *btnApplyPumpSchedule;
    QSpacerItem *spacerItem;
    QGroupBox *groupLightSchedule;
    QHBoxLayout *hboxLayout3;
    QListWidget *lstLightPairs;
    QVBoxLayout *vboxLayout6;
    QLabel *label10;
    QTimeEdit *timeLightOn;
    QLabel *label11;
    QTimeEdit *timeLightOff;
    QPushButton *btnAddLightPair;
    QPushButton *btnRemoveLightPair;
    QPushButton *btnApplyLightSchedule;
    QSpacerItem *spacerItem1;
    QGroupBox *groupDirectControl;
    QHBoxLayout *hboxLayout4;
    QVBoxLayout *vboxLayout7;
    QLabel *label12;
    QPushButton *btnPumpOn;
    QPushButton *btnPumpOff;
    QVBoxLayout *vboxLayout8;
    QLabel *label13;
    QPushButton *btnLightOn;
    QPushButton *btnLightOff;
    QVBoxLayout *vboxLayout9;
    QLabel *label14;
    QPushButton *btnFertOn;
    QPushButton *btnFertOff;
    QWidget *tabManagement;
    QHBoxLayout *hboxLayout5;
    QGroupBox *groupGardenMgmt;
    QVBoxLayout *vboxLayout10;
    QFormLayout *formLayout2;
    QLabel *label15;
    QSpinBox *spinAddGardenId;
    QPushButton *btnAddGarden;
    QFrame *line;
    QFormLayout *formLayout3;
    QLabel *label16;
    QSpinBox *spinDeleteGardenId;
    QPushButton *btnDeleteGarden;
    QSpacerItem *spacerItem2;
    QGroupBox *groupDeviceMgmt;
    QVBoxLayout *vboxLayout11;
    QFormLayout *formLayout4;
    QLabel *label17;
    QSpinBox *spinAddDeviceId;
    QLabel *label18;
    QSpinBox *spinAddDeviceGardenId;
    QLabel *label19;
    QLineEdit *editAddDeviceAppId;
    QPushButton *btnAddDevice;
    QFrame *line1;
    QFormLayout *formLayout5;
    QLabel *label20;
    QSpinBox *spinDeleteDeviceId;
    QPushButton *btnDeleteDevice;
    QSpacerItem *spacerItem3;
    QWidget *tabLogs;
    QVBoxLayout *vboxLayout12;
    QGroupBox *groupDataLogs;
    QVBoxLayout *vboxLayout13;
    QTableWidget *tableDataLogs;
    QPushButton *btnClearDataLogs;
    QGroupBox *groupAlertLogs;
    QVBoxLayout *vboxLayout14;
    QTableWidget *tableAlertLogs;
    QPushButton *btnClearAlertLogs;
    QWidget *tabSettings;
    QVBoxLayout *vboxLayout15;
    QHBoxLayout *hboxLayout6;
    QLabel *label21;
    QComboBox *comboSettingsDevice;
    QGroupBox *groupSetParameters;
    QFormLayout *formLayout6;
    QLabel *label22;
    QSpinBox *spinHmin;
    QLabel *label23;
    QSpinBox *spinHmax;
    QLabel *label24;
    QSpinBox *spinNmin;
    QLabel *label25;
    QSpinBox *spinPmin;
    QLabel *label26;
    QSpinBox *spinKmin;
    QLabel *label27;
    QSpinBox *spinFertC;
    QLabel *label28;
    QSpinBox *spinFertV;
    QLabel *label29;
    QSpinBox *spinPower;
    QLabel *label30;
    QSpinBox *spinInterval;
    QPushButton *btnApplyParameters;
    QGroupBox *groupChangePassword;
    QFormLayout *formLayout7;
    QLabel *label31;
    QLineEdit *editPasswordAppId;
    QLabel *label32;
    QLineEdit *editOldPassword;
    QLabel *label33;
    QLineEdit *editNewPassword;
    QPushButton *btnChangePassword;
    QPushButton *btnViewDeviceConfig;
    QGroupBox *groupPacketViewer;
    QVBoxLayout *vboxLayout16;
    QTextEdit *packetView;
    QTextEdit *logView;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(1000, 700);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        groupConnection = new QGroupBox(centralwidget);
        groupConnection->setObjectName("groupConnection");
        connectionLayout = new QHBoxLayout(groupConnection);
        connectionLayout->setObjectName("connectionLayout");
        labelServerIP = new QLabel(groupConnection);
        labelServerIP->setObjectName("labelServerIP");

        connectionLayout->addWidget(labelServerIP);

        editServerIP = new QLineEdit(groupConnection);
        editServerIP->setObjectName("editServerIP");

        connectionLayout->addWidget(editServerIP);

        labelUsername = new QLabel(groupConnection);
        labelUsername->setObjectName("labelUsername");

        connectionLayout->addWidget(labelUsername);

        editUsername = new QLineEdit(groupConnection);
        editUsername->setObjectName("editUsername");

        connectionLayout->addWidget(editUsername);

        labelPassword = new QLabel(groupConnection);
        labelPassword->setObjectName("labelPassword");

        connectionLayout->addWidget(labelPassword);

        editPassword = new QLineEdit(groupConnection);
        editPassword->setObjectName("editPassword");
        editPassword->setEchoMode(QLineEdit::Password);

        connectionLayout->addWidget(editPassword);

        btnConnectLogin = new QPushButton(groupConnection);
        btnConnectLogin->setObjectName("btnConnectLogin");

        connectionLayout->addWidget(btnConnectLogin);


        verticalLayout->addWidget(groupConnection);

        tabWidget = new QTabWidget(centralwidget);
        tabWidget->setObjectName("tabWidget");
        tabMonitoring = new QWidget();
        tabMonitoring->setObjectName("tabMonitoring");
        monitoringLayout = new QHBoxLayout(tabMonitoring);
        monitoringLayout->setObjectName("monitoringLayout");
        groupDeviceList = new QGroupBox(tabMonitoring);
        groupDeviceList->setObjectName("groupDeviceList");
        groupDeviceList->setMaximumWidth(200);
        vboxLayout = new QVBoxLayout(groupDeviceList);
        vboxLayout->setObjectName("vboxLayout");
        deviceList = new QListWidget(groupDeviceList);
        deviceList->setObjectName("deviceList");

        vboxLayout->addWidget(deviceList);

        btnRefreshDevices = new QPushButton(groupDeviceList);
        btnRefreshDevices->setObjectName("btnRefreshDevices");

        vboxLayout->addWidget(btnRefreshDevices);


        monitoringLayout->addWidget(groupDeviceList);

        groupDeviceDetails = new QGroupBox(tabMonitoring);
        groupDeviceDetails->setObjectName("groupDeviceDetails");
        vboxLayout1 = new QVBoxLayout(groupDeviceDetails);
        vboxLayout1->setObjectName("vboxLayout1");
        groupSensorData = new QGroupBox(groupDeviceDetails);
        groupSensorData->setObjectName("groupSensorData");
        formLayout = new QFormLayout(groupSensorData);
        formLayout->setObjectName("formLayout");
        label = new QLabel(groupSensorData);
        label->setObjectName("label");

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        lblHumidity = new QLabel(groupSensorData);
        lblHumidity->setObjectName("lblHumidity");

        formLayout->setWidget(0, QFormLayout::FieldRole, lblHumidity);

        label1 = new QLabel(groupSensorData);
        label1->setObjectName("label1");

        formLayout->setWidget(1, QFormLayout::LabelRole, label1);

        lblNLevel = new QLabel(groupSensorData);
        lblNLevel->setObjectName("lblNLevel");

        formLayout->setWidget(1, QFormLayout::FieldRole, lblNLevel);

        label2 = new QLabel(groupSensorData);
        label2->setObjectName("label2");

        formLayout->setWidget(2, QFormLayout::LabelRole, label2);

        lblPLevel = new QLabel(groupSensorData);
        lblPLevel->setObjectName("lblPLevel");

        formLayout->setWidget(2, QFormLayout::FieldRole, lblPLevel);

        label3 = new QLabel(groupSensorData);
        label3->setObjectName("label3");

        formLayout->setWidget(3, QFormLayout::LabelRole, label3);

        lblKLevel = new QLabel(groupSensorData);
        lblKLevel->setObjectName("lblKLevel");

        formLayout->setWidget(3, QFormLayout::FieldRole, lblKLevel);


        vboxLayout1->addWidget(groupSensorData);

        groupDirectStatus = new QGroupBox(groupDeviceDetails);
        groupDirectStatus->setObjectName("groupDirectStatus");
        formLayout1 = new QFormLayout(groupDirectStatus);
        formLayout1->setObjectName("formLayout1");
        label4 = new QLabel(groupDirectStatus);
        label4->setObjectName("label4");

        formLayout1->setWidget(0, QFormLayout::LabelRole, label4);

        lblPumpStatus = new QLabel(groupDirectStatus);
        lblPumpStatus->setObjectName("lblPumpStatus");

        formLayout1->setWidget(0, QFormLayout::FieldRole, lblPumpStatus);

        label5 = new QLabel(groupDirectStatus);
        label5->setObjectName("label5");

        formLayout1->setWidget(1, QFormLayout::LabelRole, label5);

        lblLightStatus = new QLabel(groupDirectStatus);
        lblLightStatus->setObjectName("lblLightStatus");

        formLayout1->setWidget(1, QFormLayout::FieldRole, lblLightStatus);

        label6 = new QLabel(groupDirectStatus);
        label6->setObjectName("label6");

        formLayout1->setWidget(2, QFormLayout::LabelRole, label6);

        lblFertStatus = new QLabel(groupDirectStatus);
        lblFertStatus->setObjectName("lblFertStatus");

        formLayout1->setWidget(2, QFormLayout::FieldRole, lblFertStatus);


        vboxLayout1->addWidget(groupDirectStatus);

        groupSchedules = new QGroupBox(groupDeviceDetails);
        groupSchedules->setObjectName("groupSchedules");
        hboxLayout = new QHBoxLayout(groupSchedules);
        hboxLayout->setObjectName("hboxLayout");
        vboxLayout2 = new QVBoxLayout();
        vboxLayout2->setObjectName("vboxLayout2");
        label7 = new QLabel(groupSchedules);
        label7->setObjectName("label7");

        vboxLayout2->addWidget(label7);

        lstPumpSchedule = new QListWidget(groupSchedules);
        lstPumpSchedule->setObjectName("lstPumpSchedule");

        vboxLayout2->addWidget(lstPumpSchedule);


        hboxLayout->addLayout(vboxLayout2);

        vboxLayout3 = new QVBoxLayout();
        vboxLayout3->setObjectName("vboxLayout3");
        label8 = new QLabel(groupSchedules);
        label8->setObjectName("label8");

        vboxLayout3->addWidget(label8);

        lstLightSchedule = new QListWidget(groupSchedules);
        lstLightSchedule->setObjectName("lstLightSchedule");

        vboxLayout3->addWidget(lstLightSchedule);


        hboxLayout->addLayout(vboxLayout3);


        vboxLayout1->addWidget(groupSchedules);


        monitoringLayout->addWidget(groupDeviceDetails);

        tabWidget->addTab(tabMonitoring, QString());
        tabControl = new QWidget();
        tabControl->setObjectName("tabControl");
        vboxLayout4 = new QVBoxLayout(tabControl);
        vboxLayout4->setObjectName("vboxLayout4");
        hboxLayout1 = new QHBoxLayout();
        hboxLayout1->setObjectName("hboxLayout1");
        label9 = new QLabel(tabControl);
        label9->setObjectName("label9");

        hboxLayout1->addWidget(label9);

        comboControlDevice = new QComboBox(tabControl);
        comboControlDevice->setObjectName("comboControlDevice");

        hboxLayout1->addWidget(comboControlDevice);


        vboxLayout4->addLayout(hboxLayout1);

        groupPumpSchedule = new QGroupBox(tabControl);
        groupPumpSchedule->setObjectName("groupPumpSchedule");
        hboxLayout2 = new QHBoxLayout(groupPumpSchedule);
        hboxLayout2->setObjectName("hboxLayout2");
        lstPumpTimes = new QListWidget(groupPumpSchedule);
        lstPumpTimes->setObjectName("lstPumpTimes");

        hboxLayout2->addWidget(lstPumpTimes);

        vboxLayout5 = new QVBoxLayout();
        vboxLayout5->setObjectName("vboxLayout5");
        timePump = new QTimeEdit(groupPumpSchedule);
        timePump->setObjectName("timePump");

        vboxLayout5->addWidget(timePump);

        btnAddPumpTime = new QPushButton(groupPumpSchedule);
        btnAddPumpTime->setObjectName("btnAddPumpTime");

        vboxLayout5->addWidget(btnAddPumpTime);

        btnRemovePumpTime = new QPushButton(groupPumpSchedule);
        btnRemovePumpTime->setObjectName("btnRemovePumpTime");

        vboxLayout5->addWidget(btnRemovePumpTime);

        btnApplyPumpSchedule = new QPushButton(groupPumpSchedule);
        btnApplyPumpSchedule->setObjectName("btnApplyPumpSchedule");

        vboxLayout5->addWidget(btnApplyPumpSchedule);

        spacerItem = new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        vboxLayout5->addItem(spacerItem);


        hboxLayout2->addLayout(vboxLayout5);


        vboxLayout4->addWidget(groupPumpSchedule);

        groupLightSchedule = new QGroupBox(tabControl);
        groupLightSchedule->setObjectName("groupLightSchedule");
        hboxLayout3 = new QHBoxLayout(groupLightSchedule);
        hboxLayout3->setObjectName("hboxLayout3");
        lstLightPairs = new QListWidget(groupLightSchedule);
        lstLightPairs->setObjectName("lstLightPairs");

        hboxLayout3->addWidget(lstLightPairs);

        vboxLayout6 = new QVBoxLayout();
        vboxLayout6->setObjectName("vboxLayout6");
        label10 = new QLabel(groupLightSchedule);
        label10->setObjectName("label10");

        vboxLayout6->addWidget(label10);

        timeLightOn = new QTimeEdit(groupLightSchedule);
        timeLightOn->setObjectName("timeLightOn");

        vboxLayout6->addWidget(timeLightOn);

        label11 = new QLabel(groupLightSchedule);
        label11->setObjectName("label11");

        vboxLayout6->addWidget(label11);

        timeLightOff = new QTimeEdit(groupLightSchedule);
        timeLightOff->setObjectName("timeLightOff");

        vboxLayout6->addWidget(timeLightOff);

        btnAddLightPair = new QPushButton(groupLightSchedule);
        btnAddLightPair->setObjectName("btnAddLightPair");

        vboxLayout6->addWidget(btnAddLightPair);

        btnRemoveLightPair = new QPushButton(groupLightSchedule);
        btnRemoveLightPair->setObjectName("btnRemoveLightPair");

        vboxLayout6->addWidget(btnRemoveLightPair);

        btnApplyLightSchedule = new QPushButton(groupLightSchedule);
        btnApplyLightSchedule->setObjectName("btnApplyLightSchedule");

        vboxLayout6->addWidget(btnApplyLightSchedule);

        spacerItem1 = new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        vboxLayout6->addItem(spacerItem1);


        hboxLayout3->addLayout(vboxLayout6);


        vboxLayout4->addWidget(groupLightSchedule);

        groupDirectControl = new QGroupBox(tabControl);
        groupDirectControl->setObjectName("groupDirectControl");
        hboxLayout4 = new QHBoxLayout(groupDirectControl);
        hboxLayout4->setObjectName("hboxLayout4");
        vboxLayout7 = new QVBoxLayout();
        vboxLayout7->setObjectName("vboxLayout7");
        label12 = new QLabel(groupDirectControl);
        label12->setObjectName("label12");

        vboxLayout7->addWidget(label12);

        btnPumpOn = new QPushButton(groupDirectControl);
        btnPumpOn->setObjectName("btnPumpOn");

        vboxLayout7->addWidget(btnPumpOn);

        btnPumpOff = new QPushButton(groupDirectControl);
        btnPumpOff->setObjectName("btnPumpOff");

        vboxLayout7->addWidget(btnPumpOff);


        hboxLayout4->addLayout(vboxLayout7);

        vboxLayout8 = new QVBoxLayout();
        vboxLayout8->setObjectName("vboxLayout8");
        label13 = new QLabel(groupDirectControl);
        label13->setObjectName("label13");

        vboxLayout8->addWidget(label13);

        btnLightOn = new QPushButton(groupDirectControl);
        btnLightOn->setObjectName("btnLightOn");

        vboxLayout8->addWidget(btnLightOn);

        btnLightOff = new QPushButton(groupDirectControl);
        btnLightOff->setObjectName("btnLightOff");

        vboxLayout8->addWidget(btnLightOff);


        hboxLayout4->addLayout(vboxLayout8);

        vboxLayout9 = new QVBoxLayout();
        vboxLayout9->setObjectName("vboxLayout9");
        label14 = new QLabel(groupDirectControl);
        label14->setObjectName("label14");

        vboxLayout9->addWidget(label14);

        btnFertOn = new QPushButton(groupDirectControl);
        btnFertOn->setObjectName("btnFertOn");

        vboxLayout9->addWidget(btnFertOn);

        btnFertOff = new QPushButton(groupDirectControl);
        btnFertOff->setObjectName("btnFertOff");

        vboxLayout9->addWidget(btnFertOff);


        hboxLayout4->addLayout(vboxLayout9);


        vboxLayout4->addWidget(groupDirectControl);

        tabWidget->addTab(tabControl, QString());
        tabManagement = new QWidget();
        tabManagement->setObjectName("tabManagement");
        hboxLayout5 = new QHBoxLayout(tabManagement);
        hboxLayout5->setObjectName("hboxLayout5");
        groupGardenMgmt = new QGroupBox(tabManagement);
        groupGardenMgmt->setObjectName("groupGardenMgmt");
        vboxLayout10 = new QVBoxLayout(groupGardenMgmt);
        vboxLayout10->setObjectName("vboxLayout10");
        formLayout2 = new QFormLayout();
        formLayout2->setObjectName("formLayout2");
        label15 = new QLabel(groupGardenMgmt);
        label15->setObjectName("label15");

        formLayout2->setWidget(0, QFormLayout::LabelRole, label15);

        spinAddGardenId = new QSpinBox(groupGardenMgmt);
        spinAddGardenId->setObjectName("spinAddGardenId");
        spinAddGardenId->setMinimum(1);
        spinAddGardenId->setMaximum(255);

        formLayout2->setWidget(0, QFormLayout::FieldRole, spinAddGardenId);

        btnAddGarden = new QPushButton(groupGardenMgmt);
        btnAddGarden->setObjectName("btnAddGarden");

        formLayout2->setWidget(1, QFormLayout::FieldRole, btnAddGarden);


        vboxLayout10->addLayout(formLayout2);

        line = new QFrame(groupGardenMgmt);
        line->setObjectName("line");
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);

        vboxLayout10->addWidget(line);

        formLayout3 = new QFormLayout();
        formLayout3->setObjectName("formLayout3");
        label16 = new QLabel(groupGardenMgmt);
        label16->setObjectName("label16");

        formLayout3->setWidget(0, QFormLayout::LabelRole, label16);

        spinDeleteGardenId = new QSpinBox(groupGardenMgmt);
        spinDeleteGardenId->setObjectName("spinDeleteGardenId");
        spinDeleteGardenId->setMinimum(1);
        spinDeleteGardenId->setMaximum(255);

        formLayout3->setWidget(0, QFormLayout::FieldRole, spinDeleteGardenId);

        btnDeleteGarden = new QPushButton(groupGardenMgmt);
        btnDeleteGarden->setObjectName("btnDeleteGarden");

        formLayout3->setWidget(1, QFormLayout::FieldRole, btnDeleteGarden);


        vboxLayout10->addLayout(formLayout3);

        spacerItem2 = new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        vboxLayout10->addItem(spacerItem2);


        hboxLayout5->addWidget(groupGardenMgmt);

        groupDeviceMgmt = new QGroupBox(tabManagement);
        groupDeviceMgmt->setObjectName("groupDeviceMgmt");
        vboxLayout11 = new QVBoxLayout(groupDeviceMgmt);
        vboxLayout11->setObjectName("vboxLayout11");
        formLayout4 = new QFormLayout();
        formLayout4->setObjectName("formLayout4");
        label17 = new QLabel(groupDeviceMgmt);
        label17->setObjectName("label17");

        formLayout4->setWidget(0, QFormLayout::LabelRole, label17);

        spinAddDeviceId = new QSpinBox(groupDeviceMgmt);
        spinAddDeviceId->setObjectName("spinAddDeviceId");
        spinAddDeviceId->setMinimum(1);
        spinAddDeviceId->setMaximum(255);

        formLayout4->setWidget(0, QFormLayout::FieldRole, spinAddDeviceId);

        label18 = new QLabel(groupDeviceMgmt);
        label18->setObjectName("label18");

        formLayout4->setWidget(1, QFormLayout::LabelRole, label18);

        spinAddDeviceGardenId = new QSpinBox(groupDeviceMgmt);
        spinAddDeviceGardenId->setObjectName("spinAddDeviceGardenId");
        spinAddDeviceGardenId->setMinimum(1);
        spinAddDeviceGardenId->setMaximum(255);

        formLayout4->setWidget(1, QFormLayout::FieldRole, spinAddDeviceGardenId);

        label19 = new QLabel(groupDeviceMgmt);
        label19->setObjectName("label19");

        formLayout4->setWidget(2, QFormLayout::LabelRole, label19);

        editAddDeviceAppId = new QLineEdit(groupDeviceMgmt);
        editAddDeviceAppId->setObjectName("editAddDeviceAppId");

        formLayout4->setWidget(2, QFormLayout::FieldRole, editAddDeviceAppId);

        btnAddDevice = new QPushButton(groupDeviceMgmt);
        btnAddDevice->setObjectName("btnAddDevice");

        formLayout4->setWidget(3, QFormLayout::FieldRole, btnAddDevice);


        vboxLayout11->addLayout(formLayout4);

        line1 = new QFrame(groupDeviceMgmt);
        line1->setObjectName("line1");
        line1->setFrameShape(QFrame::HLine);
        line1->setFrameShadow(QFrame::Sunken);

        vboxLayout11->addWidget(line1);

        formLayout5 = new QFormLayout();
        formLayout5->setObjectName("formLayout5");
        label20 = new QLabel(groupDeviceMgmt);
        label20->setObjectName("label20");

        formLayout5->setWidget(0, QFormLayout::LabelRole, label20);

        spinDeleteDeviceId = new QSpinBox(groupDeviceMgmt);
        spinDeleteDeviceId->setObjectName("spinDeleteDeviceId");
        spinDeleteDeviceId->setMinimum(1);
        spinDeleteDeviceId->setMaximum(255);

        formLayout5->setWidget(0, QFormLayout::FieldRole, spinDeleteDeviceId);

        btnDeleteDevice = new QPushButton(groupDeviceMgmt);
        btnDeleteDevice->setObjectName("btnDeleteDevice");

        formLayout5->setWidget(1, QFormLayout::FieldRole, btnDeleteDevice);


        vboxLayout11->addLayout(formLayout5);

        spacerItem3 = new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        vboxLayout11->addItem(spacerItem3);


        hboxLayout5->addWidget(groupDeviceMgmt);

        tabWidget->addTab(tabManagement, QString());
        tabLogs = new QWidget();
        tabLogs->setObjectName("tabLogs");
        vboxLayout12 = new QVBoxLayout(tabLogs);
        vboxLayout12->setObjectName("vboxLayout12");
        groupDataLogs = new QGroupBox(tabLogs);
        groupDataLogs->setObjectName("groupDataLogs");
        vboxLayout13 = new QVBoxLayout(groupDataLogs);
        vboxLayout13->setObjectName("vboxLayout13");
        tableDataLogs = new QTableWidget(groupDataLogs);
        if (tableDataLogs->columnCount() < 1)
            tableDataLogs->setColumnCount(1);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        tableDataLogs->setHorizontalHeaderItem(0, __qtablewidgetitem);
        tableDataLogs->setObjectName("tableDataLogs");
        tableDataLogs->setColumnCount(1);

        vboxLayout13->addWidget(tableDataLogs);

        btnClearDataLogs = new QPushButton(groupDataLogs);
        btnClearDataLogs->setObjectName("btnClearDataLogs");

        vboxLayout13->addWidget(btnClearDataLogs);


        vboxLayout12->addWidget(groupDataLogs);

        groupAlertLogs = new QGroupBox(tabLogs);
        groupAlertLogs->setObjectName("groupAlertLogs");
        vboxLayout14 = new QVBoxLayout(groupAlertLogs);
        vboxLayout14->setObjectName("vboxLayout14");
        tableAlertLogs = new QTableWidget(groupAlertLogs);
        if (tableAlertLogs->columnCount() < 1)
            tableAlertLogs->setColumnCount(1);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        tableAlertLogs->setHorizontalHeaderItem(0, __qtablewidgetitem1);
        tableAlertLogs->setObjectName("tableAlertLogs");
        tableAlertLogs->setColumnCount(1);

        vboxLayout14->addWidget(tableAlertLogs);

        btnClearAlertLogs = new QPushButton(groupAlertLogs);
        btnClearAlertLogs->setObjectName("btnClearAlertLogs");

        vboxLayout14->addWidget(btnClearAlertLogs);


        vboxLayout12->addWidget(groupAlertLogs);

        tabWidget->addTab(tabLogs, QString());
        tabSettings = new QWidget();
        tabSettings->setObjectName("tabSettings");
        vboxLayout15 = new QVBoxLayout(tabSettings);
        vboxLayout15->setObjectName("vboxLayout15");
        hboxLayout6 = new QHBoxLayout();
        hboxLayout6->setObjectName("hboxLayout6");
        label21 = new QLabel(tabSettings);
        label21->setObjectName("label21");

        hboxLayout6->addWidget(label21);

        comboSettingsDevice = new QComboBox(tabSettings);
        comboSettingsDevice->setObjectName("comboSettingsDevice");

        hboxLayout6->addWidget(comboSettingsDevice);


        vboxLayout15->addLayout(hboxLayout6);

        groupSetParameters = new QGroupBox(tabSettings);
        groupSetParameters->setObjectName("groupSetParameters");
        formLayout6 = new QFormLayout(groupSetParameters);
        formLayout6->setObjectName("formLayout6");
        label22 = new QLabel(groupSetParameters);
        label22->setObjectName("label22");

        formLayout6->setWidget(0, QFormLayout::LabelRole, label22);

        spinHmin = new QSpinBox(groupSetParameters);
        spinHmin->setObjectName("spinHmin");
        spinHmin->setMaximum(100);

        formLayout6->setWidget(0, QFormLayout::FieldRole, spinHmin);

        label23 = new QLabel(groupSetParameters);
        label23->setObjectName("label23");

        formLayout6->setWidget(1, QFormLayout::LabelRole, label23);

        spinHmax = new QSpinBox(groupSetParameters);
        spinHmax->setObjectName("spinHmax");
        spinHmax->setMaximum(100);

        formLayout6->setWidget(1, QFormLayout::FieldRole, spinHmax);

        label24 = new QLabel(groupSetParameters);
        label24->setObjectName("label24");

        formLayout6->setWidget(2, QFormLayout::LabelRole, label24);

        spinNmin = new QSpinBox(groupSetParameters);
        spinNmin->setObjectName("spinNmin");
        spinNmin->setMaximum(255);

        formLayout6->setWidget(2, QFormLayout::FieldRole, spinNmin);

        label25 = new QLabel(groupSetParameters);
        label25->setObjectName("label25");

        formLayout6->setWidget(3, QFormLayout::LabelRole, label25);

        spinPmin = new QSpinBox(groupSetParameters);
        spinPmin->setObjectName("spinPmin");
        spinPmin->setMaximum(255);

        formLayout6->setWidget(3, QFormLayout::FieldRole, spinPmin);

        label26 = new QLabel(groupSetParameters);
        label26->setObjectName("label26");

        formLayout6->setWidget(4, QFormLayout::LabelRole, label26);

        spinKmin = new QSpinBox(groupSetParameters);
        spinKmin->setObjectName("spinKmin");
        spinKmin->setMaximum(255);

        formLayout6->setWidget(4, QFormLayout::FieldRole, spinKmin);

        label27 = new QLabel(groupSetParameters);
        label27->setObjectName("label27");

        formLayout6->setWidget(5, QFormLayout::LabelRole, label27);

        spinFertC = new QSpinBox(groupSetParameters);
        spinFertC->setObjectName("spinFertC");
        spinFertC->setMaximum(255);

        formLayout6->setWidget(5, QFormLayout::FieldRole, spinFertC);

        label28 = new QLabel(groupSetParameters);
        label28->setObjectName("label28");

        formLayout6->setWidget(6, QFormLayout::LabelRole, label28);

        spinFertV = new QSpinBox(groupSetParameters);
        spinFertV->setObjectName("spinFertV");
        spinFertV->setMaximum(255);

        formLayout6->setWidget(6, QFormLayout::FieldRole, spinFertV);

        label29 = new QLabel(groupSetParameters);
        label29->setObjectName("label29");

        formLayout6->setWidget(7, QFormLayout::LabelRole, label29);

        spinPower = new QSpinBox(groupSetParameters);
        spinPower->setObjectName("spinPower");
        spinPower->setMaximum(100);

        formLayout6->setWidget(7, QFormLayout::FieldRole, spinPower);

        label30 = new QLabel(groupSetParameters);
        label30->setObjectName("label30");

        formLayout6->setWidget(8, QFormLayout::LabelRole, label30);

        spinInterval = new QSpinBox(groupSetParameters);
        spinInterval->setObjectName("spinInterval");
        spinInterval->setMaximum(255);

        formLayout6->setWidget(8, QFormLayout::FieldRole, spinInterval);

        btnApplyParameters = new QPushButton(groupSetParameters);
        btnApplyParameters->setObjectName("btnApplyParameters");

        formLayout6->setWidget(9, QFormLayout::FieldRole, btnApplyParameters);


        vboxLayout15->addWidget(groupSetParameters);

        groupChangePassword = new QGroupBox(tabSettings);
        groupChangePassword->setObjectName("groupChangePassword");
        formLayout7 = new QFormLayout(groupChangePassword);
        formLayout7->setObjectName("formLayout7");
        label31 = new QLabel(groupChangePassword);
        label31->setObjectName("label31");

        formLayout7->setWidget(0, QFormLayout::LabelRole, label31);

        editPasswordAppId = new QLineEdit(groupChangePassword);
        editPasswordAppId->setObjectName("editPasswordAppId");

        formLayout7->setWidget(0, QFormLayout::FieldRole, editPasswordAppId);

        label32 = new QLabel(groupChangePassword);
        label32->setObjectName("label32");

        formLayout7->setWidget(1, QFormLayout::LabelRole, label32);

        editOldPassword = new QLineEdit(groupChangePassword);
        editOldPassword->setObjectName("editOldPassword");
        editOldPassword->setEchoMode(QLineEdit::Password);

        formLayout7->setWidget(1, QFormLayout::FieldRole, editOldPassword);

        label33 = new QLabel(groupChangePassword);
        label33->setObjectName("label33");

        formLayout7->setWidget(2, QFormLayout::LabelRole, label33);

        editNewPassword = new QLineEdit(groupChangePassword);
        editNewPassword->setObjectName("editNewPassword");
        editNewPassword->setEchoMode(QLineEdit::Password);

        formLayout7->setWidget(2, QFormLayout::FieldRole, editNewPassword);

        btnChangePassword = new QPushButton(groupChangePassword);
        btnChangePassword->setObjectName("btnChangePassword");

        formLayout7->setWidget(3, QFormLayout::FieldRole, btnChangePassword);


        vboxLayout15->addWidget(groupChangePassword);

        btnViewDeviceConfig = new QPushButton(tabSettings);
        btnViewDeviceConfig->setObjectName("btnViewDeviceConfig");

        vboxLayout15->addWidget(btnViewDeviceConfig);

        tabWidget->addTab(tabSettings, QString());

        verticalLayout->addWidget(tabWidget);

        groupPacketViewer = new QGroupBox(centralwidget);
        groupPacketViewer->setObjectName("groupPacketViewer");
        groupPacketViewer->setMaximumHeight(200);
        vboxLayout16 = new QVBoxLayout(groupPacketViewer);
        vboxLayout16->setObjectName("vboxLayout16");
        packetView = new QTextEdit(groupPacketViewer);
        packetView->setObjectName("packetView");
        packetView->setReadOnly(true);
        QFont font;
        font.setFamilies({QString::fromUtf8("Courier New")});
        font.setPointSize(9);
        packetView->setFont(font);

        vboxLayout16->addWidget(packetView);


        verticalLayout->addWidget(groupPacketViewer);

        logView = new QTextEdit(centralwidget);
        logView->setObjectName("logView");
        logView->setReadOnly(true);
        logView->setMaximumHeight(150);

        verticalLayout->addWidget(logView);

        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "IoT Garden Client", nullptr));
        groupConnection->setTitle(QCoreApplication::translate("MainWindow", "Connection", nullptr));
        labelServerIP->setText(QCoreApplication::translate("MainWindow", "Server IP:", nullptr));
        editServerIP->setText(QCoreApplication::translate("MainWindow", "127.0.0.1", nullptr));
        labelUsername->setText(QCoreApplication::translate("MainWindow", "Username:", nullptr));
        labelPassword->setText(QCoreApplication::translate("MainWindow", "Password:", nullptr));
        btnConnectLogin->setText(QCoreApplication::translate("MainWindow", "Connect & Login", nullptr));
        groupDeviceList->setTitle(QCoreApplication::translate("MainWindow", "Devices", nullptr));
        btnRefreshDevices->setText(QCoreApplication::translate("MainWindow", "Refresh", nullptr));
        groupDeviceDetails->setTitle(QCoreApplication::translate("MainWindow", "Device Details", nullptr));
        groupSensorData->setTitle(QCoreApplication::translate("MainWindow", "Sensor Data", nullptr));
        label->setText(QCoreApplication::translate("MainWindow", "Humidity:", nullptr));
        lblHumidity->setText(QCoreApplication::translate("MainWindow", "--", nullptr));
        label1->setText(QCoreApplication::translate("MainWindow", "Nitrogen:", nullptr));
        lblNLevel->setText(QCoreApplication::translate("MainWindow", "--", nullptr));
        label2->setText(QCoreApplication::translate("MainWindow", "Phosphorus:", nullptr));
        lblPLevel->setText(QCoreApplication::translate("MainWindow", "--", nullptr));
        label3->setText(QCoreApplication::translate("MainWindow", "Potassium:", nullptr));
        lblKLevel->setText(QCoreApplication::translate("MainWindow", "--", nullptr));
        groupDirectStatus->setTitle(QCoreApplication::translate("MainWindow", "Direct Control Status", nullptr));
        label4->setText(QCoreApplication::translate("MainWindow", "Pump:", nullptr));
        lblPumpStatus->setText(QCoreApplication::translate("MainWindow", "OFF", nullptr));
        label5->setText(QCoreApplication::translate("MainWindow", "Light:", nullptr));
        lblLightStatus->setText(QCoreApplication::translate("MainWindow", "OFF", nullptr));
        label6->setText(QCoreApplication::translate("MainWindow", "Fertilizer:", nullptr));
        lblFertStatus->setText(QCoreApplication::translate("MainWindow", "OFF", nullptr));
        groupSchedules->setTitle(QCoreApplication::translate("MainWindow", "Schedules", nullptr));
        label7->setText(QCoreApplication::translate("MainWindow", "Pump Times:", nullptr));
        label8->setText(QCoreApplication::translate("MainWindow", "Light Schedule:", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tabMonitoring), QCoreApplication::translate("MainWindow", "Monitoring", nullptr));
        label9->setText(QCoreApplication::translate("MainWindow", "Device:", nullptr));
        groupPumpSchedule->setTitle(QCoreApplication::translate("MainWindow", "Pump Schedule", nullptr));
        timePump->setDisplayFormat(QCoreApplication::translate("MainWindow", "HH:mm", nullptr));
        btnAddPumpTime->setText(QCoreApplication::translate("MainWindow", "Add Time", nullptr));
        btnRemovePumpTime->setText(QCoreApplication::translate("MainWindow", "Remove Time", nullptr));
        btnApplyPumpSchedule->setText(QCoreApplication::translate("MainWindow", "Apply Schedule", nullptr));
        groupLightSchedule->setTitle(QCoreApplication::translate("MainWindow", "Light Schedule", nullptr));
        label10->setText(QCoreApplication::translate("MainWindow", "ON Time:", nullptr));
        timeLightOn->setDisplayFormat(QCoreApplication::translate("MainWindow", "HH:mm", nullptr));
        label11->setText(QCoreApplication::translate("MainWindow", "OFF Time:", nullptr));
        timeLightOff->setDisplayFormat(QCoreApplication::translate("MainWindow", "HH:mm", nullptr));
        btnAddLightPair->setText(QCoreApplication::translate("MainWindow", "Add Pair", nullptr));
        btnRemoveLightPair->setText(QCoreApplication::translate("MainWindow", "Remove Pair", nullptr));
        btnApplyLightSchedule->setText(QCoreApplication::translate("MainWindow", "Apply Schedule", nullptr));
        groupDirectControl->setTitle(QCoreApplication::translate("MainWindow", "Direct Control", nullptr));
        label12->setText(QCoreApplication::translate("MainWindow", "Pump", nullptr));
        btnPumpOn->setText(QCoreApplication::translate("MainWindow", "ON", nullptr));
        btnPumpOff->setText(QCoreApplication::translate("MainWindow", "OFF", nullptr));
        label13->setText(QCoreApplication::translate("MainWindow", "Light", nullptr));
        btnLightOn->setText(QCoreApplication::translate("MainWindow", "ON", nullptr));
        btnLightOff->setText(QCoreApplication::translate("MainWindow", "OFF", nullptr));
        label14->setText(QCoreApplication::translate("MainWindow", "Fertilizer", nullptr));
        btnFertOn->setText(QCoreApplication::translate("MainWindow", "ON", nullptr));
        btnFertOff->setText(QCoreApplication::translate("MainWindow", "OFF", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tabControl), QCoreApplication::translate("MainWindow", "Control", nullptr));
        groupGardenMgmt->setTitle(QCoreApplication::translate("MainWindow", "Garden Management", nullptr));
        label15->setText(QCoreApplication::translate("MainWindow", "Garden ID:", nullptr));
        btnAddGarden->setText(QCoreApplication::translate("MainWindow", "Add Garden", nullptr));
        label16->setText(QCoreApplication::translate("MainWindow", "Garden ID:", nullptr));
        btnDeleteGarden->setText(QCoreApplication::translate("MainWindow", "Delete Garden", nullptr));
        groupDeviceMgmt->setTitle(QCoreApplication::translate("MainWindow", "Device Management", nullptr));
        label17->setText(QCoreApplication::translate("MainWindow", "Device ID:", nullptr));
        label18->setText(QCoreApplication::translate("MainWindow", "Garden ID:", nullptr));
        label19->setText(QCoreApplication::translate("MainWindow", "App ID:", nullptr));
        btnAddDevice->setText(QCoreApplication::translate("MainWindow", "Add Device", nullptr));
        label20->setText(QCoreApplication::translate("MainWindow", "Device ID:", nullptr));
        btnDeleteDevice->setText(QCoreApplication::translate("MainWindow", "Delete Device", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tabManagement), QCoreApplication::translate("MainWindow", "Management", nullptr));
        groupDataLogs->setTitle(QCoreApplication::translate("MainWindow", "Data Logs", nullptr));
        QTableWidgetItem *___qtablewidgetitem = tableDataLogs->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QCoreApplication::translate("MainWindow", "Log Entry", nullptr));
        btnClearDataLogs->setText(QCoreApplication::translate("MainWindow", "Clear", nullptr));
        groupAlertLogs->setTitle(QCoreApplication::translate("MainWindow", "Alert Logs", nullptr));
        QTableWidgetItem *___qtablewidgetitem1 = tableAlertLogs->horizontalHeaderItem(0);
        ___qtablewidgetitem1->setText(QCoreApplication::translate("MainWindow", "Log Entry", nullptr));
        btnClearAlertLogs->setText(QCoreApplication::translate("MainWindow", "Clear", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tabLogs), QCoreApplication::translate("MainWindow", "Logs", nullptr));
        label21->setText(QCoreApplication::translate("MainWindow", "Device:", nullptr));
        groupSetParameters->setTitle(QCoreApplication::translate("MainWindow", "Device Parameters", nullptr));
        label22->setText(QCoreApplication::translate("MainWindow", "Humidity Min:", nullptr));
        label23->setText(QCoreApplication::translate("MainWindow", "Humidity Max:", nullptr));
        label24->setText(QCoreApplication::translate("MainWindow", "N Min:", nullptr));
        label25->setText(QCoreApplication::translate("MainWindow", "P Min:", nullptr));
        label26->setText(QCoreApplication::translate("MainWindow", "K Min:", nullptr));
        label27->setText(QCoreApplication::translate("MainWindow", "Fert Concentration:", nullptr));
        label28->setText(QCoreApplication::translate("MainWindow", "Fert Volume:", nullptr));
        label29->setText(QCoreApplication::translate("MainWindow", "Power:", nullptr));
        label30->setText(QCoreApplication::translate("MainWindow", "Interval (min):", nullptr));
        btnApplyParameters->setText(QCoreApplication::translate("MainWindow", "Apply Parameters", nullptr));
        groupChangePassword->setTitle(QCoreApplication::translate("MainWindow", "Change Password", nullptr));
        label31->setText(QCoreApplication::translate("MainWindow", "App ID:", nullptr));
        label32->setText(QCoreApplication::translate("MainWindow", "Old Password:", nullptr));
        label33->setText(QCoreApplication::translate("MainWindow", "New Password:", nullptr));
        btnChangePassword->setText(QCoreApplication::translate("MainWindow", "Change Password", nullptr));
        btnViewDeviceConfig->setText(QCoreApplication::translate("MainWindow", "View Device Config", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tabSettings), QCoreApplication::translate("MainWindow", "Settings", nullptr));
        groupPacketViewer->setTitle(QCoreApplication::translate("MainWindow", "Packet Viewer (Debug)", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
