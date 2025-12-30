#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QLabel>
#include <QScrollArea>
#include <QGridLayout>
#include <QChartView>
#include <QLineSeries>
#include <QChart>
#include "myClient.h"

class QLineEdit;
class QPushButton;
class QTextEdit;
class QComboBox;
class QSpinBox;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;
class QTableWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onConnectClicked();
    void onLoginClicked();
    void onLogoutClicked();
    void onChangePasswordClicked(); 
    void onScanClicked();
    void onInfoClicked();
    void onAddGardenClicked();

    // Inline Device Actions
    void onDevSettingsClick(int gardenId, int devId);
    void onDevScheduleClick(int devId); 
    void onDevPumpClick(int devId, bool checked);
    void onDevLightClick(int devId, bool checked);
    void onDevFertClick(int devId, bool checked); 
    void onDevDeleteClick(int gardenId, int devId);
    void onDevLogsClick(int devId); 
    void onGardenDeleteClick(int gardenId); 
    void onGardenAddDeviceClick(int gardenId);
private:
    void setupUi();
    void updateStatus(const QString &msg);

    // Context
    ClientManager& client;
    QTimer* logTimer;

    // UI Elements
    QLineEdit* ipEdit;
    QPushButton* connectBtn;
    
    QLineEdit* userEdit;
    QLineEdit* passEdit;
    QPushButton* loginBtn;
    QPushButton* logoutBtn;
    
    QLabel* tokenLabel; // New
    
    // QTabWidget* tabs; // Removed
    
    // Dashboard (New)
    QScrollArea* dashboardScroll;
    QWidget* dashboardContainer;
    QGridLayout* dashboardGrid; // Grid for Garden Cards
    QPushButton* scanBtn;
    QPushButton* infoBtn;
    QPushButton* addGardenBtn;
    
    // Logs (New)
    // Charts and Table moved to local dialog
    
    QLabel* statusLabel;

    // Helpers
    void createGardenCard(const GardenInfo& g, int row, int col);
    QWidget* createDeviceRow(int gId, const DeviceInfo& dev);
    void setupChart();
};
#endif // MAINWINDOW_H
