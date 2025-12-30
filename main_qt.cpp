#include <QApplication>
#include "MainWindow.h"
#include "myClient.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    // Instantiate Backend
    ClientManager& client = ClientManager::instance();
    
    // Optional: Auto-connect if args provided
    if (argc == 2) {
        client.connectToServer(argv[1]);
    } else {
        // Default prompt or hardcode?
        // Let GUI handle connection.
    }

    MainWindow window;
    window.show();

    return app.exec();
}
