# Network-Programing

Câu lệnh cài đặt thư viện giao diện:

```bash
sudo apt update
sudo apt install qt6-base-dev qt6-tools-dev cmake build-essential
sudo apt install qtcreator
```

Chỉnh sửa giao diện: trong thư mục qt-client gõ:

```bash
qtcreator mainwindow.ui
```

Nếu chưa build:

```bash
cd qt-client
mkdir build
cd build
cmake ..
make
```

Khởi chạy:
./clientQt
