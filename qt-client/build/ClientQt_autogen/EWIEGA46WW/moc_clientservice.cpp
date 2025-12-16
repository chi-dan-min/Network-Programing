/****************************************************************************
** Meta object code from reading C++ file 'clientservice.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../clientservice.h"
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'clientservice.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.4.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
namespace {
struct qt_meta_stringdata_RecvThread_t {
    uint offsetsAndSizes[22];
    char stringdata0[11];
    char stringdata1[13];
    char stringdata2[1];
    char stringdata3[8];
    char stringdata4[7];
    char stringdata5[13];
    char stringdata6[5];
    char stringdata7[14];
    char stringdata8[6];
    char stringdata9[6];
    char stringdata10[15];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_RecvThread_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_RecvThread_t qt_meta_stringdata_RecvThread = {
    {
        QT_MOC_LITERAL(0, 10),  // "RecvThread"
        QT_MOC_LITERAL(11, 12),  // "dataReceived"
        QT_MOC_LITERAL(24, 0),  // ""
        QT_MOC_LITERAL(25, 7),  // "uint8_t"
        QT_MOC_LITERAL(33, 6),  // "dev_id"
        QT_MOC_LITERAL(40, 12),  // "IntervalData"
        QT_MOC_LITERAL(53, 4),  // "data"
        QT_MOC_LITERAL(58, 13),  // "alertReceived"
        QT_MOC_LITERAL(72, 5),  // "Alert"
        QT_MOC_LITERAL(78, 5),  // "alert"
        QT_MOC_LITERAL(84, 14)   // "connectionLost"
    },
    "RecvThread",
    "dataReceived",
    "",
    "uint8_t",
    "dev_id",
    "IntervalData",
    "data",
    "alertReceived",
    "Alert",
    "alert",
    "connectionLost"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_RecvThread[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    2,   32,    2, 0x06,    1 /* Public */,
       7,    2,   37,    2, 0x06,    4 /* Public */,
      10,    0,   42,    2, 0x06,    7 /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3, 0x80000000 | 5,    4,    6,
    QMetaType::Void, 0x80000000 | 3, 0x80000000 | 8,    4,    9,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject RecvThread::staticMetaObject = { {
    QMetaObject::SuperData::link<QThread::staticMetaObject>(),
    qt_meta_stringdata_RecvThread.offsetsAndSizes,
    qt_meta_data_RecvThread,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_RecvThread_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<RecvThread, std::true_type>,
        // method 'dataReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        QtPrivate::TypeAndForceComplete<IntervalData, std::false_type>,
        // method 'alertReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        QtPrivate::TypeAndForceComplete<Alert, std::false_type>,
        // method 'connectionLost'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void RecvThread::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<RecvThread *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->dataReceived((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<IntervalData>>(_a[2]))); break;
        case 1: _t->alertReceived((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<Alert>>(_a[2]))); break;
        case 2: _t->connectionLost(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (RecvThread::*)(uint8_t , IntervalData );
            if (_t _q_method = &RecvThread::dataReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (RecvThread::*)(uint8_t , Alert );
            if (_t _q_method = &RecvThread::alertReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (RecvThread::*)();
            if (_t _q_method = &RecvThread::connectionLost; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
    }
}

const QMetaObject *RecvThread::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *RecvThread::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_RecvThread.stringdata0))
        return static_cast<void*>(this);
    return QThread::qt_metacast(_clname);
}

int RecvThread::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QThread::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void RecvThread::dataReceived(uint8_t _t1, IntervalData _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void RecvThread::alertReceived(uint8_t _t1, Alert _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void RecvThread::connectionLost()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}
namespace {
struct qt_meta_stringdata_ClientService_t {
    uint offsetsAndSizes[60];
    char stringdata0[14];
    char stringdata1[11];
    char stringdata2[1];
    char stringdata3[4];
    char stringdata4[13];
    char stringdata5[10];
    char stringdata6[13];
    char stringdata7[13];
    char stringdata8[9];
    char stringdata9[6];
    char stringdata10[15];
    char stringdata11[15];
    char stringdata12[18];
    char stringdata13[8];
    char stringdata14[7];
    char stringdata15[20];
    char stringdata16[6];
    char stringdata17[21];
    char stringdata18[17];
    char stringdata19[9];
    char stringdata20[11];
    char stringdata21[10];
    char stringdata22[5];
    char stringdata23[15];
    char stringdata24[7];
    char stringdata25[15];
    char stringdata26[13];
    char stringdata27[16];
    char stringdata28[6];
    char stringdata29[17];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_ClientService_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_ClientService_t qt_meta_stringdata_ClientService = {
    {
        QT_MOC_LITERAL(0, 13),  // "ClientService"
        QT_MOC_LITERAL(14, 10),  // "logMessage"
        QT_MOC_LITERAL(25, 0),  // ""
        QT_MOC_LITERAL(26, 3),  // "msg"
        QT_MOC_LITERAL(30, 12),  // "errorMessage"
        QT_MOC_LITERAL(43, 9),  // "connected"
        QT_MOC_LITERAL(53, 12),  // "disconnected"
        QT_MOC_LITERAL(66, 12),  // "loginSuccess"
        QT_MOC_LITERAL(79, 8),  // "uint32_t"
        QT_MOC_LITERAL(88, 5),  // "token"
        QT_MOC_LITERAL(94, 14),  // "devicesUpdated"
        QT_MOC_LITERAL(109, 14),  // "gardensUpdated"
        QT_MOC_LITERAL(124, 17),  // "deviceDataUpdated"
        QT_MOC_LITERAL(142, 7),  // "uint8_t"
        QT_MOC_LITERAL(150, 6),  // "dev_id"
        QT_MOC_LITERAL(157, 19),  // "deviceAlertReceived"
        QT_MOC_LITERAL(177, 5),  // "alert"
        QT_MOC_LITERAL(183, 20),  // "deviceParamsReceived"
        QT_MOC_LITERAL(204, 16),  // "SettingsResponse"
        QT_MOC_LITERAL(221, 8),  // "settings"
        QT_MOC_LITERAL(230, 10),  // "packetData"
        QT_MOC_LITERAL(241, 9),  // "direction"
        QT_MOC_LITERAL(251, 4),  // "data"
        QT_MOC_LITERAL(256, 14),  // "scanInfoResult"
        QT_MOC_LITERAL(271, 6),  // "result"
        QT_MOC_LITERAL(278, 14),  // "onDataReceived"
        QT_MOC_LITERAL(293, 12),  // "IntervalData"
        QT_MOC_LITERAL(306, 15),  // "onAlertReceived"
        QT_MOC_LITERAL(322, 5),  // "Alert"
        QT_MOC_LITERAL(328, 16)   // "onConnectionLost"
    },
    "ClientService",
    "logMessage",
    "",
    "msg",
    "errorMessage",
    "connected",
    "disconnected",
    "loginSuccess",
    "uint32_t",
    "token",
    "devicesUpdated",
    "gardensUpdated",
    "deviceDataUpdated",
    "uint8_t",
    "dev_id",
    "deviceAlertReceived",
    "alert",
    "deviceParamsReceived",
    "SettingsResponse",
    "settings",
    "packetData",
    "direction",
    "data",
    "scanInfoResult",
    "result",
    "onDataReceived",
    "IntervalData",
    "onAlertReceived",
    "Alert",
    "onConnectionLost"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_ClientService[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
      15,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      12,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,  104,    2, 0x06,    1 /* Public */,
       4,    1,  107,    2, 0x06,    3 /* Public */,
       5,    0,  110,    2, 0x06,    5 /* Public */,
       6,    0,  111,    2, 0x06,    6 /* Public */,
       7,    1,  112,    2, 0x06,    7 /* Public */,
      10,    0,  115,    2, 0x06,    9 /* Public */,
      11,    0,  116,    2, 0x06,   10 /* Public */,
      12,    1,  117,    2, 0x06,   11 /* Public */,
      15,    2,  120,    2, 0x06,   13 /* Public */,
      17,    2,  125,    2, 0x06,   16 /* Public */,
      20,    2,  130,    2, 0x06,   19 /* Public */,
      23,    1,  135,    2, 0x06,   22 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      25,    2,  138,    2, 0x08,   24 /* Private */,
      27,    2,  143,    2, 0x08,   27 /* Private */,
      29,    0,  148,    2, 0x08,   30 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 8,    9,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 13,   14,
    QMetaType::Void, 0x80000000 | 13, QMetaType::QString,   14,   16,
    QMetaType::Void, 0x80000000 | 13, 0x80000000 | 18,   14,   19,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   21,   22,
    QMetaType::Void, QMetaType::QString,   24,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 13, 0x80000000 | 26,   14,   22,
    QMetaType::Void, 0x80000000 | 13, 0x80000000 | 28,   14,   16,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject ClientService::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_ClientService.offsetsAndSizes,
    qt_meta_data_ClientService,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_ClientService_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ClientService, std::true_type>,
        // method 'logMessage'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'errorMessage'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'connected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'disconnected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'loginSuccess'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint32_t, std::false_type>,
        // method 'devicesUpdated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'gardensUpdated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'deviceDataUpdated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        // method 'deviceAlertReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'deviceParamsReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        QtPrivate::TypeAndForceComplete<SettingsResponse, std::false_type>,
        // method 'packetData'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'scanInfoResult'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'onDataReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        QtPrivate::TypeAndForceComplete<IntervalData, std::false_type>,
        // method 'onAlertReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<uint8_t, std::false_type>,
        QtPrivate::TypeAndForceComplete<Alert, std::false_type>,
        // method 'onConnectionLost'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void ClientService::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ClientService *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->logMessage((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 1: _t->errorMessage((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 2: _t->connected(); break;
        case 3: _t->disconnected(); break;
        case 4: _t->loginSuccess((*reinterpret_cast< std::add_pointer_t<uint32_t>>(_a[1]))); break;
        case 5: _t->devicesUpdated(); break;
        case 6: _t->gardensUpdated(); break;
        case 7: _t->deviceDataUpdated((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1]))); break;
        case 8: _t->deviceAlertReceived((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 9: _t->deviceParamsReceived((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<SettingsResponse>>(_a[2]))); break;
        case 10: _t->packetData((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 11: _t->scanInfoResult((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 12: _t->onDataReceived((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<IntervalData>>(_a[2]))); break;
        case 13: _t->onAlertReceived((*reinterpret_cast< std::add_pointer_t<uint8_t>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<Alert>>(_a[2]))); break;
        case 14: _t->onConnectionLost(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ClientService::*)(QString );
            if (_t _q_method = &ClientService::logMessage; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(QString );
            if (_t _q_method = &ClientService::errorMessage; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (ClientService::*)();
            if (_t _q_method = &ClientService::connected; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (ClientService::*)();
            if (_t _q_method = &ClientService::disconnected; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(uint32_t );
            if (_t _q_method = &ClientService::loginSuccess; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (ClientService::*)();
            if (_t _q_method = &ClientService::devicesUpdated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (ClientService::*)();
            if (_t _q_method = &ClientService::gardensUpdated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(uint8_t );
            if (_t _q_method = &ClientService::deviceDataUpdated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(uint8_t , QString );
            if (_t _q_method = &ClientService::deviceAlertReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(uint8_t , SettingsResponse );
            if (_t _q_method = &ClientService::deviceParamsReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 9;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(QString , QString );
            if (_t _q_method = &ClientService::packetData; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 10;
                return;
            }
        }
        {
            using _t = void (ClientService::*)(QString );
            if (_t _q_method = &ClientService::scanInfoResult; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 11;
                return;
            }
        }
    }
}

const QMetaObject *ClientService::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ClientService::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ClientService.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int ClientService::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 15)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 15;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 15)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 15;
    }
    return _id;
}

// SIGNAL 0
void ClientService::logMessage(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void ClientService::errorMessage(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void ClientService::connected()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void ClientService::disconnected()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void ClientService::loginSuccess(uint32_t _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void ClientService::devicesUpdated()
{
    QMetaObject::activate(this, &staticMetaObject, 5, nullptr);
}

// SIGNAL 6
void ClientService::gardensUpdated()
{
    QMetaObject::activate(this, &staticMetaObject, 6, nullptr);
}

// SIGNAL 7
void ClientService::deviceDataUpdated(uint8_t _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 7, _a);
}

// SIGNAL 8
void ClientService::deviceAlertReceived(uint8_t _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}

// SIGNAL 9
void ClientService::deviceParamsReceived(uint8_t _t1, SettingsResponse _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 9, _a);
}

// SIGNAL 10
void ClientService::packetData(QString _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 10, _a);
}

// SIGNAL 11
void ClientService::scanInfoResult(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 11, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
