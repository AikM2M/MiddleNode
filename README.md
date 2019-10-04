# MiddleNode
Middle Node includes the following Common Service Functions (CSFs) in accordance with OneM2M
- Security Association and Establishment (SAE)
	- Certificate Based
	- Pre-Shared Key Based
- Device Registration
- Secure MQTT Binding
- Container and Content Instance Resource Management
- Subscription and Notification
- Data Management and Repository
- Device Management
- Access Control Policies (Authorization)

### Prerequisites

Run following command to install sqlite3 DB

```
$ sudo apt-get install libsqlite3-dev
```

Run the following command to install CMake package for Debian based system  
```
$ sudo apt-get install build-essential gcc make cmake cmake-gui cmake-curses-gui
```

Install OpenSSL library package using the following command
```
$ sudo apt-get install libssl-dev
```

Run following command to install PAHO MQTT Client
```
$ git clone https://github.com/eclipse/paho.mqtt.c.git
$ cd paho.mqtt.c
$ git checkout v1.2.1
$ cmake -Bbuild -H. -DPAHO_WITH_SSL=ON
$ sudo cmake --build build/ --target install
$ sudo ldconfig
```


### Configuration

Before Installation, configure the project to run using one of the following protocols

* TCP
* TLS over TCP using Certificate
* TLS over TCP using Pre-Shared key

This can be done by commenting or uncommenting the macros defined in config.h file 

* uncomment #define TLS for using TLS/TCP
* uncomment #define TLS_PSK or #define TLS_CERT for using PSK or Certificates during TLS Handshake

To connect with MQTT Broker change the ADDRESS macro to the URL of the MQTT Broker. 
 

### Instalation

Build and run the program in current directory using following commands 

```
$ cd MiddleNode
$ cmake .
$ make
$ ./MiddleNode
``` 

### System Architechture

![Alt text](SystemArchitechture.jpg?raw=true "System Architechture")

## Authors

* **Muhammad Ahsan** - *Initial work* - [mahsan321](https://github.com/mahsan321)

## oneM2M Project Funding Agency
- National Centre for Cyber Security (NCCS) HEC Gov. Pakistan
## oneM2M Team 
- Internet of Things Research & Innovation Lab (IRIL) KICS UET Lahore, Pakistan
## Team Members
- Dr. Ghalib A. Shah (Principal Investigator)
- Dr. Ali Hammad Akbar (Co-Principal Investigator)
- Bilal Afzal (Previous Team Leader)
- Muhammad Ahsan (Team Leader)
- Bilal Imran (Sr. Research Officer)
- Muhammad Rehan (Research Officer)
- Asim Tanwir (Research Officer)
