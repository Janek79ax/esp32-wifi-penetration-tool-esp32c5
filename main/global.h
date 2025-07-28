#ifndef GLOBAL_H
#define GLOBAL_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/i2c.h"

#define MAX_STRINGS 10

#define I2C_MASTER_NUM              I2C_NUM_0         // I2C port number
#define I2C_MASTER_SDA_IO           26                // SDA pin
#define I2C_MASTER_SCL_IO           25                // SCL pin
#define I2C_MASTER_FREQ_HZ          100000            // I2C clock frequency
#define I2C_MASTER_TX_BUF_DISABLE   0
#define I2C_MASTER_RX_BUF_DISABLE   0
#define I2C_SLAVE_ADDR              0x08              // Slave address





//properties for GUI task
extern char *globalData[MAX_STRINGS];
extern int globalDataCount;
extern int framesPerSecond;

//properties for slave evil twin i2c communication:


enum ApplicationState {
    DEAUTH,
    DEAUTH_EVIL_TWIN,
    EVIL_TWIN_PASS_CHECK,
    IDLE,
    DRAGON_DRAIN,
    SAE_OVERFLOW
};


enum ApplicationState applicationState = IDLE;
char * evilTwinSSID;
char * evilTwinVerifiedPassword;

//used during password verification phase
int passwordStatus;

#endif // GLOBAL_H
