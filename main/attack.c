/**
 * @file attack.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-02
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements common attack wrapper.
 */

#include "attack.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"

#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_dos.h"
#include "webserver.h"
#include "wifi_controller.h"

static const char* TAG = "attack";
static attack_status_t attack_status = { .state = READY, .type = -1, .content_size = 0, .content = NULL };
static esp_timer_handle_t attack_timeout_handle;

const attack_status_t *attack_get_status() {
    return &attack_status;
}

void attack_update_status(attack_state_t state) {
    attack_status.state = state;
    if(state == FINISHED) {
        ESP_LOGD(TAG, "Stopping attack timeout timer");
        ESP_ERROR_CHECK(esp_timer_stop(attack_timeout_handle));
    } 
}

void attack_append_status_content(uint8_t *buffer, unsigned size){
    if(size == 0){
        ESP_LOGE(TAG, "Size can't be 0 if you want to reallocate");
        return;
    }
    // temporarily save new location in case of realloc failure to preserve current content
    char *reallocated_content = realloc(attack_status.content, attack_status.content_size + size);
    if(reallocated_content == NULL){
        ESP_LOGE(TAG, "Error reallocating status content! Status content may not be complete.");
        return;
    }
    // copy new data after current content
    memcpy(&reallocated_content[attack_status.content_size], buffer, size);
    attack_status.content = reallocated_content;
    attack_status.content_size += size;
}

char *attack_alloc_result_content(unsigned size) {
    attack_status.content_size = size;
    attack_status.content = (char *) malloc(size);
    return attack_status.content;
}

/**
 * @brief Callback function for attack timeout timer.
 * 
 * This function is called when attack times out. 
 * It updates attack status state to TIMEOUT.
 * It calls appropriate abort functions based on current attack type.
 * @param arg not used.
 */
static void attack_timeout(void* arg){
    ESP_LOGD(TAG, "Attack timed out");
    
    attack_update_status(TIMEOUT);

    switch(attack_status.type) {
        case ATTACK_TYPE_PMKID:
            ESP_LOGI(TAG, "Aborting PMKID attack...");
            attack_pmkid_stop();
            break;
        case ATTACK_TYPE_HANDSHAKE:
            ESP_LOGI(TAG, "Abort HANDSHAKE attack...");
            attack_handshake_stop();
            break;
        case ATTACK_TYPE_PASSIVE:
            ESP_LOGI(TAG, "Abort PASSIVE attack...");
            break;
        case ATTACK_TYPE_DOS:
            ESP_LOGI(TAG, "Abort DOS attack...");
            attack_dos_stop();
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack type. Not aborting anything");
    }
}

void log_attack_request(const attack_request_t *request) {
    if (!request) {
        ESP_LOGI(TAG, "attack_request_t is NULL");
        return;
    }

    //ESP_LOGI(TAG, "Raw Request Data:");
    //ESP_LOG_BUFFER_HEX(TAG, (const void*)request, sizeof(attack_request_t));

    //ESP_LOGI(TAG, "===== Attack Request =====");
    //ESP_LOGI(TAG, "Number of APs: %d", request->num_aps);
    //ESP_LOGI(TAG, "Attack Type: %d", request->type);
    //ESP_LOGI(TAG, "Attack Method: %d", request->method);
    //ESP_LOGI(TAG, "Timeout: %d seconds", request->timeout);

    // if (request->num_aps > 0) {
    //     ESP_LOGI(TAG, "AP IDs:");
    //     for (uint8_t i = 0; i < request->num_aps; i++) {
    //         ESP_LOGI(TAG, "  AP ID[%d]: %d", i, request->ap_ids[i]);
    //     }
    // } else {
    //     ESP_LOGI(TAG, "AP IDs: NULL or empty");
    // }
}

void log_attack_config(const attack_config_t *config) {
    if (!config) {
        ESP_LOGI(TAG, "log_attack_config attack_config_t is NULL");
        return;
    }

    ESP_LOGI(TAG, "===== Attack Config =====");
    ESP_LOGI(TAG, "Attack Type: %d", config->type);
    ESP_LOGI(TAG, "Attack Method: %d", config->method);
    ESP_LOGI(TAG, "Timeout: %d seconds", config->timeout);
    ESP_LOGI(TAG, "Actual Amount of AP Records: %d", config->actualAmount);

    // Logowanie poszczególnych rekordów AP
    for (uint16_t i = 0; i < config->actualAmount && i < 10; i++) {
        ESP_LOGI(TAG, "AP Record [%d]", i);
        ESP_LOGI(TAG, "SSID: %s", config->ap_records[i].ssid);
    }
}


/**
 * @brief Callback for WEBSERVER_EVENT_ATTACK_REQUEST event.
 * 
 * This function handles WEBSERVER_EVENT_ATTACK_REQUEST event from event loop.
 * It parses attack_request_t structure and set initial values to attack_status.
 * It sets attack state to RUNNING.
 * It starts attack timeout timer.
 * It starts attack based on chosen type.
 * 
 * @param args not used
 * @param event_base expects WEBSERVER_EVENTS
 * @param event_id expects WEBSERVER_EVENT_ATTACK_REQUEST
 * @param event_data expects attack_request_t
 */
static void attack_request_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {

    ESP_LOGI(TAG, "Starting attack...");

    ESP_LOGI(TAG, "Raw Event Data:");
    ESP_LOG_BUFFER_HEX(TAG, event_data, sizeof(attack_request_t));


    attack_request_t *attack_request = (attack_request_t *) event_data;
   
    ESP_LOGI("ATTACK_REQ", "Received attack request:");
    ESP_LOGI("ATTACK_REQ", "Type: %u", attack_request->type);
    ESP_LOGI("ATTACK_REQ", "Method: %u", attack_request->method);
    ESP_LOGI("ATTACK_REQ", "Timeout: %u sec", attack_request->timeout);
    ESP_LOGI("ATTACK_REQ", "Number of selected APs: %u", attack_request->num_aps);
    char ap_ids_str[64] = {0};
    char *ptr = ap_ids_str;
    for (int i = 0; i < attack_request->num_aps && i < 10; i++) {
        ptr += snprintf(ptr, sizeof(ap_ids_str) - (ptr - ap_ids_str), "%u ", attack_request->ap_ids[i]);
    }
    ESP_LOGI("ATTACK_REQ", "AP IDs: %s", ap_ids_str);
    ESP_LOGI("ATTACK_REQ", "Evil AP Name: \"%.*s\"", 32, attack_request->evil_ap_name);

    attack_config_t attack_config = { .type = attack_request->type, .method = attack_request->method, .timeout = attack_request->timeout };
    attack_config.actualAmount = attack_request->num_aps;
    attack_config.evil_ap_name[0] = '\0'; // Initialize evil_ap_name to empty string
    if (attack_request->evil_ap_name[0] != '\0') {
        strncpy(attack_config.evil_ap_name, (char *) attack_request->evil_ap_name, sizeof(attack_config.evil_ap_name) - 1);
        attack_config.evil_ap_name[sizeof(attack_config.evil_ap_name) - 1] = '\0'; // Ensure null termination
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    for (int i = 0; i < attack_request->num_aps; i++) {
        wifi_ap_record_t *ap_record = wifictl_get_ap_record(attack_request->ap_ids[i]);
        if (ap_record) {
            attack_config.ap_records[i] = *ap_record;
            //ESP_LOGI(TAG, "Stored AP Record [%d]: SSID: %s, RSSI: %d", i, ap_record->ssid, ap_record->rssi);
        } else {
            ESP_LOGE(TAG, "wifictl_get_ap_record() returned NULL for AP ID %d", attack_request->ap_ids[i]);
        }
    }

    log_attack_config (&attack_config);

    attack_status.state = RUNNING;
    attack_status.type = attack_config.type;
    
    // start attack based on it's type
    switch(attack_config.type) {
        case ATTACK_TYPE_PMKID:
            attack_pmkid_start(&attack_config);
            break;
        case ATTACK_TYPE_HANDSHAKE:
            attack_handshake_start(&attack_config);
            break;
        case ATTACK_TYPE_PASSIVE:
            ESP_LOGW(TAG, "ATTACK_TYPE_PASSIVE not implemented yet!");
            break;
        case ATTACK_TYPE_DOS:
            attack_dos_start(&attack_config);
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack type!");
    }

}

/**
 * @brief Callback for WEBSERVER_EVENT_ATTACK_RESET event.
 * 
 * This callback resets attack status by freeing previously allocated status content and putting attack to READY state.
 * 
 * @param args not used
 * @param event_base expects WEBSERVER_EVENTS
 * @param event_id expects WEBSERVER_EVENT_ATTACK_RESET
 * @param event_data not used
 */
static void attack_reset_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Resetting attack status...");
    if(attack_status.content){
        free(attack_status.content);
        attack_status.content = NULL;
    }
    attack_status.content_size = 0;
    attack_status.type = -1;
    attack_status.state = READY;
}

/**
 * @brief Initialises common attack resources.
 * 
 * Creates attack timeout timer.
 * Registers event loop event handlers.
 */
void attack_init(){
    const esp_timer_create_args_t attack_timeout_args = {
        .callback = &attack_timeout
    };
    ESP_ERROR_CHECK(esp_timer_create(&attack_timeout_args, &attack_timeout_handle));

    ESP_ERROR_CHECK(esp_event_handler_register(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST, &attack_request_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, &attack_reset_handler, NULL));
}