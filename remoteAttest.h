#ifndef NAMESPACE_REMOTEATTEST
#define NAMESPACE_REMOTEATTEST
#include <ESPAsyncWebServer.h>
#include "esp_hmac.h"
#include "esp_partition.h"

namespace remoteAttest {
    void calculate_full_rom_hmac(uint8_t *final_hmac);
    void handleChallenge(AsyncWebServerRequest *request, const uint8_t *final_hmac);
    void setup_remoteAttest(void *pvParameters);
}

#endif