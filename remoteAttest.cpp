#include <Arduino.h>
#include "remoteAttest.h"
#include "esp_task_wdt.h"
#define CHUNK_SIZE 4096

namespace remoteAttest {
    // Function to calculate the full ROM HMAC
    void calculate_full_rom_hmac(AsyncWebServerRequest *request, uint8_t *final_hmac) {
        esp_task_wdt_delete(NULL);  
        uint32_t flash_size;
        esp_flash_get_size(NULL, &flash_size);

        Serial.printf("Calculating HMAC for entire ROM (flash size: %u bytes)...\n", flash_size);

        uint8_t *chunk_buffer = (uint8_t *)malloc(CHUNK_SIZE);
        if (!chunk_buffer) {
            Serial.println("Failed to allocate memory for chunk buffer!");
            return;
        }

        uint8_t intermediate_hash[32] = {0};
        // TODO: Accept further http get parameters to configure the ranges to calculate the hash
        size_t offset = 65536; //0x00010000
        size_t remaining = flash_size-offset;
        esp_err_t err = ESP_OK;
        size_t challenge_len = NULL;
        uint8_t challenge_bytes[challenge_len];
        if (request->hasParam("challenge")) {
            String challenge = request->getParam("challenge")->value();
            Serial.printf("Received challenge: %s\n", challenge.c_str());

            // Convert challenge to bytes
            challenge_len = challenge.length();
            memcpy(challenge_bytes, challenge.c_str(), challenge_len);
          while (remaining > 0) {
            size_t read_size = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
            err = esp_flash_read(NULL, chunk_buffer, offset, read_size);
            if (err != ESP_OK) {
                Serial.printf("Failed to read flash chunk at offset 0x%X. Error: %s\n", offset, esp_err_to_name(err));
                break;
            }

            uint8_t combined_buffer[sizeof(intermediate_hash) + CHUNK_SIZE + challenge_len];
            memcpy(combined_buffer, intermediate_hash, sizeof(intermediate_hash));
            memcpy(combined_buffer + sizeof(intermediate_hash), chunk_buffer, read_size);
            memcpy(combined_buffer + sizeof(intermediate_hash) + CHUNK_SIZE, challenge_bytes, challenge_len);

            err = esp_hmac_calculate(HMAC_KEY3, combined_buffer, sizeof(intermediate_hash) + read_size + challenge_len, final_hmac);
            if (err != ESP_OK) {
                Serial.printf("Failed to calculate HMAC for chunk at offset 0x%X. Error: %s\n", offset, esp_err_to_name(err));
                break;
            }

            memcpy(intermediate_hash, final_hmac, sizeof(intermediate_hash));
            remaining -= read_size;
            offset += read_size;

            //Serial.println("Partial HMAC block:");
            //for (int i = 0; i < 32; i++) {
            //    Serial.printf("%02x", final_hmac[i]);
            //}
          }

          free(chunk_buffer);
          if (err == ESP_OK) {
                Serial.println("Final concatenated HMAC calculated successfully for the entire ROM:");
                for (int i = 0; i < 32; i++) {
                    Serial.printf("%02x", final_hmac[i]);
                }
                Serial.println();
          } else {
                Serial.println("Failed to calculate HMAC for the entire ROM.");
          }

          String response;
          for (int i = 0; i < 32; i++) {
              char hex[3];
              sprintf(hex, "%02x", final_hmac[i]);
              response += hex;
          }
          request->send(200, "text/plain", response);
        } else {
          request->send(400, "text/plain", "Missing 'challenge' parameter");
        }
    }

    // Function to handle HTTP GET requests
    void handleChallenge(AsyncWebServerRequest *request, const uint8_t *final_hmac) {
        if (request->hasParam("challenge")) {
            String challenge = request->getParam("challenge")->value();
            Serial.printf("Received challenge: %s\n", challenge.c_str());

            // Convert challenge to bytes
            size_t challenge_len = challenge.length();
            uint8_t challenge_bytes[challenge_len];
            memcpy(challenge_bytes, challenge.c_str(), challenge_len);

            // Combine final HMAC and challenge
            uint8_t combined_data[32 + challenge_len];
            memcpy(combined_data, final_hmac, 32);
            memcpy(combined_data + 32, challenge_bytes, challenge_len);

            // Calculate HMAC for the combined data
            uint8_t response_hmac[32];
            esp_hmac_calculate(HMAC_KEY3, combined_data, sizeof(combined_data), response_hmac);

            // Convert response HMAC to hex string
            String response;
            for (int i = 0; i < 32; i++) {
                char hex[3];
                sprintf(hex, "%02x", response_hmac[i]); 
                response += hex;
            }

            Serial.printf("Response HMAC: %s\n", response.c_str());

            // Send the response
            request->send(200, "text/plain", response);
        } else {
            request->send(400, "text/plain", "Missing 'challenge' parameter");
        }
    }

    AsyncWebServer server(8888);

    void setup_remoteAttest(void *pvParameters){
        // Setup the server
        // HTTP server
        
        server.on("/hash", HTTP_GET, [](AsyncWebServerRequest *request) {
            uint8_t final_hmac[32] = {0};
            calculate_full_rom_hmac(request, final_hmac); // Calculate the HMAC dynamically
            //handleChallenge(request, final_hmac);
        });
      // http://172.20.10.2/hash?challenge=123123123123ihihi
      
        server.begin();

    }
}