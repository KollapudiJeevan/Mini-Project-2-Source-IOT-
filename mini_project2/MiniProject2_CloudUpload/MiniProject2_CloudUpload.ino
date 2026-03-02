#include <WiFi.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <DHT.h>
#include <ArduinoJson.h>

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

// ===================== DHT SETUP =====================
#define DHTPIN 26
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// ===================== WIFI (CHANGE THIS) =====================
const char* WIFI_SSID = "jeevaniphone";
const char* WIFI_PASS = "12345678";

// ===================== CLOUD SERVER (CHANGE THIS) =====================
String CLOUD_POST_URL = "http://172.20.10.2:8888/post-data";  // your laptop IP
String TEAM_NUMBER = "6";

// ===================== CONFIG (can be changed by POST /config) =====================
volatile bool encryptionEnabled = true;
volatile uint32_t uploadIntervalMs = 5000;

// ===================== REST SERVER =====================
WebServer apiServer(80);
unsigned long bootMs = 0;

// ===================== AES SETTINGS (MUST MATCH server.py) =====================
static const uint8_t AES_KEY[16] = {
  '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
};
static const uint8_t AES_IV[16]  = {
  'A','B','C','D','E','F','0','1','2','3','4','5','6','7','8','9'
};

// ===================== LAST SENSOR CACHE =====================
float lastT = NAN;
float lastH = NAN;
uint32_t lastReadTs = 0; // seconds since boot for demo
bool lastReadOk = false;

// ---------- helper: safe DHT read ----------
bool readDHT(float &t, float &h) {
  for (int i = 0; i < 5; i++) {
    t = dht.readTemperature();
    h = dht.readHumidity();
    if (!isnan(t) && !isnan(h)) return true;
    delay(200);
  }
  return false;
}

void refreshSensorCache() {
  float t, h;
  if (readDHT(t, h)) {
    lastT = t;
    lastH = h;
    lastReadTs = (uint32_t)(millis() / 1000);
    lastReadOk = true;
  } else {
    lastReadOk = false;
  }
}

// ---------- helper: PKCS7 pad to 16 bytes ----------
int pkcs7Pad(const uint8_t* in, int inLen, uint8_t* out, int outMax) {
  int padLen = 16 - (inLen % 16);
  int total = inLen + padLen;
  if (total > outMax) return -1;
  memcpy(out, in, inLen);
  for (int i = 0; i < padLen; i++) out[inLen + i] = (uint8_t)padLen;
  return total;
}

// ---------- helper: AES-128-CBC encrypt ----------
bool aesEncryptCbc(const uint8_t* plaintext, int ptLen, uint8_t* ciphertext, int ctMax, int &ctLen) {
  uint8_t padded[256];
  int paddedLen = pkcs7Pad(plaintext, ptLen, padded, sizeof(padded));
  if (paddedLen < 0 || paddedLen > ctMax) return false;

  uint8_t ivCopy[16];
  memcpy(ivCopy, AES_IV, 16);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  if (mbedtls_aes_setkey_enc(&aes, AES_KEY, 128) != 0) {
    mbedtls_aes_free(&aes);
    return false;
  }

  int rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, ivCopy, padded, ciphertext);
  mbedtls_aes_free(&aes);

  if (rc != 0) return false;
  ctLen = paddedLen;
  return true;
}

// ---------- helper: Base64 encode ----------
String base64Encode(const uint8_t* data, size_t len) {
  size_t outLen = 0;
  unsigned char out[512];
  int rc = mbedtls_base64_encode(out, sizeof(out), &outLen, data, len);
  if (rc != 0) return String("");
  out[outLen] = '\0';
  return String((char*)out);
}

// ---------- build inner JSON for temp/hum/timestamp ----------
String buildPlainSensorJson(float t, float h, uint32_t ts) {
  StaticJsonDocument<256> inner;
  inner["temperature"] = t;
  inner["humidity"] = h;
  inner["timestamp"] = ts;
  String s;
  serializeJson(inner, s);
  return s;
}

// ---------- upload one reading to cloud (encrypted wrapper OR plain) ----------
bool uploadToCloud(float t, float h, uint32_t ts) {
  HTTPClient http;
  http.begin(CLOUD_POST_URL);
  http.addHeader("Content-Type", "application/json");

  String body;

  if (encryptionEnabled) {
    // encrypt inner JSON
    String innerJson = buildPlainSensorJson(t, h, ts);

    uint8_t ct[256];
    int ctLen = 0;
    if (!aesEncryptCbc((const uint8_t*)innerJson.c_str(), innerJson.length(), ct, sizeof(ct), ctLen)) {
      Serial.println("Encrypt failed");
      http.end();
      return false;
    }

    String payload_b64 = base64Encode(ct, ctLen);
    if (payload_b64.length() == 0) {
      Serial.println("Base64 failed");
      http.end();
      return false;
    }

    // wrapper JSON
    StaticJsonDocument<512> wrap;
    wrap["team_number"] = TEAM_NUMBER;
    wrap["encrypted"] = true;
    wrap["payload_b64"] = payload_b64;
    serializeJson(wrap, body);
  } else {
    // plain JSON
    StaticJsonDocument<256> plain;
    plain["team_number"] = TEAM_NUMBER;
    plain["temperature"] = t;
    plain["humidity"] = h;
    plain["timestamp"] = ts;
    serializeJson(plain, body);
  }

  int code = http.POST((uint8_t*)body.c_str(), body.length());
  String resp = http.getString();
  http.end();

  Serial.print("Cloud POST code: ");
  Serial.println(code);
  Serial.print("Cloud resp: ");
  Serial.println(resp);

  return (code >= 200 && code < 300);
}

// ===================== REST ENDPOINTS (EXTRA CREDIT) =====================

// GET /health  -> { "ok": true, "uptime_s": 120 }
void handleHealth() {
  StaticJsonDocument<128> doc;
  doc["ok"] = true;
  doc["uptime_s"] = (uint32_t)((millis() - bootMs) / 1000);

  String out;
  serializeJson(doc, out);
  apiServer.send(200, "application/json", out);
}

// GET /sensor
// - if encryptionEnabled: returns { "encrypted":true, "payload_b64":"..." }
// - else returns plain sensor JSON { "temperature":..., "humidity":..., "timestamp":... }
void handleSensor() {
  refreshSensorCache();

  if (!lastReadOk) {
    apiServer.send(500, "application/json", "{\"ok\":false,\"error\":\"DHT read failed\"}");
    return;
  }

  if (encryptionEnabled) {
    String innerJson = buildPlainSensorJson(lastT, lastH, lastReadTs);

    uint8_t ct[256];
    int ctLen = 0;
    if (!aesEncryptCbc((const uint8_t*)innerJson.c_str(), innerJson.length(), ct, sizeof(ct), ctLen)) {
      apiServer.send(500, "application/json", "{\"ok\":false,\"error\":\"encrypt failed\"}");
      return;
    }

    String payload_b64 = base64Encode(ct, ctLen);
    if (payload_b64.length() == 0) {
      apiServer.send(500, "application/json", "{\"ok\":false,\"error\":\"base64 failed\"}");
      return;
    }

    StaticJsonDocument<512> doc;
    doc["encrypted"] = true;
    doc["payload_b64"] = payload_b64;

    String out;
    serializeJson(doc, out);
    apiServer.send(200, "application/json", out);
  } else {
    // plain
    String out = buildPlainSensorJson(lastT, lastH, lastReadTs);
    apiServer.send(200, "application/json", out);
  }
}

// POST /config
// Accept JSON: { "upload_interval_ms": 5000, "encryption": true }
// Response: { "ok": true, "upload_interval_ms":..., "encryption":... }
void handleConfig() {
  if (!apiServer.hasArg("plain")) {
    apiServer.send(400, "application/json", "{\"ok\":false,\"error\":\"Missing JSON body\"}");
    return;
  }

  String body = apiServer.arg("plain");
  StaticJsonDocument<256> in;
  DeserializationError err = deserializeJson(in, body);
  if (err) {
    apiServer.send(400, "application/json", "{\"ok\":false,\"error\":\"Bad JSON\"}");
    return;
  }

  if (in.containsKey("upload_interval_ms")) {
    uint32_t v = in["upload_interval_ms"];
    if (v < 1000) v = 1000;         // safety minimum
    if (v > 600000) v = 600000;     // safety maximum 10 min
    uploadIntervalMs = v;
  }

  if (in.containsKey("encryption")) {
    encryptionEnabled = (bool)in["encryption"];
  }

  StaticJsonDocument<256> out;
  out["ok"] = true;
  out["upload_interval_ms"] = uploadIntervalMs;
  out["encryption"] = encryptionEnabled;

  String resp;
  serializeJson(out, resp);
  apiServer.send(200, "application/json", resp);
}

// POST /push-now -> reads sensor and uploads immediately
void handlePushNow() {
  refreshSensorCache();
  if (!lastReadOk) {
    apiServer.send(500, "application/json", "{\"ok\":false,\"error\":\"DHT read failed\"}");
    return;
  }

  bool ok = uploadToCloud(lastT, lastH, lastReadTs);

  StaticJsonDocument<128> out;
  out["ok"] = ok;

  String resp;
  serializeJson(out, resp);
  apiServer.send(ok ? 200 : 500, "application/json", resp);
}

// ===================== WIFI =====================
void connectWiFi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    tries++;
    if (tries > 40) { // ~20s
      Serial.println("\nWiFi failed. Restarting...");
      ESP.restart();
    }
  }

  Serial.println("\nWiFi connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());
}

// ===================== MAIN =====================
unsigned long lastUpload = 0;

void setup() {
  Serial.begin(115200);
  delay(300);

  bootMs = millis();
  dht.begin();
  connectWiFi();

  // REST API endpoints (extra credit requirement) :contentReference[oaicite:2]{index=2}
  apiServer.on("/health", HTTP_GET, handleHealth);
  apiServer.on("/sensor", HTTP_GET, handleSensor);
  apiServer.on("/config", HTTP_POST, handleConfig);
  apiServer.on("/push-now", HTTP_POST, handlePushNow);
  apiServer.begin();

  Serial.println("Mini Project 2 + Extra Credit REST API Ready");
  Serial.print("Cloud URL: "); Serial.println(CLOUD_POST_URL);
  Serial.println("Try in browser: http://<ESP32_IP>/health  and  /sensor");
}

void loop() {
  apiServer.handleClient();

  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  // periodic push to cloud
  if (millis() - lastUpload >= uploadIntervalMs) {
    lastUpload = millis();
    refreshSensorCache();
    if (lastReadOk) {
      uploadToCloud(lastT, lastH, lastReadTs);
    } else {
      Serial.println("DHT read failed (periodic upload)");
    }
  }
}