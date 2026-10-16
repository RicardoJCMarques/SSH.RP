/*!
 * @file        src/main.cpp
 * @description SSH daemon with an LED shell for RP2040 + W5500 boards.
 * @author      Eltryus - Ricardo Marques
 * @copyright   2026 Eltryus - Ricardo Marques
 * @see         https://github.com/RicardoJCMarques/SSH.RP
 *
 * SPDX-FileCopyrightText: 2026 Eltryus - Ricardo Marques
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <Arduino.h>

#if defined(TARGET_W55RP20)
#include <W55RP20lwIP.h>
Wiznet55rp20lwIP eth(20);
#elif defined(TARGET_RP2040_W5500)
#include <SPI.h>
#include <W5500lwIP.h>
Wiznet5500lwIP eth(W5500_CS_PIN);
#else
#error "Build with -DTARGET_W55RP20 or -DTARGET_RP2040_W5500"
#endif

#include <WiFiClient.h>
#include <WiFiServer.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/coding.h>

#if !__has_include("keys.h")
#error "include/keys.h is missing - follow include/KEY_MANAGEMENT.md"
#endif
#include "keys.h"

#define SSH_PORT 22
#define SSH_USER "sshrp"
#define HANDSHAKE_TIMEOUT_MS 60000UL
#define CLOSE_TIMEOUT_MS 1000UL
#define BLINK_INTERVAL_MS 500UL

static const IPAddress BOARD_IP(192, 168, 1, 120);
static const IPAddress BOARD_GATEWAY(192, 168, 1, 1);
static const IPAddress BOARD_NETMASK(255, 255, 255, 0);

enum SessionState { ST_IDLE, ST_HANDSHAKE, ST_SHELL, ST_CLOSING };
enum LedMode { LED_OFF, LED_ON, LED_BLINK };

static WiFiServer server(SSH_PORT);
static WiFiClient client;
static WOLFSSH_CTX* ctx = nullptr;
static WOLFSSH* ssh = nullptr;
static SessionState state = ST_IDLE;
static unsigned long stateSince = 0;
static char lineBuf[32];
static size_t lineLen = 0;
static bool lastWasCR = false;
static LedMode ledMode = LED_OFF;
static unsigned long lastBlink = 0;
static byte authorizedKey[64];
static word32 authorizedKeyLen = 0;

static const char BANNER[] =
    "\r\n=========================================\r\n"
    "       RP2040 SSH Terminal Server        \r\n"
    "=========================================\r\n"
    " Commands: on, off, blink, status, exit\r\n"
    "=========================================\r\n";
static const char PROMPT[] = "\r\nRP2040> ";

static void haltWithMessage(const char* msg) {
    Serial.println(msg);
    while (true) delay(1000);
}

/*
 * keys.h holds both keys exactly as ssh-keygen writes them, so creating keys needs no
 * tool besides ssh-keygen. wolfSSH 1.6 only loads an Ed25519 host key as PKCS#8 DER and
 * hands the auth callback the client key as a binary SSH key blob, so the functions
 * below convert both at boot. Field layouts: OpenSSH PROTOCOL.key and RFC 4253 6.6.
 */

static bool readU32(const byte* buf, word32 len, word32* pos, word32* value) {
    if (len - *pos < 4) return false;
    const byte* p = buf + *pos;
    *value = ((word32)p[0] << 24) | ((word32)p[1] << 16) | ((word32)p[2] << 8) | p[3];
    *pos += 4;
    return true;
}

// Reads an SSH "string": a 32-bit big-endian length followed by that many bytes.
static bool readString(const byte* buf, word32 len, word32* pos, const byte** str, word32* strLen) {
    if (!readU32(buf, len, pos, strLen) || *strLen > len - *pos) return false;
    *str = buf + *pos;
    *pos += *strLen;
    return true;
}

static bool stringIs(const byte* str, word32 strLen, const char* expected) {
    return strLen == strlen(expected) && memcmp(str, expected, strLen) == 0;
}

// Turns the text of an unencrypted ssh-keygen Ed25519 private key into the 48-byte
// PKCS#8 DER form: a fixed 16-byte header followed by the 32-byte private seed.
static bool hostKeyToDer(const char* text, byte der[48]) {
    static const char BEGIN[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
    static const char END[] = "-----END OPENSSH PRIVATE KEY-----";
    static const char MAGIC[] = "openssh-key-v1";  // the key stores it with its NUL, hence sizeof
    static const byte PKCS8_ED25519[16] = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                                           0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};

    const char* b64 = strstr(text, BEGIN);
    const char* end = b64 ? strstr(b64, END) : nullptr;
    if (end == nullptr) return false;
    b64 += sizeof(BEGIN) - 1;

    byte bin[1024];
    word32 binLen = sizeof(bin);
    if (Base64_Decode((const byte*)b64, (word32)(end - b64), bin, &binLen) != 0) return false;
    if (binLen < sizeof(MAGIC) || memcmp(bin, MAGIC, sizeof(MAGIC)) != 0) return false;

    word32 pos = sizeof(MAGIC);
    word32 privPos = 0;
    word32 n, keyCount, check1, check2, privLen;
    const byte* s;
    const byte* priv;
    bool ok = readString(bin, binLen, &pos, &s, &n) && stringIs(s, n, "none")  // cipher: no passphrase
        && readString(bin, binLen, &pos, &s, &n) && stringIs(s, n, "none")     // KDF
        && readString(bin, binLen, &pos, &s, &n)                               // KDF options
        && readU32(bin, binLen, &pos, &keyCount) && keyCount == 1
        && readString(bin, binLen, &pos, &s, &n)                               // public key blob
        && readString(bin, binLen, &pos, &priv, &privLen)                      // private section
        && readU32(priv, privLen, &privPos, &check1)
        && readU32(priv, privLen, &privPos, &check2) && check1 == check2
        && readString(priv, privLen, &privPos, &s, &n) && stringIs(s, n, "ssh-ed25519")
        && readString(priv, privLen, &privPos, &s, &n) && n == 32              // public key
        && readString(priv, privLen, &privPos, &s, &n) && n == 64;             // seed + public key
    if (ok) {
        memcpy(der, PKCS8_ED25519, sizeof(PKCS8_ED25519));
        memcpy(der + sizeof(PKCS8_ED25519), s, 32);
    }
    return ok;
}

// Decodes the base64 field of an id_ed25519.pub line ("ssh-ed25519 <base64> comment") into
// the 51-byte key blob: length + "ssh-ed25519" + length + 32-byte public key.
static bool loadAuthorizedKey(const char* line) {
    static const char TYPE[] = "ssh-ed25519";
    while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') line++;
    if (strncmp(line, TYPE, sizeof(TYPE) - 1) != 0) return false;
    const char* b64 = line + sizeof(TYPE) - 1;
    if (*b64 != ' ' && *b64 != '\t') return false;
    while (*b64 == ' ' || *b64 == '\t') b64++;
    authorizedKeyLen = sizeof(authorizedKey);
    return Base64_Decode((const byte*)b64, (word32)strcspn(b64, " \t\r\n"),
                         authorizedKey, &authorizedKeyLen) == 0
        && authorizedKeyLen == 51;
}

static int ioRecv(WOLFSSH*, void* buf, word32 sz, void* ioCtx) {
    WiFiClient* c = static_cast<WiFiClient*>(ioCtx);
    int avail = c->available();
    if (avail <= 0) return c->connected() ? WS_CBIO_ERR_WANT_READ : WS_CBIO_ERR_CONN_CLOSE;
    size_t want = (sz < (word32)avail) ? sz : (size_t)avail;
    int n = c->read(static_cast<uint8_t*>(buf), want);
    return (n > 0) ? n : WS_CBIO_ERR_WANT_READ;
}

static int ioSend(WOLFSSH*, void* buf, word32 sz, void* ioCtx) {
    WiFiClient* c = static_cast<WiFiClient*>(ioCtx);
    if (!c->connected()) return WS_CBIO_ERR_CONN_CLOSE;
    size_t n = c->write(static_cast<const uint8_t*>(buf), sz);
    return (n > 0) ? (int)n : WS_CBIO_ERR_WANT_WRITE;
}

static bool ctEqual(const byte* a, size_t aLen, const byte* b, size_t bLen) {
    if (a == nullptr || aLen != bLen) return false;
    byte diff = 0;
    for (size_t i = 0; i < aLen; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

// Login methods offered to the client; password only when keys.h defines one.
static int userAuthTypes(WOLFSSH*, void*) {
#ifdef SSH_PASSWORD
    return WOLFSSH_USERAUTH_PUBLICKEY | WOLFSSH_USERAUTH_PASSWORD;
#else
    return WOLFSSH_USERAUTH_PUBLICKEY;
#endif
}

static int userAuth(byte authType, WS_UserAuthData* d, void*) {
    if (!ctEqual(d->username, d->usernameSz, (const byte*)SSH_USER, strlen(SSH_USER)))
        return WOLFSSH_USERAUTH_FAILURE;
    if (authType == WOLFSSH_USERAUTH_PUBLICKEY &&
        ctEqual(d->sf.publicKey.publicKey, d->sf.publicKey.publicKeySz,
                authorizedKey, authorizedKeyLen))
        return WOLFSSH_USERAUTH_SUCCESS;
#ifdef SSH_PASSWORD
    if (authType == WOLFSSH_USERAUTH_PASSWORD &&
        ctEqual(d->sf.password.password, d->sf.password.passwordSz,
                (const byte*)SSH_PASSWORD, strlen(SSH_PASSWORD)))
        return WOLFSSH_USERAUTH_SUCCESS;
#endif
    return WOLFSSH_USERAUTH_FAILURE;
}

static void setLed(LedMode mode) {
    ledMode = mode;
    lastBlink = millis();
    digitalWrite(USER_LED, mode == LED_OFF ? LOW : HIGH);
}

// Runs every loop() pass. Blinking pauses while a handshake's key exchange is computed.
static void updateLed() {
    if (ledMode == LED_BLINK && millis() - lastBlink >= BLINK_INTERVAL_MS) {
        lastBlink = millis();
        digitalWrite(USER_LED, !digitalRead(USER_LED));
    }
}

static void sshPrint(const char* s) {
    wolfSSH_stream_send(ssh, (byte*)s, (word32)strlen(s));
}

static void dropSession(const char* why) {
    if (ssh) {
        wolfSSH_free(ssh);
        ssh = nullptr;
    }
    client.stop();
    state = ST_IDLE;
    Serial.printf("[SSH] Session closed (%s)\n", why);
}

static bool runCommand(const char* cmd) {
    if (strcmp(cmd, "exit") == 0) return false;
    if (strcmp(cmd, "on") == 0) {
        setLed(LED_ON);
        sshPrint("\r\nLED ON.");
    } else if (strcmp(cmd, "off") == 0) {
        setLed(LED_OFF);
        sshPrint("\r\nLED OFF.");
    } else if (strcmp(cmd, "blink") == 0) {
        setLed(LED_BLINK);
        sshPrint("\r\nLED BLINKING.");
    } else if (strcmp(cmd, "status") == 0) {
        sshPrint(ledMode == LED_BLINK ? "\r\nLED: BLINKING"
                 : ledMode == LED_ON  ? "\r\nLED: ON"
                                      : "\r\nLED: OFF");
    } else if (cmd[0] != '\0') {
        sshPrint("\r\nUnknown command. Options: on, off, blink, status, exit");
    }
    sshPrint(PROMPT);
    return true;
}

static bool handleInput(const byte* buf, int len) {
    for (int i = 0; i < len; i++) {
        char ch = (char)buf[i];
        if (ch == '\n' && lastWasCR) {
            lastWasCR = false;
            continue;
        }
        lastWasCR = (ch == '\r');
        if (ch == '\r' || ch == '\n') {
            lineBuf[lineLen] = '\0';
            lineLen = 0;
            if (!runCommand(lineBuf)) return false;
        } else if (ch == 0x7F || ch == '\b') {
            if (lineLen > 0) {
                lineLen--;
                sshPrint("\b \b");
            }
        } else if (ch >= 0x20 && ch < 0x7F && lineLen < sizeof(lineBuf) - 1) {
            lineBuf[lineLen++] = ch;
            wolfSSH_stream_send(ssh, (byte*)&ch, 1);
        }
    }
    return true;
}

void setup() {
    pinMode(USER_LED, OUTPUT);
    setLed(LED_OFF);

    Serial.begin(115200);
    delay(1500);
    Serial.println("\n[INIT] Starting SSH Daemon...");

#if defined(TARGET_RP2040_W5500)
    pinMode(W5500_RST_PIN, OUTPUT);
    digitalWrite(W5500_RST_PIN, LOW);
    delay(10);
    digitalWrite(W5500_RST_PIN, HIGH);
    delay(50);

    SPI.setRX(16);
    SPI.setCS(W5500_CS_PIN);
    SPI.setSCK(18);
    SPI.setTX(19);
#endif

    eth.config(BOARD_IP, BOARD_GATEWAY, BOARD_NETMASK);
    if (!eth.begin()) haltWithMessage("[ERR] Ethernet hardware initialization failed.");
    while (!eth.connected()) {
        delay(500);
        Serial.print(".");
    }
    Serial.printf("\n[NET] IP: %s\n", eth.localIP().toString().c_str());

    // Checked once the network is up, so a bad key makes ssh fail with "Connection refused"
    // (board reachable, no SSH server) instead of a timeout. Serial shows which key.
    byte hostKeyDer[48];
    if (!hostKeyToDer(SSH_HOST_KEY, hostKeyDer))
        haltWithMessage("[ERR] SSH_HOST_KEY in keys.h is not an ssh-keygen Ed25519 key without a passphrase.");
    if (!loadAuthorizedKey(SSH_AUTHORIZED_KEY))
        haltWithMessage("[ERR] SSH_AUTHORIZED_KEY in keys.h is not an ssh-ed25519 public key line.");

    if (wolfSSH_Init() != WS_SUCCESS) haltWithMessage("[ERR] wolfSSH_Init failed.");
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, nullptr);
    if (!ctx) haltWithMessage("[ERR] wolfSSH_CTX_new failed.");

    wolfSSH_SetIORecv(ctx, ioRecv);
    wolfSSH_SetIOSend(ctx, ioSend);
    wolfSSH_SetUserAuth(ctx, userAuth);
    wolfSSH_SetUserAuthTypes(ctx, userAuthTypes);

    int ret = wolfSSH_CTX_UsePrivateKey_buffer(ctx, hostKeyDer, sizeof(hostKeyDer),
                                               WOLFSSH_FORMAT_ASN1);
    if (ret != WS_SUCCESS) {
        Serial.printf("[ERR] Host key load failed: %d (%s)\n", ret, wolfSSH_ErrorToName(ret));
        haltWithMessage("[ERR] Halted.");
    }

    server.begin();
    Serial.printf("[SSH] Daemon listening on port %d\n", SSH_PORT);
}

void loop() {
    updateLed();

    switch (state) {
    case ST_IDLE: {
        WiFiClient incoming = server.accept();
        if (!incoming) return;
        client = incoming;
        client.setNoDelay(true);
        // Only one session runs at a time, so a client that vanishes without closing
        // (cable pulled, laptop asleep) must not hold it forever: TCP keepalive probes
        // after 30 s of silence drop it within about a minute.
        client.keepAlive(30, 10, 3);
        ssh = wolfSSH_new(ctx);
        if (!ssh) {
            client.stop();
            return;
        }
        wolfSSH_SetIOReadCtx(ssh, &client);
        wolfSSH_SetIOWriteCtx(ssh, &client);
        lineLen = 0;
        lastWasCR = false;
        stateSince = millis();
        state = ST_HANDSHAKE;
        Serial.printf("[NET] Client %s connected.\n", client.remoteIP().toString().c_str());
        return;
    }
    case ST_HANDSHAKE: {
        if (wolfSSH_accept(ssh) == WS_SUCCESS) {
            Serial.printf("[SSH] Authenticated after %lu ms.\n", millis() - stateSince);
            sshPrint(BANNER);
            sshPrint(PROMPT);
            state = ST_SHELL;
            return;
        }
        int err = wolfSSH_get_error(ssh);
        if (err != WS_WANT_READ && err != WS_WANT_WRITE) {
            dropSession(wolfSSH_ErrorToName(err));
        } else if (millis() - stateSince > HANDSHAKE_TIMEOUT_MS) {
            dropSession("handshake timeout");
        }
        return;
    }
    case ST_SHELL: {
        byte buf[64];
        int n = wolfSSH_stream_read(ssh, buf, sizeof(buf));
        if (n > 0) {
            if (!handleInput(buf, n)) {
                sshPrint("\r\nSession closed.\r\n");
                wolfSSH_stream_exit(ssh, 0);
                stateSince = millis();
                state = ST_CLOSING;
            }
            return;
        }
        int err = wolfSSH_get_error(ssh);
        if (err != WS_WANT_READ && err != WS_WANT_WRITE) dropSession(wolfSSH_ErrorToName(err));
        return;
    }
    case ST_CLOSING:
        // Let the client hang up first. Closing while its last messages are unread makes
        // lwIP reset the connection, which ssh can report as an error instead of a clean exit.
        while (client.available() > 0) client.read();
        if (!client.connected() || millis() - stateSince > CLOSE_TIMEOUT_MS) dropSession("exit");
        return;
    }
}
