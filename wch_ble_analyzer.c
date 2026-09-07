/*
 * WCH BLE Analyzer Pro – Linux libusb driver implementation
 *
 * Protocol confirmed by reverse-engineering BleAnalyzer64.exe:
 *
 *   Command format (EP 0x02, Bulk OUT):
 *     [0xAA][CMD][len_lo][len_hi][payload…]
 *
 *   Init sequence (state=3, firmware already loaded):
 *     1. AA 84 13 00 [00 00 00 00] "BLEAnalyzer&IAP"  → EP 0x82: 33 32
 *     2. AA 81 19 00 [25-byte BLE config payload]      → starts BLE streaming
 *     3. AA A1 00 00                                   → status echo + scan
 *
 *   Data frame format (received on EP 0x82, one per USB transfer):
 *     Byte 0:    0x55 (magic)
 *     Byte 1:    0x10 (data packet) | 0x01 (status echo)
 *     Byte 2-3:  payload_len (LE uint16)
 *     Payload:
 *       [0-3]  timestamp_us (LE uint32, μs from device boot)
 *       [4]    channel_index (0-39)
 *       [5]    flags (0x00 or 0x01)
 *       [6-7]  reserved (0x00 0x00)
 *       [8]    rssi (signed int8, dBm)
 *       [9]    reserved
 *       [10]   pdu_hdr0 (BLE LL PDU header byte 0)
 *       [11]   pdu_payload_len (bytes, includes AdvA, excludes CRC)
 *       [12-17] addr (AdvA, or ScanA for SCAN_REQ)
 *       [18+]  rest of PDU payload (AdvData, or AdvA for SCAN_REQ)
 */

#include "wch_ble_analyzer.h"
#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Globals defined in wch_capture.c – shared for data channel AA substitution */
extern bool g_following;
extern uint32_t g_follow_aa;

/*
 * -B: mark the Access Address and CRCInit fields of the AA 81 payload as
 * valid (flags bits 0x10 and 0x20).  Defined in wch_capture.c.  See
 * wch_reconfig_capture() for why this is opt-in.
 */
extern bool g_aa81_mark_fields;

/* ── Protocol constants ─────────────────────────────────────────────────── */

#define WCH_MAGIC 0xAA      /* command magic byte */
#define CMD_IDENTIFY 0x84   /* identify/arm */
#define CMD_BLE_CONFIG 0x81 /* BLE monitor config + start */
#define CMD_SCAN_START 0xA1 /* start scan trigger */
#define CMD_LL_UPDATE 0x82  /* relay an LL control PDU (conn param update) */

/* "BLEAnalyzer&IAP" – 15-byte ASCII string used in the identify command */
static const uint8_t IAP_STR[15] = {'B', 'L', 'E', 'A', 'n', 'a', 'l', 'y',
                                    'z', 'e', 'r', '&', 'I', 'A', 'P'};

/* Device frame magic bytes */
#define FRAME_MAGIC 0x55
#define FRAME_TYPE_DATA 0x10
#define FRAME_TYPE_STS 0x01 /* status / config echo */

/* BLE advertising access address (little-endian) */
#define BLE_ADV_AA UINT32_C(0x8E89BED6)

/* Advertising Access Address / CRCInit as they sit in the AA 81 payload.
 * Confirmed against the device's own AA A1 config read-back. */
static const uint8_t ADV_AA_BYTES[4] = {0xD6, 0xBE, 0x89, 0x8E};
static const uint8_t ADV_CRCINIT[3] = {0x55, 0x55, 0x55};

/* AA 81 flags byte bits (firmware treats this as a field-presence mask). */
#define F81_START 0x01    /* begin capturing                       */
#define F81_CHANNEL 0x02  /* frame[6] holds a channel              */
#define F81_AA_VALID 0x10 /* frame[15..18] holds an Access Address */
#define F81_CRC_VALID 0x20/* frame[19..21] holds a CRCInit         */

/*
 * Check an AA A1 config read-back against what we asked for.  The echo is
 * 55 01 19 00 followed by the accepted 25-byte payload, so the field offsets
 * are identical to the command frame's.  Returns true when they agree.
 */
static bool echo_matches(const uint8_t *resp, int got, const uint8_t aa[4],
                         const uint8_t crc[3]) {
  if (got < 29 || resp[0] != 0x55 || resp[1] != 0x01)
    return false;
  return memcmp(resp + 15, aa, 4) == 0 && memcmp(resp + 19, crc, 3) == 0;
}

/* Minimum payload bytes in a data frame */
#define MIN_DATA_PAYLOAD 18 /* 12 meta + 6 addr */

/* ── Internal helpers ───────────────────────────────────────────────────── */

static int bulk_write(wch_device_t *dev, const uint8_t *buf, int len) {
  int xfer = 0;
  return libusb_bulk_transfer(dev->handle, EP_BULK_OUT, (uint8_t *)buf, len,
                              &xfer, 1000);
}

static int bulk_read(wch_device_t *dev, uint8_t *buf, int len, int *got,
                     int timeout_ms) {
  *got = 0;
  return libusb_bulk_transfer(dev->handle, EP_BULK_IN, buf, len, got,
                              timeout_ms);
}

/* ── wch_init ────────────────────────────────────────────────────────────── */

int wch_init(libusb_context **ctx_out) { return libusb_init(ctx_out); }

/* ── wch_exit ────────────────────────────────────────────────────────────── */

void wch_exit(libusb_context *ctx) { libusb_exit(ctx); }

/* ── wch_find_devices ────────────────────────────────────────────────────── */

int wch_find_devices(libusb_context *ctx, wch_device_t devs[MAX_MCU_DEVICES]) {
  libusb_device **list;
  ssize_t cnt = libusb_get_device_list(ctx, &list);
  if (cnt < 0)
    return (int)cnt;

  int found = 0;
  for (ssize_t i = 0; i < cnt && found < MAX_MCU_DEVICES; i++) {
    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(list[i], &desc) != 0)
      continue;
    if (desc.idVendor != WCH_VID || desc.idProduct != WCH_PID_BLE_MCU)
      continue;

    memset(&devs[found], 0, sizeof(wch_device_t));
    devs[found].ctx = ctx;
    devs[found].bus = libusb_get_bus_number(list[i]);
    devs[found].addr = libusb_get_device_address(list[i]);
    devs[found].is_open = false;
    found++;
  }

  libusb_free_device_list(list, 1);
  return found;
}

/* ── wch_open_device ─────────────────────────────────────────────────────── */

int wch_open_device(wch_device_t *dev) {
  libusb_device **list;
  ssize_t cnt = libusb_get_device_list(dev->ctx, &list);
  if (cnt < 0)
    return (int)cnt;

  libusb_device *target = NULL;
  for (ssize_t i = 0; i < cnt; i++) {
    if (libusb_get_bus_number(list[i]) == dev->bus &&
        libusb_get_device_address(list[i]) == dev->addr) {
      target = list[i];
      break;
    }
  }

  if (!target) {
    libusb_free_device_list(list, 1);
    return LIBUSB_ERROR_NO_DEVICE;
  }

  int r = libusb_open(target, &dev->handle);
  libusb_free_device_list(list, 1);
  if (r != 0)
    return r;

  libusb_set_auto_detach_kernel_driver(dev->handle, 1);

  r = libusb_claim_interface(dev->handle, 0);
  if (r != 0) {
    libusb_close(dev->handle);
    dev->handle = NULL;
    return r;
  }

  dev->is_open = true;
  dev->rx_count = 0;
  dev->err_count = 0;
  dev->ts_prev_us = 0;
  dev->ts_hi_us = 0;
  dev->pkt_seq = 0;
  return 0;
}

/* ── wch_close_device ────────────────────────────────────────────────────── */

void wch_close_device(wch_device_t *dev) {
  if (!dev->is_open)
    return;
  libusb_release_interface(dev->handle, 0);
  libusb_close(dev->handle);
  dev->handle = NULL;
  dev->is_open = false;
}

/* ── wch_start_capture ───────────────────────────────────────────────────── */

/*
 * Confirmed init sequence for state=3 (firmware already loaded):
 *
 *   Step 1 – AA 84: identify / arm
 *     Frame: AA 84 13 00  [00 00 00 00]  "BLEAnalyzer&IAP"
 *     Response on EP 0x82: 33 32  (non-zero byte 0 → firmware present, state=3)
 *
 *   Step 2 – AA 81: BLE monitor config
 *     Frame: AA 81 19 00  [25-byte payload]
 *     Payload: [0]=0x01 (BLE mode flag)  [1]=PHY  [2-24]=zeros (no filters)
 *     Sending this makes the device start streaming captured BLE packets
 *     immediately; you may receive a BLE packet during the response read.
 *
 *   Step 3 – AA A1: start-scan trigger
 *     Frame: AA A1 00 00
 *     Device sends a 29-byte status echo, then continues streaming.
 */
int wch_start_capture(wch_device_t *dev, const wch_capture_config_t *cfg) {
  uint8_t frame[64];
  uint8_t resp[64];
  int got, r;

  /* ── Step 1: AA 84 identify ─────────────────────────────────── */
  memset(frame, 0, sizeof(frame));
  frame[0] = WCH_MAGIC;
  frame[1] = CMD_IDENTIFY;
  frame[2] = 0x13; /* payload len = 19 = 4 + 15 */
  frame[3] = 0x00;
  /* bytes [4..7] = 4-byte device ID (zeros works) */
  memcpy(frame + 8, IAP_STR, sizeof(IAP_STR));

  r = bulk_write(dev, frame, 4 + 4 + 15);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  /* Read response: expect 2 bytes (e.g. 33 32) indicating firmware present */
  r = bulk_read(dev, resp, sizeof(resp), &got, 2000);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
    fprintf(stderr, "[wch bus=%d addr=%d] AA84 read error: %s\n", dev->bus,
            dev->addr, libusb_error_name(r));
    return r;
  }
  if (got >= 1)
    fprintf(stderr, "[wch bus=%d addr=%d] AA84 response[0]=0x%02X (%s)\n",
            dev->bus, dev->addr, resp[0],
            resp[0] ? "firmware present, state=3" : "no firmware?");

  /* ── Step 2: AA 81 BLE monitor config ───────────────────────── */
  memset(frame, 0, sizeof(frame));
  frame[0] = WCH_MAGIC;
  frame[1] = CMD_BLE_CONFIG;
  frame[2] = 0x19; /* payload len = 25 */
  frame[3] = 0x00;
  frame[4] = F81_START; /* BLE monitor mode flag */
  frame[5] = cfg->phy ? cfg->phy : 1; /* PHY: 1=1M 2=2M 3/4=Coded */
  frame[6] = cfg->ble_channel;        /* channel: adv 37/38/39, or data 0-36 */
  /* bytes [7..28] = zeros (no MAC filters, no LTK, no pass-key) */

  /*
   * Are we starting directly on a known connection, or on advertising?
   * conn_req_data holds the 22-byte LLData from a CONNECT_IND: Access Address
   * in bytes 0..3, CRCInit in 4..6.  All-zero means we have no connection.
   */
  static const uint8_t no_conn[22] = {0};
  bool have_conn =
      cfg->follow_conn && memcmp(cfg->conn_req_data, no_conn, 22) != 0;

  /*
   * Channel-present bit.  On advertising a zero channel legitimately means
   * "all three advertising channels", so the bit stays conditional.  On a
   * connection the channel is an explicit data channel and 0 is a valid one,
   * so the bit must be unconditional -- the same reasoning as
   * wch_reconfig_capture().
   */
  if (have_conn || cfg->ble_channel)
    frame[4] |= F81_CHANNEL;

  /*
   * Access Address and CRCInit.
   *
   * This used to be `memcpy(frame + 7, cfg->conn_req_data, 22)`, which
   * splattered the whole LLData across frame[7..28] and so overwrote the
   * reserved word, MAC filter #1, the Access Address, CRCInit, the frame[22]
   * bitfield and MAC filter #2 all at once, landing the LLData's own Access
   * Address at frame[7..10] instead of frame[15..18].  It only ever appeared
   * harmless because the reconfig path immediately rewrote the two fields that
   * matter.  The real layout is confirmed three ways: the AA 81 payload
   * builder at 0x14028c280 in BleAnalyzer64.exe, the device's own AA A1 config
   * read-back, and the firmware's AA 81 handler.
   *
   * The firmware only copies either field when its presence bit is set, so the
   * values and the bits must travel together.  Stating the advertising
   * defaults explicitly when there is no connection is what recovers a radio
   * left holding a stale connection Access Address by an earlier session,
   * without needing a USB reset.
   */
  if (g_aa81_mark_fields) {
    if (have_conn) {
      memcpy(frame + 15, cfg->conn_req_data, 4);     /* Access Address */
      memcpy(frame + 19, cfg->conn_req_data + 4, 3); /* CRCInit        */
    } else {
      memcpy(frame + 15, ADV_AA_BYTES, 4);
      memcpy(frame + 19, ADV_CRCINIT, 3);
    }
    frame[4] |= F81_AA_VALID | F81_CRC_VALID;
  }

  r = bulk_write(dev, frame, 4 + 25);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  /* Device may immediately stream a BLE packet – drain it briefly */
  r = bulk_read(dev, resp, sizeof(resp), &got, 100);
  if (r == 0 && got > 0)
    fprintf(stderr,
            "[wch bus=%d addr=%d] AA81 triggered %d byte(s) "
            "(BLE streaming started)\n",
            dev->bus, dev->addr, got);

  /* ── Step 3: AA A1 start-scan trigger ───────────────────────── */
  memset(frame, 0, sizeof(frame));
  frame[0] = WCH_MAGIC;
  frame[1] = CMD_SCAN_START;
  frame[2] = 0x00;
  frame[3] = 0x00;

  r = bulk_write(dev, frame, 4);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  /* Read the 29-byte status echo (55 01 19 00 …) and check it agreed. */
  r = bulk_read(dev, resp, sizeof(resp), &got, 1000);
  if (r == 0 && got >= 1)
    fprintf(stderr,
            "[wch bus=%d addr=%d] AA A1 response: %d bytes "
            "(magic=0x%02X type=0x%02X)\n",
            dev->bus, dev->addr, got, resp[0], got > 1 ? resp[1] : 0);

  if (g_aa81_mark_fields && !have_conn) {
    if (r == 0 && got >= 29 &&
        !echo_matches(resp, got, ADV_AA_BYTES, ADV_CRCINIT))
      fprintf(stderr,
              "[wch bus=%d addr=%d] WARNING: config read-back disagrees. "
              "AA=%02X%02X%02X%02X CRCInit=%02X%02X%02X (wanted D6BE898E / "
              "555555). This radio may not hear advertising.\n",
              dev->bus, dev->addr, resp[18], resp[17], resp[16], resp[15],
              resp[21], resp[20], resp[19]);
  }

  return 0;
}

/* ── wch_reconfig_capture ─────────────────────────────────────────────────
 *
 * Fast reconfiguration used after detecting a CONNECT_IND.  Skips the
 * AA 84 identify step (which costs ~20-50 ms of USB round-trip) so we
 * reach the data channels before the LL_ENC_REQ / LL_START_ENC window
 * closes.  Only AA 81 + AA A1 are sent.
 */
int wch_reconfig_capture(wch_device_t *dev, const wch_capture_config_t *cfg) {
  uint8_t frame[64];
  int r;

  /* AA 81 BLE monitor config with connection LLData */
  memset(frame, 0, sizeof(frame));
  frame[0] = WCH_MAGIC;
  frame[1] = CMD_BLE_CONFIG;
  frame[2] = 0x19;
  frame[3] = 0x00;
  frame[4] = F81_START; /* BLE monitor mode flag */
  /*
   * The channel-present bit must be set unconditionally here.
   *
   * BLE data channel 0 is a perfectly valid channel, but the old
   * `if (cfg->ble_channel)` test left the bit clear for it.  The firmware only
   * reads frame[6] when the bit is set, so whenever CSA#1 or CSA#2 selected
   * channel 0 the radio was simply never retuned, and that connection event
   * was missed.  Measured at 15 of 126 retunes with a channel map of {0..7},
   * roughly one event in eight.
   *
   * This function only ever runs while following a connection, where the
   * channel is always an explicit data channel in 0..36, so there is no
   * "unspecified" case to preserve.  wch_start_capture() keeps the
   * conditional, because there a zero channel genuinely means "all
   * advertising channels".
   */
  frame[4] |= F81_CHANNEL;
  frame[5] = cfg->phy ? cfg->phy : 1;
  frame[6] = cfg->ble_channel;

  if (cfg->follow_conn && cfg->conn_req_data[0]) {
    /* Critical Hardware Offset Fix:
     * When hopping to a Data Channel, the CH582F firmware cannot natively
     * track connections via BLE Monitor mode just by pasting the LLData struct.
     * We MUST use the explicit offsets reverse-engineered from
     * the Windows `BleAnalyzer64.exe` binary.
     *
     * In BLE Monitor mode, the hardware accepts
     * explicit Access Address, CRCInit, and RF Channel via these exact offsets:
     *   frame[15] = Access Address (4 bytes)
     *   frame[19] = CRCInit (3 bytes)
     *
     * Both offsets are CONFIRMED against the AA 81 payload builder at
     * 0x14028c280 in BleAnalyzer64.exe, which writes the default values
     * 0x8E89BED6 to frame[15..18] and 0x555555 to frame[19..21].
     *
     * The channel is frame[6] (set above), NOT frame[23].  frame[23..28] is
     * MAC filter #2 in the Windows layout; the old `frame[23] = cfg->channel`
     * write here was scribbling into that field.  It was harmless only
     * because its presence bit (0x80) is never set, so the removal below is
     * a pure correctness fix and is not gated behind any flag.
     */
    /* The first 4 bytes of conn_req_data contain the Access Address */
    memcpy(frame + 15, cfg->conn_req_data, 4);

    /* The next 3 bytes (conn_req_data[4..6]) contain the CRCInit */
    memcpy(frame + 19, cfg->conn_req_data + 4, 3);

    /*
     * Field-validity flags.  The Windows application always marks the Access
     * Address (0x10) and CRCInit (0x20) fields as valid, even when it is only
     * supplying the advertising defaults.  This tool has never set them, so
     * the firmware may be ignoring the connection AA/CRCInit written above.
     *
     * Opt-in (-B) rather than default: it changes a path that currently
     * captures data-channel traffic, and the bits are inferred from the
     * Windows builder, not observed on the wire.
     *
     * Deliberately NOT set here: bit 0x04, which the Windows builder sets
     * unconditionally (`or al, 4`).  Its meaning is unknown, and including it
     * would make the -B experiment untestable as a single variable.
     */
    if (g_aa81_mark_fields)
      frame[4] |= F81_AA_VALID | F81_CRC_VALID;
  }

  r = bulk_write(dev, frame, 4 + 25);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  /* Send AA A1 to commit config and explicitly start hopping */
  memset(frame, 0, sizeof(frame));
  frame[0] = WCH_MAGIC;
  frame[1] = CMD_SCAN_START;
  frame[2] = 0x00;
  frame[3] = 0x00;
  r = bulk_write(dev, frame, 4);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  return 0;
}

/* ── wch_send_ll_update ───────────────────────────────────────────────────
 *
 * AA 82: relay a Link Layer control PDU to the MCU so its firmware can apply
 * the new connection parameters at the Instant carried in the PDU.
 *
 * Wire format, recovered from the AA 82 sender at 0x14028c6d0 in
 * BleAnalyzer64.exe:
 *
 *     AA 82 <len:u16 LE> <payload[len]>          (len < 508)
 *
 * The payload is the LL Control PDU verbatim, starting at its two-byte data
 * channel header:
 *
 *     [hdr0][len][opcode][params…]
 *
 * so the opcode lands at payload[2] = frame[6], which is where the firmware
 * reads its selector.  The Windows application sends this for exactly three
 * device packet types — 0x13 LL_CTRL_CONN_UPDATE_IND, 0x14
 * LL_CTRL_CHANNEL_MAP_REQ and 0x2B LL_CTRL_PHY_UPDATE_IND — whose LL opcodes
 * are 0x00, 0x01 and 0x18, matching the firmware's three selectors.
 *
 * The Windows sender does not read a response, so neither do we.
 *
 * Caller must pass a PDU whose opcode is at pdu[2]; a control PDU carrying a
 * CTE Info byte shifts the opcode to pdu[3] and must NOT be relayed verbatim.
 * See the guard in on_packet().
 *
 * Returns 0 on success, negative libusb error otherwise.
 */
int wch_send_ll_update(wch_device_t *dev, const uint8_t *pdu, int pdu_len) {
  uint8_t frame[4 + 64];

  if (!dev || !dev->is_open || !pdu)
    return LIBUSB_ERROR_INVALID_PARAM;
  /* Need at least [hdr0][len][opcode]; cap at what one frame can carry. */
  if (pdu_len < 3 || pdu_len > (int)sizeof(frame) - 4)
    return LIBUSB_ERROR_INVALID_PARAM;

  frame[0] = WCH_MAGIC;
  frame[1] = CMD_LL_UPDATE;
  frame[2] = (uint8_t)(pdu_len & 0xFF);
  frame[3] = (uint8_t)((pdu_len >> 8) & 0xFF);
  memcpy(frame + 4, pdu, (size_t)pdu_len);

  int r = bulk_write(dev, frame, 4 + pdu_len);
  return (r == LIBUSB_ERROR_TIMEOUT) ? 0 : r;
}

/* ── wch_park_advertising ─────────────────────────────────────────────────
 *
 * Return one MCU to advertising monitoring: advertising Access Address and
 * CRCInit, on @ble_channel, with the presence bits set so the firmware
 * actually copies them.  Used after a followed connection ends, and any time a
 * radio needs rescuing from a stale connection Access Address.
 *
 * Returns 0 if the device's config read-back confirms the advertising values,
 * 1 if the command was sent but the read-back disagreed or was missing, or a
 * negative libusb error.
 */
int wch_park_advertising(wch_device_t *dev, uint8_t phy, uint8_t ble_channel) {
  uint8_t frame[64], resp[64];
  int got = 0, r;

  if (!dev || !dev->is_open)
    return LIBUSB_ERROR_INVALID_PARAM;

  memset(frame, 0, sizeof(frame));
  frame[0] = WCH_MAGIC;
  frame[1] = CMD_BLE_CONFIG;
  frame[2] = 0x19;
  frame[3] = 0x00;
  frame[4] = F81_START | F81_AA_VALID | F81_CRC_VALID;
  if (ble_channel)
    frame[4] |= F81_CHANNEL;
  frame[5] = phy ? phy : 1;
  frame[6] = ble_channel;
  memcpy(frame + 15, ADV_AA_BYTES, 4);
  memcpy(frame + 19, ADV_CRCINIT, 3);

  r = bulk_write(dev, frame, 4 + 25);
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  /* Drain whatever the config write shook loose before asking for the echo. */
  bulk_read(dev, resp, sizeof(resp), &got, 100);

  uint8_t a1[4] = {WCH_MAGIC, CMD_SCAN_START, 0x00, 0x00};
  r = bulk_write(dev, a1, sizeof(a1));
  if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
    return r;

  /* The echo can arrive behind a few packet frames; look for it briefly. */
  for (int i = 0; i < 8; i++) {
    got = 0;
    r = bulk_read(dev, resp, sizeof(resp), &got, 200);
    if (r != 0 || got <= 0)
      continue;
    if (resp[0] == 0x55 && resp[1] == 0x01)
      return echo_matches(resp, got, ADV_AA_BYTES, ADV_CRCINIT) ? 0 : 1;
  }
  return 1;
}

int wch_stop_capture(wch_device_t *dev) {
  /*
   * No confirmed stop command yet.  Closing the USB interface effectively
   * stops the stream.  Sending an empty AA A1 again seems harmless.
   */
  uint8_t frame[4] = {WCH_MAGIC, CMD_SCAN_START, 0x00, 0x00};
  int r = bulk_write(dev, frame, sizeof(frame));
  return (r == LIBUSB_ERROR_TIMEOUT) ? 0 : r;
}

/* ── wch_read_packets ────────────────────────────────────────────────────── */

/*
 * Reads one USB bulk transfer from EP 0x82 and decodes all device frames
 * found in the buffer.
 *
 * Device frame format:
 *   [0x55][type][len_lo][len_hi][payload…]
 *
 * type=0x10: BLE data packet – decoded and reported via callback.
 * type=0x01: status echo     – silently skipped.
 * other:     resync one byte.
 *
 * Returns number of decoded packets (≥0) or negative libusb error.
 * LIBUSB_ERROR_TIMEOUT is treated as 0 (normal when no packets arrive).
 */
int wch_read_packets(wch_device_t *dev, uint8_t *buf, wch_packet_cb_t cb,
                     void *user_ctx, int timeout_ms) {
  int xfer = 0;
  int r = libusb_bulk_transfer(dev->handle, EP_BULK_IN, buf, BULK_TRANSFER_SIZE,
                               &xfer, timeout_ms);
  if (r == LIBUSB_ERROR_TIMEOUT)
    return 0;
  if (r != 0)
    return r;
  if (xfer < 4)
    return 0;

  int decoded = 0;
  int offset = 0;

  while (offset + 4 <= xfer) {
    if (buf[offset] != FRAME_MAGIC) {
      offset++;
      continue;
    }

    uint8_t ftype = buf[offset + 1];
    uint16_t plen =
        (uint16_t)buf[offset + 2] | ((uint16_t)buf[offset + 3] << 8);
    int frame_size = 4 + (int)plen;

    if (offset + frame_size > xfer)
      break; /* truncated frame – wait for more data */

    /* Status echo: skip silently */
    if (ftype == FRAME_TYPE_STS) {
      offset += frame_size;
      dev->err_count++;
      continue;
    }

    /* Unknown type: skip */
    if (ftype != FRAME_TYPE_DATA) {
      offset++;
      continue;
    }

    /* Data frame: need at least MIN_DATA_PAYLOAD bytes of payload */
    if (plen < MIN_DATA_PAYLOAD) {
      offset += frame_size;
      continue;
    }

    const uint8_t *p = buf + offset + 4; /* payload start */

    uint8_t channel = p[4];
    if (channel > 39) {
      offset += frame_size;
      continue;
    }

    uint32_t ts32 = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    uint8_t flags = p[5];
    int8_t rssi = (int8_t)p[8];
    uint8_t pdu_hdr0 = p[10];
    uint8_t pdu_plen = p[11];
    uint8_t pkt_type_ble = pdu_hdr0 & 0x0F; /* BLE LL PDU type */

    /* Extend 32-bit device timestamp to 64-bit */
    if (ts32 < dev->ts_prev_us)
      dev->ts_hi_us += UINT64_C(0x100000000);
    uint64_t ts64 = dev->ts_hi_us | ts32;
    uint64_t dt = ts64 - (dev->ts_hi_us | dev->ts_prev_us);
    dev->ts_prev_us = ts32;

    /* Build wch_pkt_hdr_t */
    wch_pkt_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.rssi = rssi;
    hdr.pkt_type = pkt_type_ble;
    hdr.direction = flags & 0x01; /* 0=M→S, 1=S→M */
    /* Determine if this is a Data Channel frame.
     *
     * The WCH hardware updates `channel_index` to the physical data channel.
     * Since advertising channels are strictly 37, 38, 39, anything <= 36
     * is definitively a Data Channel packed.
     *
     * We also guard on `g_following` so that we never assign the connection AA
     * before we have actually seen a CONNECT_IND (avoids false positives).
     */
    bool is_data_ch = (channel <= 36);
    hdr.access_addr = (is_data_ch && g_following) ? g_follow_aa : BLE_ADV_AA;
    hdr.channel_index = channel;
    hdr.timestamp_us = ts64;
    hdr.interval_us = dt;
    hdr.pkt_index = dev->pkt_seq++;

    /* src_addr = first address in PDU payload (AdvA or ScanA) */
    memcpy(hdr.src_addr, p + 12, 6);

    /* dst_addr = second address (AdvA for SCAN_REQ / CONNECT_IND) */
    if ((pkt_type_ble == PKT_SCAN_REQ || pkt_type_ble == PKT_CONNECT_REQ) &&
        pdu_plen >= 12 && plen >= 18 + 6)
      memcpy(hdr.dst_addr, p + 18, 6);

    /* BLE LL PDU for callback: [pdu_hdr0][pdu_plen][PDU payload…] */
    const uint8_t *pdu = p + 10;
    int pdu_len = 2 + (int)pdu_plen;

    dev->rx_count++;
    if (cb)
      cb(&hdr, pdu, pdu_len, user_ctx);

    decoded++;
    offset += frame_size;
  }

  return decoded;
}

/* ── Utility ────────────────────────────────────────────────────────────────
 */

const char *wch_pkt_type_name(uint8_t pkt_type) {
  switch (pkt_type) {
  case PKT_ADV_IND:
    return "ADV_IND";
  case PKT_ADV_DIRECT_IND:
    return "ADV_DIRECT_IND";
  case PKT_ADV_NONCONN_IND:
    return "ADV_NONCONN_IND";
  case PKT_SCAN_REQ:
    return "SCAN_REQ";
  case PKT_SCAN_RSP:
    return "SCAN_RSP";
  case PKT_CONNECT_REQ:
    return "CONNECT_REQ";
  case PKT_ADV_SCAN_IND:
    return "ADV_SCAN_IND";
  case PKT_AUX_SCAN_REQ:
    return "AUX_SCAN_REQ";
  case PKT_AUX_CONNECT_REQ:
    return "AUX_CONNECT_REQ";
  case PKT_AUX_COMMON:
    return "AUX_COMMON";
  case PKT_AUX_ADV_IND:
    return "AUX_ADV_IND";
  case PKT_AUX_SCAN_RSP:
    return "AUX_SCAN_RSP";
  case PKT_AUX_SYNC_IND:
    return "AUX_SYNC_IND";
  case PKT_AUX_CONNECT_RSP:
    return "AUX_CONNECT_RSP";
  case PKT_AUX_CHAIN_IND:
    return "AUX_CHAIN_IND";
  case PKT_DATA_PDU_RESERVED:
    return "DATA_PDU_RESERVED";
  case PKT_DATA_PDU_EMPORCON:
    return "DATA_PDU_CONT";
  case PKT_DATA_PDU_DATA:
    return "DATA_PDU_DATA";
  case PKT_DATA_PDU_CONTROL:
    return "DATA_PDU_CTRL";
  case PKT_LL_CTRL_CONN_UPDATE_IND:
    return "LL_CONN_UPDATE_IND";
  case PKT_LL_CTRL_TERMINATE_IND:
    return "LL_TERMINATE_IND";
  case PKT_CRC_ERR:
    return "CRC_ERR";
  case PKT_MISS:
    return "PKT_MISS";
  case PKT_LL_EMPTY:
    return "LL_EMPTY";
  default: {
    static char buf[8];
    snprintf(buf, sizeof(buf), "0x%02X", pkt_type);
    return buf;
  }
  }
}

void wch_mac_to_str(const uint8_t mac[6], char out[18]) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[5], mac[4], mac[3],
           mac[2], mac[1], mac[0]);
}

void wch_print_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu,
                      int pdu_len) {
  char src[18], dst[18];
  wch_mac_to_str(hdr->src_addr, src);
  wch_mac_to_str(hdr->dst_addr, dst);

  printf("[%12llu us] ch%02u  %-22s  rssi %4d dBm  AA %08X  %s",
         (unsigned long long)hdr->timestamp_us, hdr->channel_index,
         wch_pkt_type_name(hdr->pkt_type), (int)hdr->rssi, hdr->access_addr,
         src);

  if (hdr->pkt_type == PKT_SCAN_REQ || hdr->pkt_type == PKT_CONNECT_REQ)
    printf("→%s", dst);

  if (pdu && pdu_len > 0) {
    int show = (pdu_len < 24) ? pdu_len : 24;
    printf("  PDU[%d]:", pdu_len);
    for (int i = 0; i < show; i++)
      printf(" %02x", pdu[i]);
    if (pdu_len > show)
      printf(" ...");
  }
  putchar('\n');
}
