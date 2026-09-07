/*
 * wch_capture – CLI BLE packet capture tool for the WCH BLE Analyzer Pro
 *
 * _POSIX_C_SOURCE 200112L is required for sigaction(2) under -std=c11.
 */
#define _POSIX_C_SOURCE 200112L

/*
 *
 * Usage:
 *   wch_capture [OPTIONS]
 *
 * Options:
 *   -v            Verbose: print every packet to stdout
 *   -w FILE.pcap  Write captured packets to a PCAP file
 *   -p PHY        PHY mode: 1=1M (default), 2=2M, 3=CodedS8, 4=CodedS2
 *   -i ADDR       Initiator MAC filter  (e.g. AA:BB:CC:DD:EE:FF)
 *   -a ADDR       Advertiser MAC filter (e.g. AA:BB:CC:DD:EE:FF)
 *   -k KEY        LTK for decryption    (32 hex chars)
 *   -K PASSKEY    BLE pass key (6-digit decimal)
 *   -2            Custom 2.4G mode (default: BLE monitor)
 *   -c CHAN       2.4G channel 0-39     (default 37)
 *   -A AADDR      2.4G access address   (hex, e.g. 8E89BED6)
 *   -C CRCINIT    2.4G CRC init         (6 hex chars, e.g. 555555)
 *   -W WHITEN     2.4G whitening init   (hex byte)
 *   -h            Show this help
 *
 * Signals:
 *   SIGINT / SIGTERM   Stop capture and exit cleanly.
 *
 * PCAP output uses DLT_BLUETOOTH_LE_LL_WITH_PHDR (256), which Wireshark
 * decodes natively.  The pseudo-header is 10 bytes:
 *
 *   uint8_t  rf_channel          (0-39)
 *   int8_t   signal_power        (RSSI dBm, or 0x80 = invalid)
 *   int8_t   noise_power         (0x80 = invalid)
 *   uint8_t  access_address_offenses
 *   uint32_t reference_access_address (LE)
 *   uint16_t flags               (LE)
 *
 * Flags bit assignments (Wireshark packet-btle.h):
 *   bit 0: DEWHITENED      – data already de-whitened by hardware (MUST be 1)
 *   bit 1: SIGPOWER_VALID  – signal_power field is valid
 *   bit 2: NOISE_VALID     – noise_power field is valid
 *   bit 3: DECRYPTED       – payload was decrypted
 *   bit 4: REF_AA_VALID    – reference_access_address is valid
 *   bit 5: AA_OFFENSES_VALID
 *   bit 6: LE_PHYS_CODING_VALID
 *   bit 7: MIC_CHECKED_OK
 */

#include "wch_ble_analyzer.h"
#include <errno.h> // Added back as it was in the original and is likely needed
#include <fcntl.h> // Fixed and added back as it was in the original and is likely needed
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <fcntl.h>

// Follow globals for PCAP headers
bool g_following = false;
uint32_t g_follow_aa = 0x8E89BED6;
static uint32_t g_follow_crcinit = 0x555555;

/* Set to true by on_packet when CONNECT_IND is seen.
 * The MAIN LOOP reads this flag and performs the USB reconfig after
 * the current bulk_read returns, avoiding re-entrant USB access. */
static volatile bool g_need_reconfig = false;

FILE *g_debuglog_file = NULL;

#include <pthread.h>

/* ── BLE channel → RF channel conversion ────────────────────────────────── */

/*
 * DLT_BLUETOOTH_LE_LL_WITH_PHDR rf_channel field is the PHYSICAL RF channel
 * index where 0 = 2402 MHz, 1 = 2404 MHz, ..., n = 2402+2n MHz.
 * This is NOT the same as the BLE logical channel index (0-39):
 *   BLE ch 37 → RF ch  0  (2402 MHz, advertising)
 *   BLE ch 38 → RF ch 12  (2426 MHz, advertising)
 *   BLE ch 39 → RF ch 39  (2480 MHz, advertising)
 *   BLE ch  0 → RF ch  1  (2404 MHz, data)
 *   BLE ch 1-10 → RF ch 2-11
 *   BLE ch 11-36 → RF ch 13-38
 */
static uint8_t ble_ch_to_rf_ch(uint8_t ch) {
  if (ch == 37)
    return 0;
  if (ch == 38)
    return 12;
  if (ch == 39)
    return 39;
  if (ch <= 10)
    return ch + 1;
  return ch + 2;
}

/* ── BLE CRC-24 ─────────────────────────────────────────────────────────── */

/*
 * BLE uses CRC-24 with polynomial x^24+x^10+x^9+x^6+x^4+x^3+x+1 (= 0x65B),
 * processed LSB-first (reflected polynomial = 0xDA6000).
 * Advertising channel CRC init: 0x555555.
 * CRC covers the PDU only (not the access address).
 */
static uint32_t ble_crc24(uint32_t init, const uint8_t *buf, int len) {
  uint32_t lfsr = init & 0xFFFFFF;
  for (int i = 0; i < len; i++) {
    uint8_t byte = buf[i];
    for (int j = 0; j < 8; j++) {
      int in = (byte ^ (int)lfsr) & 1;
      lfsr >>= 1;
      byte >>= 1;
      if (in)
        lfsr ^= 0xDA6000u; /* reflected BLE polynomial */
    }
  }
  return lfsr;
}

/* ── PCAP file format ───────────────────────────────────────────────────── */

#define PCAP_MAGIC 0xa1b2c3d4u
#define PCAP_VERSION_MAJ 2
#define PCAP_VERSION_MIN 4
#define PCAP_SNAPLEN 65535
#define PCAP_DLT_BLE_LL_WITH_PHDR 256 /* Wireshark DLT for BLE LL + phdr */

#pragma pack(push, 1)
typedef struct {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_file_hdr_t;

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} pcap_rec_hdr_t;

/* DLT_BLUETOOTH_LE_LL_WITH_PHDR pseudo-header (10 bytes) */
typedef struct {
  uint8_t rf_channel;
  int8_t signal_power;
  int8_t noise_power;
  uint8_t access_address_offenses;
  uint32_t reference_access_address;
  uint16_t flags;
} ble_phdr_t;
#pragma pack(pop)

/* ── Globals ────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig) {
  (void)sig;
  g_stop = 1;
}

static FILE *g_pcap_file = NULL;
static bool g_verbose = false;
static uint64_t g_pkt_count = 0;
static uint8_t g_phy = PHY_1M;

/* FIFO and Wireshark */
static bool g_use_fifo = false;
static char *g_fifo_name = "/tmp/blepipe";
static bool g_launch_ws = false;

/* globals for Host-Side Connection Frequency Hopping */
static pthread_t g_hop_thread;
/*
 * Connection interval in µs.  MUST be 32-bit: this used to be a uint16_t,
 * which silently truncated any interval above 52 units (65.535 ms).  Phones
 * routinely move a connection to 100–500 ms with LL_CONNECTION_UPDATE_IND,
 * so the apply-at-Instant path below would otherwise be unusable at exactly
 * the intervals it exists to handle.
 */
static uint32_t g_hop_interval_us = 0;
static uint8_t g_hop_increment = 0;
static uint64_t g_channel_map = 0;
static uint8_t g_last_unmapped_ch = 0;
static uint8_t g_remapped_channels[37];
static int g_num_used_channels = 0;
static wch_device_t *g_devs_ptr = NULL;
static int g_ndevs = 0;
static wch_capture_config_t g_active_cfg;
static uint32_t g_win_offset_us = 0; /* WinOffset * 1250 µs */
static uint64_t g_conn_req_hw_ts = 0;
static uint64_t g_active_host_hw_offset_us = 0;

/*
 * ── Follow-mode radio assignment ──────────────────────────────────────────
 *
 * By default only ONE MCU follows a connection onto the data channels.  The
 * remaining MCUs stay parked on the advertising channel they were started on,
 * so advertising traffic keeps being captured while a connection is followed.
 * Retuning all three MCUs to the same data channel is redundant: it triplicates
 * every connection packet in the pcap and blinds the tool to advertising.
 *
 * g_follow_dev_idx indexes g_devs_ptr[].  It is written by on_packet() before
 * pthread_create() spawns hop_thread_func(), and thread creation establishes
 * happens-before ordering, so the hop thread observes the final value.
 */
static int g_follow_dev_idx = -1;        /* -1 = no MCU chosen yet          */
static uint8_t g_follow_vacated_ch = 0;  /* adv channel the follower left   */
static bool g_follow_all_radios = false; /* -F: legacy all-MCUs-follow mode */

/*
 * -R: relay LL_CONNECTION_UPDATE_IND / LL_CHANNEL_MAP_IND / LL_PHY_UPDATE_IND
 * to the follower MCU with the AA 82 command, so its firmware can apply the
 * new parameters at the Instant.  Experimental: the frame format is confirmed
 * from BleAnalyzer64.exe, but that the CH582F acts on it in this tool's
 * configuration is not verified on the wire.
 */
static bool g_relay_ll_updates = false;
static uint64_t g_relay_count = 0;

/*
 * -B: set the AA 81 field-validity flag bits 0x10 (Access Address) and 0x20
 * (CRCInit).  Read by wch_reconfig_capture() in wch_ble_analyzer.c, hence
 * non-static.
 */
bool g_aa81_mark_fields = true;

/*
 * Re-park state.  A followed connection must be handed back so the follower
 * MCU returns to advertising; without this it keeps a stale connection Access
 * Address and hears nothing at all, permanently.
 */
static volatile bool g_need_repark = false; /* set by on_packet, done in main */
static volatile bool g_hop_running = false; /* hop thread liveness            */
static uint8_t g_follow_phy = PHY_1M;

/*
 * ── Channel Selection Algorithm state ─────────────────────────────────────
 *
 * --csa 1|2|auto.  "auto" (the default) takes the algorithm from the ChSel
 * bit of the CONNECT_IND, which is sufficient on its own: per Core Spec
 * Vol 6 Part B §4.5.8.1 an initiator sets ChSel in CONNECT_IND only when the
 * advertiser advertised ChSel=1, so the single bit already encodes "both ends
 * support CSA#2".  The peripheral makes the same decision from the same bit
 * and nothing else (cf. Zephyr ull_peripheral.c, which sets data_chan_sel
 * straight from pdu_adv->chan_sel).  We therefore do not track the ChSel bit
 * of preceding ADV_IND/ADV_DIRECT_IND PDUs.
 */
#define CSA_AUTO 0
#define CSA_FORCE_1 1
#define CSA_FORCE_2 2
static int g_csa_force = CSA_AUTO;
static bool g_use_csa2 = false; /* resolved once, at CONNECT_IND */
static uint16_t g_chan_id = 0;  /* CSA#2 channelIdentifier            */

/*
 * Connection event counter.  0 is the first connection event, i.e. the event
 * containing the anchor point, and it wraps naturally at 2^16.
 *
 * CSA#2 is a pure function of this counter, so an event the host misses
 * costs nothing: the next computed channel is still correct.  CSA#1 by
 * contrast carries incremental state (g_last_unmapped_ch) that must be
 * stepped once per event whether or not the event was observed, which is why
 * the fast-forward path below has to advance the channel math at all.
 */
static uint16_t g_conn_event_counter = 0;

/*
 * ── Pending LL updates, applied host-side at their Instant ────────────────
 *
 * The host drives every retune, so an LL_CHANNEL_MAP_IND or
 * LL_CONNECTION_UPDATE_IND that the host does not apply desyncs the follower
 * permanently, for both algorithms.  Relaying the PDU to the MCU (-R) does
 * not help here: the host still sends an explicit channel with every AA 81
 * retune, so whatever the firmware decides is overridden.
 *
 * on_packet() (USB reader thread) only deposits into these slots, writing the
 * _valid flag last; hop_thread_func() is the sole writer of the live
 * parameters.  That keeps the active channel map single-writer.
 */
static uint64_t g_pending_map = 0;
static uint16_t g_pending_map_instant = 0;
static volatile bool g_pending_map_valid = false;

static uint32_t g_pending_cu_interval_us = 0;
static uint32_t g_pending_cu_win_offset_us = 0;
static uint16_t g_pending_cu_instant = 0;
static volatile bool g_pending_cu_valid = false;

/* ── BLE Channel Selection Algorithm #2 ───────────────────────────────────
 *
 * Core Spec 5.x Vol 6, Part B, §4.5.8.3.  Cross-checked against Zephyr's
 * lll_chan.c (chan_perm / chan_mam / chan_prn_e / lll_chan_sel_2); see
 * csa2_test.c for the vectors.  Subevents / PAwR (§4.5.8.3.4 onwards) are
 * deliberately not implemented — this tool follows ACL connections only.
 */

/* permutation(): reverse the bit order within each octet of a 16-bit word. */
static inline uint8_t csa2_rev8(uint8_t b) {
  b = (uint8_t)(((b & 0xF0u) >> 4) | ((b & 0x0Fu) << 4));
  b = (uint8_t)(((b & 0xCCu) >> 2) | ((b & 0x33u) << 2));
  b = (uint8_t)(((b & 0xAAu) >> 1) | ((b & 0x55u) << 1));
  return b;
}

static inline uint16_t csa2_perm(uint16_t v) {
  return (uint16_t)(((uint16_t)csa2_rev8((uint8_t)(v >> 8)) << 8) |
                    csa2_rev8((uint8_t)(v & 0xFFu)));
}

/* MAM(): multiply-add-modulo, a*17 + b mod 2^16. */
static inline uint16_t csa2_mam(uint16_t a, uint16_t b) {
  return (uint16_t)(((uint32_t)a * 17u + (uint32_t)b) & 0xFFFFu);
}

/* prn_e: three rounds of perm()/MAM() over counter^chan_id, then ^chan_id. */
static uint16_t csa2_prn_e(uint16_t counter, uint16_t chan_id) {
  uint16_t v = (uint16_t)(counter ^ chan_id);
  for (int i = 0; i < 3; i++) {
    v = csa2_perm(v);
    v = csa2_mam(v, chan_id);
  }
  return (uint16_t)(v ^ chan_id);
}

/* channelIdentifier = AA[31:16] XOR AA[15:0], read from wire-order bytes. */
static inline uint16_t csa2_chan_id(const uint8_t aa_le[4]) {
  uint16_t lo = (uint16_t)(aa_le[0] | ((uint16_t)aa_le[1] << 8));
  uint16_t hi = (uint16_t)(aa_le[2] | ((uint16_t)aa_le[3] << 8));
  return (uint16_t)(hi ^ lo);
}

/* Rebuild the sorted used-channel table from a 37-bit channel map. */
static void conn_set_channel_map(uint64_t map) {
  g_channel_map = map & UINT64_C(0x1FFFFFFFFF);
  g_num_used_channels = 0;
  for (int i = 0; i < 37; i++) {
    if (g_channel_map & (1ULL << i))
      g_remapped_channels[g_num_used_channels++] = (uint8_t)i;
  }
}

/* CSA#2 data channel for one connection event.  Pure function of counter. */
static uint8_t csa2_channel(uint16_t counter) {
  uint16_t prn_e = csa2_prn_e(counter, g_chan_id);
  uint8_t ch = (uint8_t)(prn_e % 37u);

  if (!(g_channel_map & (1ULL << ch))) {
    if (g_num_used_channels <= 0)
      return 0;
    /* remappingIndex = (N * prn_e) / 2^16, always < N. */
    unsigned idx =
        (unsigned)(((uint32_t)g_num_used_channels * (uint32_t)prn_e) >> 16);
    if (idx >= (unsigned)g_num_used_channels)
      idx = (unsigned)g_num_used_channels - 1u; /* unreachable; belt & braces */
    ch = g_remapped_channels[idx];
  }
  return ch;
}

/*
 * CSA#1 step: advance lastUnmapped by hopIncrement and remap.  Must be called
 * exactly once per connection event, including events the host missed.
 */
static uint8_t csa1_next_channel(void) {
  g_last_unmapped_ch = (uint8_t)((g_last_unmapped_ch + g_hop_increment) % 37);
  uint8_t ch = g_last_unmapped_ch;
  if (!(g_channel_map & (1ULL << ch))) {
    if (g_num_used_channels > 0)
      ch = g_remapped_channels[g_last_unmapped_ch % g_num_used_channels];
    else
      ch = 0;
  }
  return ch;
}

/*
 * Wrap-safe "counter is at or after instant" test (Core Spec Vol 6 Part B
 * §5.1.1: the Instant is a 16-bit event counter with modulo comparison).
 * Using == would lose the update outright if the host's counter ever skipped
 * past it, leaving the follower on a stale map with no error.
 */
static inline bool instant_reached(uint16_t counter, uint16_t instant) {
  return (uint16_t)(counter - instant) < 0x8000u;
}

static inline uint8_t wch_ble_channel_to_rf_index(uint8_t ble_ch) {
  if (ble_ch == 37)
    return 0;
  if (ble_ch == 38)
    return 12;
  if (ble_ch == 39)
    return 39;
  if (ble_ch <= 10)
    return ble_ch + 1;
  return ble_ch + 2;
}

/*
 * Apply any pending LL update whose Instant has been reached.  Called from
 * the hop thread only, with g_conn_event_counter already stepped to the event
 * being scheduled and *anchor_hw_us already holding that event's anchor under
 * the OLD parameters.
 */
static void hop_apply_pending_updates(uint64_t *anchor_hw_us) {
  if (g_pending_map_valid &&
      instant_reached(g_conn_event_counter, g_pending_map_instant)) {
    g_pending_map_valid = false;
    conn_set_channel_map(g_pending_map);
    fprintf(stderr,
            "[hop] LL_CHANNEL_MAP_IND applied at event %u: map=0x%010llX "
            "(%d used channels)\n",
            g_conn_event_counter, (unsigned long long)g_channel_map,
            g_num_used_channels);
  }

  if (g_pending_cu_valid &&
      instant_reached(g_conn_event_counter, g_pending_cu_instant)) {
    g_pending_cu_valid = false;
    /*
     * Core Spec Vol 6 Part B §4.5.1: the connection event at the Instant
     * starts one transmitWindowDelay (1.25 ms on an uncoded PHY) plus
     * WinOffset after the anchor the old interval would have given, and the
     * new interval applies from that event onwards.
     */
    *anchor_hw_us += 1250u + g_pending_cu_win_offset_us;
    g_hop_interval_us = g_pending_cu_interval_us;
    fprintf(stderr,
            "[hop] LL_CONNECTION_UPDATE_IND applied at event %u: "
            "interval=%u us, WinOffset=%u us\n",
            g_conn_event_counter, g_hop_interval_us,
            g_pending_cu_win_offset_us);
  }
}

/*
 * Step to the next connection event: advance the anchor, the event counter,
 * any Instant-gated parameter change, and the staged channel.  Called once
 * per event from both the on-time and the fast-forward paths, so the channel
 * math never drifts relative to the counter.
 */
static void hop_advance_event(uint64_t *anchor_hw_us) {
  /* Anchor of the next event under the parameters currently in force. */
  *anchor_hw_us += g_hop_interval_us;
  g_conn_event_counter++;
  hop_apply_pending_updates(anchor_hw_us);

  uint8_t next_ch =
      g_use_csa2 ? csa2_channel(g_conn_event_counter) : csa1_next_channel();
  g_active_cfg.ble_channel = next_ch;
  g_active_cfg.channel = wch_ble_channel_to_rf_index(next_ch);
}

static void *hop_thread_func(void *arg) {
  (void)arg;
  g_hop_running = true;

  /*
   * Start our HW-time anchor precisely at the hardware's
   * timestamp of the CONNECT_IND packet plus the WinOffset.
   */
  uint64_t next_hop_hw_us = g_conn_req_hw_ts + g_win_offset_us;
  bool is_event_0 = true;

  while (g_following && !g_stop) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t host_now_us = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;

    /* Map the hardware anchor to the current host monotonic timeline */
    uint64_t abs_next_hop_host_us = next_hop_hw_us + g_active_host_hw_offset_us;
    int64_t diff_us = (int64_t)(abs_next_hop_host_us - host_now_us);

    if (diff_us < 0) {
      /* Event is in the past! We missed the window entirely (USB latency).
       * Fast-Forward the channel math to the next interval without hitting USB.
       */
      hop_advance_event(&next_hop_hw_us);

      if (is_event_0) {
        fprintf(
            stderr,
            "[hop] Event 0 MISSED (diff %lld us), fast-forwarding math...\n",
            (long long)diff_us);
        is_event_0 = false;
      }
      continue;
    }

    /* We are on time. Calculate how long to sleep before firing the command.
     * Give the USB stack and MCU a lead time. Cap it at min(15ms, interval/2).
     */
    int64_t lead_us = g_hop_interval_us / 2;
    if (lead_us > 15000LL)
      lead_us = 15000LL;

    int64_t sleep_us = diff_us - lead_us;

    if (sleep_us > 0)
      usleep((useconds_t)sleep_us);

    if (!g_following || g_stop)
      break;

    /* Issue retune for the currently scheduled channel.
     * Unless -F was given, only the follower MCU is retuned; the others keep
     * their advertising-channel configuration untouched. */
    for (int i = 0; i < g_ndevs; i++) {
      if (!g_devs_ptr[i].is_open)
        continue;
      if (!g_follow_all_radios && i != g_follow_dev_idx)
        continue;
      wch_reconfig_capture(&g_devs_ptr[i], &g_active_cfg);
    }

    if (is_event_0) {
      fprintf(stderr,
              "[hop] Event 0: scheduled BLE ch %d (WinOffset %lld us diff)\n",
              g_active_cfg.ble_channel, (long long)diff_us);
      is_event_0 = false;
    }

    /* Stage the next connection event: anchor, counter, pending LL updates
     * and the channel from the selected algorithm (CSA#1 or CSA#2). */
    hop_advance_event(&next_hop_hw_us);
  }
  g_hop_running = false;
  return NULL;
}

/* ── PCAP helpers ─────────────────────────────────────────────────────────
 */

static bool pcap_open(const char *path, bool is_fifo) {
  if (is_fifo) {
    if (access(path, F_OK) == -1) {
      if (mkfifo(path, 0666) != 0) {
        perror("mkfifo");
        return false;
      }
    }
  }
  g_pcap_file = fopen(path, "wb");
  if (!g_pcap_file) {
    perror(path);
    return false;
  }

  pcap_file_hdr_t fh = {
      .magic = PCAP_MAGIC,
      .version_major = PCAP_VERSION_MAJ,
      .version_minor = PCAP_VERSION_MIN,
      .thiszone = 0,
      .sigfigs = 0,
      .snaplen = PCAP_SNAPLEN,
      .network = PCAP_DLT_BLE_LL_WITH_PHDR,
  };
  fwrite(&fh, sizeof(fh), 1, g_pcap_file);
  fflush(g_pcap_file);
  return true;
}

static void pcap_write_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu,
                              int pdu_len) {
  if (!g_pcap_file)
    return;

  /*
   * Build the BLE LL pseudo-header.
   * DEWHITENED (0x0001) MUST be set: the CH582F hardware de-whitens all
   * received PDUs before sending them over USB.  Without this bit Wireshark
   * would try to re-apply whitening, producing garbled PDU type fields.
   * SIGPOWER_VALID (0x0002): RSSI from device is always valid.
   * REF_AA_VALID   (0x0010): reference_access_address is valid.
   *
   * reference_access_address MUST be derived per packet from hdr->access_addr,
   * never from the global g_following flag.  In split-follow mode advertising
   * packets and connection packets are interleaved in the same pcap, so a
   * global choice would stamp the connection's AA onto advertising frames.
   */
  uint16_t flags = 0x0001    /* DEWHITENED      */
                   | 0x0002  /* SIGPOWER_VALID  */
                   | 0x0010; /* REF_AA_VALID    */

  ble_phdr_t ph = {
      .rf_channel = ble_ch_to_rf_ch(hdr->channel_index),
      .signal_power = (int8_t)hdr->rssi,
      .noise_power = (int8_t)0x80, /* unknown */
      .access_address_offenses = 0,
      .reference_access_address = hdr->access_addr,
      .flags = flags,
  };

  /*
   * Use wall-clock time for pcap timestamps so that packets from all three
   * MCUs have monotonically increasing, comparable timestamps.  The device's
   * own 32-bit μs clock (hdr->timestamp_us) is per-MCU-boot and cannot be
   * compared across devices without synchronisation.
   */
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  uint32_t ts_sec = (uint32_t)now.tv_sec;
  uint32_t ts_usec = (uint32_t)(now.tv_nsec / 1000);

  /*
   * Per pcap-linktype(7) for LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256),
   * the packet data after the 10-byte PHDR is:
   *   [Access Address 4 B] [BLE LL PDU 2+N B] [CRC 3 B]
   * Wireshark uses the Access Address to determine advertising vs. data
   * channel and routes to the correct dissector.
   */
  uint32_t aa_le = hdr->access_addr; /* already LE uint32 */

  /* Compute BLE CRC-24 over the PDU bytes.
   * If the frame's Access Address is the Adv AA, use standard CRC.
   * Otherwise, use the dynamic Connection CRC.
   */
  bool is_adv_frame = (hdr->access_addr == 0x8E89BED6);
  uint32_t crc_val =
      ble_crc24(is_adv_frame ? 0x555555 : g_follow_crcinit, pdu, pdu_len);
  uint8_t crc[3] = {
      (uint8_t)(crc_val),
      (uint8_t)(crc_val >> 8),
      (uint8_t)(crc_val >> 16),
  };

  uint32_t data_len = (uint32_t)(sizeof(ph) + 4 + pdu_len + 3);

  pcap_rec_hdr_t rh = {
      .ts_sec = ts_sec,
      .ts_usec = ts_usec,
      .incl_len = data_len,
      .orig_len = data_len,
  };

  fwrite(&rh, sizeof(rh), 1, g_pcap_file);
  fwrite(&ph, sizeof(ph), 1, g_pcap_file);
  fwrite(&aa_le, 4, 1, g_pcap_file); /* access address */
  if (pdu && pdu_len > 0)
    fwrite(pdu, 1, pdu_len, g_pcap_file); /* BLE LL PDU     */
  fwrite(crc, 3, 1, g_pcap_file);         /* CRC-24         */
  fflush(g_pcap_file); /* ensure each complete record hits disk */
}

/* ── Packet callback ──────────────────────────────────────────────────────
 */

struct cb_ctx {
  wch_device_t *dev;  /* this MCU */
  wch_device_t *devs; /* all MCUs */
  int ndev;           /* MCU count */
  wch_capture_config_t *cfg;
};

static void on_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu, int pdu_len,
                      void *ctx_arg) {
  struct cb_ctx *cctx = (struct cb_ctx *)ctx_arg;
  wch_capture_config_t *cfg = cctx ? cctx->cfg : NULL;
  wch_device_t *dev = cctx ? cctx->dev : NULL;

  if (g_debuglog_file) {
    fprintf(g_debuglog_file,
            "[wch bus=%d addr=%d] CH=%d RSSI=%d TYPE=0x%02X LEN=%d PDU=",
            dev ? dev->bus : 0, dev ? dev->addr : 0, hdr->channel_index,
            hdr->rssi, hdr->pkt_type, pdu_len);
    for (int i = 0; i < pdu_len; i++) {
      fprintf(g_debuglog_file, "%02X", pdu[i]);
    }
    fprintf(g_debuglog_file, "\n");
    fflush(g_debuglog_file);
  }

  /*
   * Phase-Locked Loop (PLL) Time offset compensator.
   * Every valid packet gives us a pair of (Host Now, HW Now) times.
   * Minimum offset perfectly tracks the lowest USB latency, thereby filtering
   * out arbitrary USB bulk-read delays.
   * We track this PER-DEVICE because each MCU has its own independent clock.
   * MUST BE EXECUTED BEFORE ANY FILTER DROPS to keep it primed and accurate!
   */
  if (dev) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t host_now_us = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
    uint64_t current_offset = host_now_us - hdr->timestamp_us;

    if (dev->host_hw_offset_us == 0 ||
        current_offset < dev->host_hw_offset_us) {
      dev->host_hw_offset_us = current_offset;
    }
  }

  /* Auto-follow logic:
   * CONNECT_IND only appears on advertising channels (37/38/39).
   * LL_DATA packets on data channels share the same pkt_type byte value,
   * so we must guard against false positives using the channel index. */
  bool is_adv_channel = (hdr->channel_index == 37 || hdr->channel_index == 38 ||
                         hdr->channel_index == 39);
  if (cfg && cfg->follow_conn && is_adv_channel &&
      hdr->pkt_type == PKT_CONNECT_REQ && !g_following) {
    /*
     * Strict CONNECT_IND validation:
     * 1. pdu[1] MUST be exactly 34 (legacy CONNECT_IND is always
     *    34 bytes: InitA(6)+AdvA(6)+LLData(22)). Anything else is
     *    a corrupt read or a different PDU type.
     * 2. pdu_len must be >= 36 (to safely read pdu[0..35]).
     * 3. If an AdvA filter is configured (-a flag), pdu[8..13] must
     *    match — we only want the connection TO OUR target device.
     */
    bool valid_llength = (pdu_len >= 36 && pdu[1] == 34);
    uint8_t zero_mac[6] = {0};
    bool has_adv_filter = (memcmp(cfg->adv_addr, zero_mac, 6) != 0);
    bool adva_match = !has_adv_filter ||
                      (pdu_len >= 14 && memcmp(pdu + 8, cfg->adv_addr, 6) == 0);
    /*
     * 4. Interval must be within the Core Spec range, 6..3200 units of
     *    1.25 ms (7.5 ms .. 4 s).  A CRC-damaged CONNECT_IND can pass the
     *    length and AdvA checks above, and an interval of 0 would make the
     *    hop thread add nothing to its anchor and spin at 100% CPU forever.
     *    Nothing may set g_following while g_hop_interval_us is 0.
     */
    uint16_t conn_interval =
        (pdu_len >= 36) ? (uint16_t)(pdu[24] | ((uint16_t)pdu[25] << 8)) : 0;
    bool valid_interval = (conn_interval >= 6 && conn_interval <= 3200);
    /*
     * 5. transmitWindowOffset must not exceed connInterval (Core Spec Vol 6
     *    Part B §2.3.3.1: it is a multiple of 1.25 ms in the range 0 to
     *    connInterval).  This is not pedantry.  A corrupt CONNECT_IND seen in
     *    the field carried WinOffset 0x8007 units against an interval of 25,
     *    which is 40.97 s: the hop thread duly scheduled event 0 forty-one
     *    seconds into the future and the followed radio captured nothing at
     *    all until the operator gave up.  Because g_following is a one-shot
     *    latch, one such frame blinds a radio for the rest of the session.
     *    Rejecting it lets the tool wait for the next clean connection.
     *
     * 6. transmitWindowSize is bounded by the spec at min(10 ms,
     *    connInterval - 1.25 ms), but the host never uses it, so the check
     *    here is deliberately looser than the spec: reject only values that
     *    exceed connInterval, which cannot occur in a compliant CONNECT_IND
     *    and so only ever fires on corruption.  A tighter bound would risk
     *    dropping real connections from slightly non-compliant peers for no
     *    benefit.
     */
    uint16_t win_offset =
        (pdu_len >= 36) ? (uint16_t)(pdu[22] | ((uint16_t)pdu[23] << 8)) : 0;
    uint8_t win_size = (pdu_len >= 36) ? pdu[21] : 0;
    bool valid_winoffset = (win_offset <= conn_interval);
    bool valid_winsize = (win_size <= conn_interval);
    if (valid_llength && adva_match && valid_interval && valid_winoffset &&
        valid_winsize) {
      /*
       * CONNECT_IND PDU layout:
       *   pdu[0..1]   = PDU header (type + length)
       *   pdu[2..7]   = InitA  (Initiator MAC, 6 bytes)
       *   pdu[8..13]  = AdvA   (Advertiser MAC, 6 bytes)
       *   pdu[14..35] = LLData (22 bytes) ← what the firmware needs
       *
       * LLData layout:
       *   [14..17] = Access Address (4 bytes)
       *   [18..20] = CRCInit (3 bytes)
       *   [21..35] = WinSize, WinOffset, Interval, Latency, Timeout, ChMap,
       * Hop
       *
       * g_following is a one-shot latch: once the first MCU sets it,
       * all other MCUs skip their CONNECT_IND processing (prevents race where
       * two MCUs detect different connections and overwrite g_follow_aa).
       */
      /* Retain original Little-Endian layout for hardware Access-Address
       * filtering */
      memcpy(cfg->conn_req_data, pdu + 14, 22);

      /* Latch AA and CRCInit */
      memcpy(&g_follow_aa, pdu + 14, 4);
      g_follow_crcinit =
          pdu[18] | ((uint32_t)pdu[19] << 8) | ((uint32_t)pdu[20] << 16);

      /* Calculate Software Hopping parameters (Core Spec 5.0 Vol 6 Part B
       * §4.5.8)
       *
       * CONNECT_IND LLData offsets (relative to pdu[0]):
       *   pdu[21]      = WinSize   (1 byte, units of 1.25 ms)
       *   pdu[22..23]  = WinOffset (2 bytes LE, units of 1.25 ms)
       *   pdu[24..25]  = Interval  (2 bytes LE, units of 1.25 ms)
       *   pdu[30..34]  = ChM       (5 bytes, 37-bit channel map)
       *   pdu[35]      = HopIncrement (5 LSBs) | SCA (3 MSBs)
       */
      g_win_offset_us = (uint32_t)win_offset * 1250;
      g_hop_interval_us = (uint32_t)conn_interval * 1250u;
      g_hop_increment = pdu[35] & 0x1F;

      uint64_t map0 = 0;
      for (int i = 0; i < 5; i++) {
        map0 |= ((uint64_t)pdu[30 + i]) << (i * 8);
      }
      conn_set_channel_map(map0);

      /* A stale pending update from a previous connection must never leak
       * into this one. */
      g_pending_map_valid = false;
      g_pending_cu_valid = false;

      /*
       * Pick the channel selection algorithm.  ChSel is bit 5 (0x20) of the
       * advertising PDU header byte, valid in CONNECT_IND (cf. Wireshark's
       * packet-btle.c, which marks it valid for ADV_IND, ADV_DIRECT_IND and
       * CONNECT_IND on channels >= 37).  See the --csa notes above for why
       * this bit alone is authoritative.
       */
      bool chsel = (pdu[0] & 0x20) != 0;
      if (g_csa_force == CSA_FORCE_1)
        g_use_csa2 = false;
      else if (g_csa_force == CSA_FORCE_2)
        g_use_csa2 = true;
      else
        g_use_csa2 = chsel;

      g_chan_id = csa2_chan_id(pdu + 14); /* AA in wire order */
      g_conn_event_counter = 0;           /* event 0 holds the anchor point */
      g_last_unmapped_ch = 0;             /* CSA#1 lastUnmapped starts at 0 */

      /*
       * Channel of connection event 0.  For CSA#1 this steps lastUnmapped
       * from 0 to hopIncrement, exactly as the per-event step does; for CSA#2
       * it is the pure function of counter 0.
       */
      uint8_t first_ch =
          g_use_csa2 ? csa2_channel(0) : csa1_next_channel();

      g_active_cfg = *cfg;
      g_active_cfg.ble_channel = first_ch;
      g_active_cfg.channel = wch_ble_channel_to_rf_index(first_ch);

      /*
       * Choose the MCU that will follow this connection: the one that saw the
       * CONNECT_IND.  g_conn_req_hw_ts is expressed in that MCU's hardware
       * clock, so following it keeps the anchor and the follower's subsequent
       * packet timestamps in a single clock domain.  (It does not change the
       * retune timing itself: the hop instant is resolved into host-monotonic
       * time before any USB write is issued.)
       */
      int dev_idx = (cctx && dev && cctx->devs) ? (int)(dev - cctx->devs) : -1;
      if (dev_idx < 0 || (cctx && dev_idx >= cctx->ndev)) {
        /* Should not happen. Fall back to retuning every MCU rather than
         * leaving no MCU following the connection at all. */
        dev_idx = -1;
        g_follow_all_radios = true;
      }
      g_follow_dev_idx = dev_idx;
      g_follow_vacated_ch = hdr->channel_index;
      g_follow_phy = cfg->phy ? cfg->phy : PHY_1M;

      /* Set g_following last to act as a write barrier */
      g_following = true;

      /* Record the exact hardware timestamp of the CONNECT_REQ */
      g_conn_req_hw_ts = hdr->timestamp_us;
      if (dev && dev->host_hw_offset_us == 0) {
        struct timespec ts_init;
        clock_gettime(CLOCK_MONOTONIC, &ts_init);
        dev->host_hw_offset_us =
            (ts_init.tv_sec * 1000000ULL + ts_init.tv_nsec / 1000ULL) -
            hdr->timestamp_us;
      }
      g_active_host_hw_offset_us = dev ? dev->host_hw_offset_us : 0;

      fprintf(stderr,
              "[wch bus=%d addr=%d] Following CONNECT_IND! AA=%08X "
              "CRCInit=%06X interval=%u us WinOffset=%u us ch_map=0x%010llX "
              "hop=%d\n",
              dev ? dev->bus : -1, dev ? dev->addr : -1, g_follow_aa,
              g_follow_crcinit, g_hop_interval_us, g_win_offset_us,
              (unsigned long long)g_channel_map, g_hop_increment);

      fprintf(stderr,
              "[wch] Channel selection: CSA#%d (CONNECT_IND ChSel=%d, "
              "--csa %s), chanId=0x%04X, %d used channels, event 0 -> ch%d\n",
              g_use_csa2 ? 2 : 1, chsel ? 1 : 0,
              g_csa_force == CSA_AUTO ? "auto"
                                      : (g_csa_force == CSA_FORCE_2 ? "2" : "1"),
              g_chan_id, g_num_used_channels, first_ch);

      if (g_follow_all_radios) {
        fprintf(stderr, "[wch] Follow mode: ALL MCUs retune to the data "
                        "channels (-F); advertising capture suspended.\n");
      } else {
        int parked = 0;
        for (int i = 0; i < g_ndevs; i++)
          if (i != g_follow_dev_idx && g_devs_ptr[i].is_open)
            parked++;
        /* Deliberately does not claim the vacated channel is now uncovered:
         * with -c the user may have pinned every MCU to the same channel, and
         * we do not track per-device channel assignments. */
        fprintf(stderr,
                "[wch] Follow mode: MCU %d (was on BLE ch%d) follows the "
                "connection, %d MCU(s) stay on advertising.\n",
                g_follow_dev_idx, g_follow_vacated_ch, parked);
      }

      /* Spawn POSIX Timer Thread to track channel hopping */
      pthread_create(&g_hop_thread, NULL, hop_thread_func, NULL);
      pthread_detach(g_hop_thread);

      /* Signal the main loop to reconfig all MCUs.
       * We CANNOT call wch_reconfig_capture here: on_packet runs inside
       * wch_read_packets (a bulk_read context) — doing another bulk_write
       * on the same handle is re-entrant USB access and corrupts the read. */
      g_need_reconfig = true;
    } else {
      fprintf(stderr,
              "[wch debug] CONNECT_IND dropped! pdu_len=%d, pdu[1]=%d\n"
              "            valid_llength=%d, adva_match=%d, "
              "valid_interval=%d (interval=%u units),\n"
              "            valid_winoffset=%d (WinOffset=%u units), "
              "valid_winsize=%d (WinSize=%u units)\n",
              pdu_len, pdu[1], valid_llength, adva_match, valid_interval,
              conn_interval, valid_winoffset, win_offset, valid_winsize,
              win_size);
      if (!adva_match) {
        fprintf(stderr,
                "            AdvA in packet: %02X:%02X:%02X:%02X:%02X:%02X\n"
                "            Target filter:  %02X:%02X:%02X:%02X:%02X:%02X\n",
                pdu[13], pdu[12], pdu[11], pdu[10], pdu[9], pdu[8],
                cfg->adv_addr[5], cfg->adv_addr[4], cfg->adv_addr[3],
                cfg->adv_addr[2], cfg->adv_addr[1], cfg->adv_addr[0]);
      }
    }
  }

  if (cfg) {
    uint8_t zero_mac[6] = {0};
    bool has_adv_filter = memcmp(cfg->adv_addr, zero_mac, 6) != 0;
    bool has_init_filter = memcmp(cfg->initiator_addr, zero_mac, 6) != 0;

    bool match = false;
    if (has_adv_filter || has_init_filter) {

      if (has_adv_filter) {
        if (memcmp(hdr->src_addr, cfg->adv_addr, 6) == 0 ||
            memcmp(hdr->dst_addr, cfg->adv_addr, 6) == 0)
          match = true;
      }

      if (has_init_filter) {
        if (memcmp(hdr->src_addr, cfg->initiator_addr, 6) == 0 ||
            memcmp(hdr->dst_addr, cfg->initiator_addr, 6) == 0)
          match = true;
      }

      /* Data PDUs (like LL_ENC_REQ) do not contain MAC addresses in their
       * headers. If it's a data packet (channel <= 36), we bypass the MAC
       * filter so the user can still see control opcodes when the sniffer
       * happens to be on the right channel.
       */
      if (hdr->channel_index <= 36) {
        match = true;
      }
    } else {
      /* If no filters were specified, implicitly accept all unencrypted packets
       */
      match = true;
    }

    if (!match)
      return; /* Drop packet quietly */
  }

  g_pkt_count++;

  if (g_verbose)
    wch_print_packet(hdr, pdu, pdu_len);

  /* User requested Real-Time Control Opcode Logging */
  if (g_following && hdr->channel_index <= 36 && pdu_len > 2) {
    uint8_t llid = pdu[0] & 0x03;
    if (llid == 0x03) {                  /* LL Control PDU */
      uint8_t cp = (pdu[0] & 0x20) >> 5; /* CTE Info Present bit */
      uint8_t opcode_offset = 2 + cp;    /* Opcode shifts if CTE byte exists */

      if (pdu_len > opcode_offset) {
        uint8_t opcode = pdu[opcode_offset];
        const char *op_name = "UNKNOWN_OPCODE";
        switch (opcode) {
        case 0x00:
          op_name = "LL_CONNECTION_UPDATE_IND";
          break;
        case 0x01:
          op_name = "LL_CHANNEL_MAP_IND";
          break;
        case 0x02:
          op_name = "LL_TERMINATE_IND";
          break;
        case 0x03:
          op_name = "LL_ENC_REQ";
          break;
        case 0x04:
          op_name = "LL_ENC_RSP";
          break;
        case 0x05:
          op_name = "LL_START_ENC_REQ";
          break;
        case 0x06:
          op_name = "LL_START_ENC_RSP";
          break;
        case 0x07:
          op_name = "LL_UNKNOWN_RSP";
          break;
        case 0x08:
          op_name = "LL_FEATURE_REQ";
          break;
        case 0x09:
          op_name = "LL_FEATURE_RSP";
          break;
        case 0x0A:
          op_name = "LL_PAUSE_ENC_REQ";
          break;
        case 0x0B:
          op_name = "LL_PAUSE_ENC_RSP";
          break;
        case 0x0C:
          op_name = "LL_VERSION_IND";
          break;
        case 0x0D:
          op_name = "LL_REJECT_IND";
          break;
        case 0x0E:
          op_name = "LL_SLAVE_FEATURE_REQ";
          break;
        case 0x0F:
          op_name = "LL_CONNECTION_PARAM_REQ";
          break;
        case 0x10:
          op_name = "LL_CONNECTION_PARAM_RSP";
          break;
        case 0x11:
          op_name = "LL_REJECT_EXT_IND";
          break;
        case 0x12:
          op_name = "LL_PING_REQ";
          break;
        case 0x13:
          op_name = "LL_PING_RSP";
          break;
        case 0x14:
          op_name = "LL_LENGTH_REQ";
          break;
        case 0x15:
          op_name = "LL_LENGTH_RSP";
          break;
        case 0x16:
          op_name = "LL_PHY_REQ";
          break;
        case 0x17:
          op_name = "LL_PHY_RSP";
          break;
        case 0x18:
          op_name = "LL_PHY_UPDATE_IND";
          break;
        case 0x19:
          op_name = "LL_MIN_USED_CHANNELS_IND";
          break;
        case 0x1A:
          op_name = "LL_CTE_REQ";
          break;
        case 0x1B:
          op_name = "LL_CTE_RSP";
          break;
        case 0x24:
          op_name = "LL_CS_CAPABILITIES_REQ";
          break;
        case 0x25:
          op_name = "LL_CS_CAPABILITIES_RSP";
          break;
        case 0x2A:
          op_name = "LL_CS_REQ";
          break;
        case 0x2B:
          op_name = "LL_CS_RSP";
          break;
        case 0x2C:
          op_name = "LL_CS_IND";
          break;
        case 0x2E:
          op_name = "LL_CS_FAA_IND";
          break;
        }

        fprintf(stderr,
                "\033[1;32m[wch bus=%d addr=%d] * Control Opcode Captured: %s "
                "(0x%02X) on ch%d\033[0m\n",
                dev ? dev->bus : -1, dev ? dev->addr : -1, op_name, opcode,
                hdr->channel_index);

        /*
         * ── Host-side apply-at-Instant ───────────────────────────────────
         *
         * The host hop thread drives every retune, so it must track
         * parameter changes itself.  Latch the new values here and let the
         * hop thread apply them when its event counter reaches the Instant.
         *
         * A CTE Info byte (cp != 0) shifts every field by one and is not
         * expected on these opcodes, so those PDUs are ignored rather than
         * mis-parsed.  Lengths are checked exactly: a CRC-damaged frame
         * accepted here would send the follower to a bogus channel map for
         * the rest of the connection.
         */
        if (cp == 0 && opcode == 0x01 && pdu[1] == 8 && pdu_len >= 10) {
          /* LL_CHANNEL_MAP_IND: [hdr0][len=8][0x01][ChM 5][Instant 2] */
          uint64_t map = 0;
          for (int k = 0; k < 5; k++)
            map |= ((uint64_t)pdu[3 + k]) << (k * 8);
          map &= UINT64_C(0x1FFFFFFFFF);
          int used = 0;
          for (int k = 0; k < 37; k++)
            if (map & (1ULL << k))
              used++;
          uint16_t instant = (uint16_t)(pdu[8] | ((uint16_t)pdu[9] << 8));
          if (used < 2) {
            fprintf(stderr,
                    "[hop] Ignoring LL_CHANNEL_MAP_IND: implausible map "
                    "0x%010llX (%d used channels)\n",
                    (unsigned long long)map, used);
          } else {
            g_pending_map = map;
            g_pending_map_instant = instant;
            g_pending_map_valid = true; /* publish last */
            fprintf(stderr,
                    "[hop] LL_CHANNEL_MAP_IND queued: map=0x%010llX (%d used) "
                    "at instant %u (now at event %u)\n",
                    (unsigned long long)map, used, instant,
                    g_conn_event_counter);
          }
        } else if (cp == 0 && opcode == 0x00 && pdu[1] == 12 && pdu_len >= 14) {
          /* LL_CONNECTION_UPDATE_IND:
           * [hdr0][len=12][0x00][WinSize][WinOffset 2][Interval 2]
           * [Latency 2][Timeout 2][Instant 2] */
          uint16_t win_off = (uint16_t)(pdu[4] | ((uint16_t)pdu[5] << 8));
          uint16_t ival = (uint16_t)(pdu[6] | ((uint16_t)pdu[7] << 8));
          uint16_t instant = (uint16_t)(pdu[12] | ((uint16_t)pdu[13] << 8));
          if (ival < 6 || ival > 3200) {
            fprintf(stderr,
                    "[hop] Ignoring LL_CONNECTION_UPDATE_IND: interval %u "
                    "out of range\n",
                    ival);
          } else if (win_off > ival) {
            /* Same guard as the CONNECT_IND path: a WinOffset larger than the
             * interval is impossible per spec, and applying one would push the
             * anchor arbitrarily far into the future mid-connection. */
            fprintf(stderr,
                    "[hop] Ignoring LL_CONNECTION_UPDATE_IND: WinOffset %u "
                    "exceeds interval %u\n",
                    win_off, ival);
          } else {
            g_pending_cu_interval_us = (uint32_t)ival * 1250u;
            g_pending_cu_win_offset_us = (uint32_t)win_off * 1250u;
            g_pending_cu_instant = instant;
            g_pending_cu_valid = true; /* publish last */
            fprintf(stderr,
                    "[hop] LL_CONNECTION_UPDATE_IND queued: interval=%u us "
                    "WinOffset=%u us at instant %u (now at event %u)\n",
                    g_pending_cu_interval_us, g_pending_cu_win_offset_us,
                    instant, g_conn_event_counter);
          }
        }

        /*
         * AA 82 relay (-R).  Hand the LL control PDU to the follower MCU so
         * its firmware can apply the new parameters at the Instant.
         *
         * Only the three opcodes the Windows application relays are sent:
         * 0x00 CONNECTION_UPDATE_IND, 0x01 CHANNEL_MAP_IND, 0x18
         * PHY_UPDATE_IND.
         *
         * cp != 0 means a CTE Info byte sits between the length and the
         * opcode, so the opcode is at pdu[3].  The firmware reads its selector
         * at payload[2], so forwarding such a PDU verbatim would place the CTE
         * byte where the selector belongs.  Skip those rather than guess at a
         * repacking the Windows binary gives no evidence for.
         *
         * Relayed only by the MCU that is following, which is also the only
         * MCU on data channels in split-follow mode.  Under -F every MCU sees
         * the same PDU, and this test keeps exactly one relay per PDU.
         */
        /* LL_TERMINATE_IND ends the connection.  Ask the main loop to hand
         * the follower back to advertising; we cannot issue USB writes here
         * because on_packet runs inside a bulk_read. */
        if (opcode == 0x02 && g_following) {
          fprintf(stderr, "[wch] LL_TERMINATE_IND seen - releasing follow.\n");
          g_need_repark = true;
        }

        int relay_idx = (cctx && dev && cctx->devs)
                            ? (int)(dev - cctx->devs)
                            : -1;
        if (g_relay_ll_updates && g_following && cp == 0 &&
            (opcode == 0x00 || opcode == 0x01 || opcode == 0x18) &&
            relay_idx >= 0 && relay_idx == g_follow_dev_idx) {
          int rr = wch_send_ll_update(&cctx->devs[relay_idx], pdu, pdu_len);
          g_relay_count++;
          fprintf(stderr,
                  "\033[1;36m[wch] AA82 relay -> MCU %d: %s (0x%02X), "
                  "%d byte PDU%s\033[0m\n",
                  relay_idx, op_name, opcode, pdu_len,
                  rr == 0 ? "" : " (WRITE FAILED)");
        }
      }
    }
  }

  pcap_write_packet(hdr, pdu, pdu_len);
}

/* ── MAC address parsing ───────────────────────────────────────────────────
 */

static bool parse_mac(const char *str, uint8_t out[6]) {
  /* Accept "AA:BB:CC:DD:EE:FF" or "AABBCCDDEEFF" */
  unsigned v[6];
  if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &v[0], &v[1], &v[2], &v[3],
             &v[4], &v[5]) == 6 ||
      sscanf(str, "%02x%02x%02x%02x%02x%02x", &v[0], &v[1], &v[2], &v[3], &v[4],
             &v[5]) == 6) {
    /* Convert from display order (MSB first) to wire order (LSB first) */
    for (int i = 0; i < 6; i++)
      out[5 - i] = (uint8_t)v[i];
    return true;
  }
  return false;
}

static bool parse_ltk(const char *str, uint8_t out[16]) {
  if (strlen(str) != 32)
    return false;
  for (int i = 0; i < 16; i++) {
    unsigned v;
    if (sscanf(str + i * 2, "%02x", &v) != 1)
      return false;
    out[i] = (uint8_t)v;
  }
  return true;
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]\n"
          "\n"
          "Options:\n"
          "  -v            Print packets to stdout\n"
          "  -w FILE.pcap  Write PCAP (DLT 256, BLE LL + phdr)\n"
          "  -p PHY        PHY: 1=1M (default), 2=2M, 3=CodedS8, 4=CodedS2\n"
          "  -i ADDR       Central/Phone MAC filter (Initiator)  "
          "(AA:BB:CC:DD:EE:FF)\n"
          "  -a ADDR       Peripheral/Device MAC filter (Advertiser) "
          "(AA:BB:CC:DD:EE:FF)\n"
          "  -k KEY        LTK, 32 hex chars\n"
          "  -K PASSKEY    BLE passkey (6-digit decimal)\n"
          "  -2            Custom 2.4G mode (default: BLE monitor)\n"
          "  -c CHAN       Channel 0-39: BLE adv 37/38/39 or 0=all (auto per "
          "MCU); 2.4G raw\n"
          "  -A AADDR      2.4G access addr (hex, e.g. 8E89BED6)\n"
          "  -C CRCINIT    2.4G CRC init (6 hex chars, e.g. 555555)\n"
          "  -W WHITEN     2.4G whitening init (hex byte)\n"
          "  -f            Follow connections dynamically (one MCU jumps to "
          "the data\n"
          "                channels, the others keep watching advertising)\n"
          "  -F            Follow with ALL MCUs (legacy): every MCU jumps to "
          "the data\n"
          "                channels. Duplicates packets and stops advertising "
          "capture.\n"
          "  -R            EXPERIMENTAL: relay LL_CONNECTION_UPDATE_IND / "
          "CHANNEL_MAP_IND\n"
          "                / PHY_UPDATE_IND to the follower MCU (AA 82). "
          "Implies -f.\n"
          "  -B            Set AA 81 field-validity flags 0x10/0x20 (default; "
          "kept for\n"
          "                explicitness). Without them the radio ignores the "
          "AA/CRCInit.\n"
          "  -b            A/B TESTING ONLY: use the old flags 0x03. The radio "
          "then\n"
          "                cannot be given an Access Address and may go "
          "deaf.\n"
          "  --csa 1|2|auto  Channel selection algorithm while following "
          "(default:\n"
          "                auto = CSA#2 if the CONNECT_IND ChSel bit is set, "
          "else CSA#1).\n"
          "                Modern phones negotiate CSA#2.\n"
          "  -ff           Enable FIFO pipeline to communicate with Wireshark\n"
          "  -ffn NAME     FIFO file name (default: /tmp/blepipe)\n"
          "  -ws           Open Wireshark reading from FIFO\n"
          "  -debuglog LOG Write raw unfiltered packets to LOG file\n"
          "  -h            Show this help\n"
          "\n"
          "Capture stops on SIGINT (Ctrl+C) or SIGTERM.\n",
          prog);
}


/*
 * Hand a followed connection back: stop the hop thread, return the follower to
 * its original advertising channel with the advertising Access Address and
 * CRCInit, and clear the follow latch so a later CONNECT_IND can be followed.
 *
 * Must be called from the main thread with no bulk_read in flight.
 */
static void repark_follower(wch_device_t *devs, int ndev) {
  if (!g_following && g_follow_dev_idx < 0)
    return;

  int idx = g_follow_dev_idx;
  uint8_t ch = g_follow_vacated_ch ? g_follow_vacated_ch : 37;

  /* Stop the hop thread and wait for it to actually leave its loop, so it
   * cannot retune the radio again after we have re-parked it. */
  g_following = false;
  for (int i = 0; i < 100 && g_hop_running; i++)
    usleep(5000);
  if (g_hop_running)
    fprintf(stderr, "[wch] warning: hop thread still running at re-park\n");

  if (idx >= 0 && idx < ndev && devs[idx].is_open) {
    int r = wch_park_advertising(&devs[idx], g_follow_phy, ch);
    if (r == 0)
      fprintf(stderr, "[wch] MCU %d re-parked on BLE ch%d (read-back OK).\n",
              idx, ch);
    else if (r > 0)
      fprintf(stderr,
              "[wch] MCU %d re-parked on BLE ch%d, but the config read-back "
              "did not confirm it.\n",
              idx, ch);
    else
      fprintf(stderr, "[wch] MCU %d re-park FAILED: %s\n", idx,
              libusb_error_name(r));
  }

  /* Reset follow state so the next CONNECT_IND is eligible. */
  g_follow_aa = 0x8E89BED6;
  g_follow_crcinit = 0x555555;
  g_follow_dev_idx = -1;
  g_follow_vacated_ch = 0;
  g_need_reconfig = false;
  g_need_repark = false;
}

/* ── main ──────────────────────────────────────────────────────────────────
 */

int main(int argc, char *argv[]) {
  fprintf(stderr, "\n"
                  "WCH BLE Analyzer PRO macOS Capture tool\n"
                  "Author: Jadkorr (https://x.com/jadkorr)\n"
                  "Based on original research and Linux reversing by Xecaz\n"
                  "---------------------------------------\n"
                  "\n");

  wch_capture_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mode = MODE_BLE_MONITOR;
  cfg.phy = PHY_1M;

  const char *pcap_path = NULL;
  int opt;

  // Manual parsing for -ff, -ffn, -ws before getopt
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-ff") == 0) {
      g_use_fifo = true;
      // Remove this argument from argv for getopt
      for (int j = i; j < argc - 1; j++)
        argv[j] = argv[j + 1];
      argc--;
      i--; // Re-check the current index
    } else if (strcmp(argv[i], "-ffn") == 0) {
      g_use_fifo = true;
      if (i + 1 < argc) {
        g_fifo_name = argv[i + 1];
        // Remove -ffn and its argument from argv for getopt
        for (int j = i; j < argc - 2; j++)
          argv[j] = argv[j + 2];
        argc -= 2;
        i--; // Re-check the current index
      } else {
        fprintf(stderr, "Error: -ffn requires a file name.\n");
        usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "-debuglog") == 0) {
      if (i + 1 < argc) {
        g_debuglog_file = fopen(argv[i + 1], "w");
        if (!g_debuglog_file) {
          fprintf(stderr, "Error opening debuglog file %s: %s\n", argv[i + 1],
                  strerror(errno));
          return 1;
        }
        for (int j = i; j < argc - 2; j++)
          argv[j] = argv[j + 2];
        argc -= 2;
        i--;
      } else {
        fprintf(stderr, "Error: -debuglog requires a file name.\n");
        usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "--csa") == 0) {
      /* Long option, so parsed here rather than through getopt(). */
      if (i + 1 < argc) {
        if (strcmp(argv[i + 1], "1") == 0)
          g_csa_force = CSA_FORCE_1;
        else if (strcmp(argv[i + 1], "2") == 0)
          g_csa_force = CSA_FORCE_2;
        else if (strcmp(argv[i + 1], "auto") == 0)
          g_csa_force = CSA_AUTO;
        else {
          fprintf(stderr, "Error: --csa expects 1, 2 or auto.\n");
          usage(argv[0]);
          return 1;
        }
        for (int j = i; j < argc - 2; j++)
          argv[j] = argv[j + 2];
        argc -= 2;
        i--;
      } else {
        fprintf(stderr, "Error: --csa requires an argument (1, 2 or auto).\n");
        usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "-ws") == 0) {
      g_launch_ws = true;
      g_use_fifo = true; // -ws implies -ff
      // Remove this argument from argv for getopt
      for (int j = i; j < argc - 1; j++)
        argv[j] = argv[j + 1];
      argc--;
      i--; // Re-check the current index
    }
  }

  while ((opt = getopt(argc, argv, "vw:p:i:a:k:K:2c:A:C:W:fFRBbh")) != -1) {
    switch (opt) {
    case 'f':
      cfg.follow_conn = true;
      break;
    case 'F':
      /* Legacy behaviour: every MCU retunes to the connection's data
       * channels, so advertising is no longer captured while following. */
      cfg.follow_conn = true;
      g_follow_all_radios = true;
      break;
    case 'R':
      /* Relaying only makes sense while following a connection. */
      cfg.follow_conn = true;
      g_relay_ll_updates = true;
      break;
    case 'B':
      g_aa81_mark_fields = true;
      break;
    case 'b':
      /* A/B experiments only: revert to the old flags 0x03, which cannot
       * write the Access Address or CRCInit in either direction. */
      g_aa81_mark_fields = false;
      break;
    case 'v':
      g_verbose = true;
      break;
    case 'w':
      pcap_path = optarg;
      break;
    case 'p':
      cfg.phy = (uint8_t)atoi(optarg);
      if (cfg.phy < 1 || cfg.phy > 4) {
        fprintf(stderr, "Invalid PHY %d (1-4)\n", cfg.phy);
        return 1;
      }
      g_phy = cfg.phy;
      break;
    case 'i':
      if (!parse_mac(optarg, cfg.initiator_addr)) {
        fprintf(stderr, "Invalid initiator MAC: %s\n", optarg);
        return 1;
      }
      break;
    case 'a':
      if (!parse_mac(optarg, cfg.adv_addr)) {
        fprintf(stderr, "Invalid advertiser MAC: %s\n", optarg);
        return 1;
      }
      break;
    case 'k':
      if (!parse_ltk(optarg, cfg.ltk)) {
        fprintf(stderr, "Invalid LTK (need 32 hex chars): %s\n", optarg);
        return 1;
      }
      break;
    case 'K':
      cfg.pass_key = (uint32_t)atol(optarg);
      break;
    case '2':
      cfg.mode = MODE_CUSTOM_2G4;
      break;
    case 'c': {
      int v = atoi(optarg);
      if (v < 0 || v > 39) {
        fprintf(stderr, "Channel out of range (0-39)\n");
        return 1;
      }
      cfg.channel = (uint8_t)v;     /* 2.4G mode */
      cfg.ble_channel = (uint8_t)v; /* BLE monitor mode */
      break;
    }
    case 'A': {
      unsigned long v;
      if (sscanf(optarg, "%lx", &v) != 1) {
        fprintf(stderr, "Invalid access address: %s\n", optarg);
        return 1;
      }
      cfg.access_addr_24g = (uint32_t)v;
      break;
    }
    case 'C': {
      unsigned v[3];
      if (sscanf(optarg, "%02x%02x%02x", &v[0], &v[1], &v[2]) != 3) {
        fprintf(stderr, "Invalid CRC init (need 6 hex chars): %s\n", optarg);
        return 1;
      }
      cfg.crc_init[0] = (uint8_t)v[0];
      cfg.crc_init[1] = (uint8_t)v[1];
      cfg.crc_init[2] = (uint8_t)v[2];
      break;
    }
    case 'W': {
      unsigned v;
      if (sscanf(optarg, "%x", &v) != 1) {
        fprintf(stderr, "Invalid whitening: %s\n", optarg);
        return 1;
      }
      cfg.whitening = (uint8_t)v;
      break;
    }
    case 'h':
    default:
      usage(argv[0]);
      return opt == 'h' ? 0 : 1;
    }
  }

  if (!g_verbose && !pcap_path && !g_use_fifo) {
    fprintf(stderr, "Nothing to do – use -v, -w FILE.pcap, or -ff\n");
    usage(argv[0]);
    return 1;
  }

  fprintf(stderr, "Active Configuration:\n");
  fprintf(stderr, "  PHY:         %s\n",
          cfg.phy == 1   ? "1M"
          : cfg.phy == 2 ? "2M"
          : cfg.phy == 3 ? "Coded S8"
                         : "Coded S2");

  if (cfg.mode == MODE_CUSTOM_2G4) {
    fprintf(stderr, "  Mode:        Custom 2.4G (Ch %d)\n", cfg.channel);
  } else {
    if (cfg.ble_channel) {
      fprintf(stderr, "  Channel:     %d\n", cfg.ble_channel);
    } else {
      fprintf(stderr, "  Channel:     Auto-Hopping (37, 38, 39)\n");
    }
  }

  uint8_t zero_mac[6] = {0};
  if (memcmp(cfg.initiator_addr, zero_mac, 6) != 0) {
    fprintf(
        stderr,
        "  Filter (C):  %02X:%02X:%02X:%02X:%02X:%02X (Central/Initiator)\n",
        cfg.initiator_addr[5], cfg.initiator_addr[4], cfg.initiator_addr[3],
        cfg.initiator_addr[2], cfg.initiator_addr[1], cfg.initiator_addr[0]);
  }
  if (memcmp(cfg.adv_addr, zero_mac, 6) != 0) {
    fprintf(stderr,
            "  Filter (P):  %02X:%02X:%02X:%02X:%02X:%02X "
            "(Peripheral/Advertiser)\n",
            cfg.adv_addr[5], cfg.adv_addr[4], cfg.adv_addr[3], cfg.adv_addr[2],
            cfg.adv_addr[1], cfg.adv_addr[0]);
  }
  fprintf(stderr, "---------------------------------------\n");

  /* Set up signal handlers */
  struct sigaction sa = {.sa_handler = sig_handler};
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Initialise libusb */
  libusb_context *ctx = NULL;
  int r = wch_init(&ctx);
  if (r != 0) {
    fprintf(stderr, "libusb_init: %s\n", libusb_error_name(r));
    return 1;
  }

  /* Find MCU devices */
  wch_device_t devs[MAX_MCU_DEVICES];
  int ndev = wch_find_devices(ctx, devs);
  if (ndev <= 0) {
    fprintf(stderr,
            "No WCH BLE Analyzer MCUs found "
            "(VID 0x%04X / PID 0x%04X).\n"
            "Check USB connection and udev rules.\n",
            WCH_VID, WCH_PID_BLE_MCU);
    wch_exit(ctx);
    return 1;
  }
  fprintf(stderr, "Found %d MCU device(s).\n", ndev);

  /* Open all found devices */
  int opened = 0;
  for (int i = 0; i < ndev; i++) {
    r = wch_open_device(&devs[i]);
    if (r != 0) {
      fprintf(stderr, "open bus=%d addr=%d: %s\n", devs[i].bus, devs[i].addr,
              libusb_error_name(r));
    } else {
      fprintf(stderr, "Opened bus=%d addr=%d\n", devs[i].bus, devs[i].addr);
      opened++;
    }
  }
  if (opened == 0) {
    fprintf(stderr, "Could not open any device.\n");
    wch_exit(ctx);
    return 1;
  }

  if (g_use_fifo) {
    pcap_path = g_fifo_name;
  }

  if (g_launch_ws && g_use_fifo) {
    fprintf(stderr, "Launching Wireshark...\n");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "wireshark -k -i %s &", g_fifo_name);
    if (system(cmd) == -1) {
      perror("system");
    }
  } else if (g_use_fifo) {
    fprintf(stderr, "FIFO mode enabled. Awaiting reader on %s...\n",
            g_fifo_name);
  }

  /* Open PCAP output file */
  if (pcap_path && !pcap_open(pcap_path, g_use_fifo)) {
    for (int i = 0; i < ndev; i++)
      wch_close_device(&devs[i]);
    wch_exit(ctx);
    return 1;
  }

  /*
   * Send start command to all open devices.
   *
   * Channel assignment for BLE monitor mode:
   *   The hardware has 3 independent CH582F MCUs, one per BLE advertising
   *   channel (37 / 38 / 39).  Assign a different channel to each MCU so
   *   all three advertising channels are captured simultaneously.
   *   Confirmed by RE of BleAnalyzer64.exe (AA81 payload byte [2] = channel).
   */
  static const uint8_t adv_ch[3] = {37, 38, 39};

  for (int i = 0; i < ndev; i++) {
    if (!devs[i].is_open)
      continue;

    wch_capture_config_t dev_cfg = cfg;
    /* Auto-assign one adv channel per MCU unless user pinned a channel */
    if (cfg.mode == MODE_BLE_MONITOR && ndev > 1 && cfg.ble_channel == 0)
      dev_cfg.ble_channel = (i < 3) ? adv_ch[i] : 0;

    r = wch_start_capture(&devs[i], &dev_cfg);
    if (r != 0)
      fprintf(stderr, "start_capture bus=%d addr=%d: %s\n", devs[i].bus,
              devs[i].addr, libusb_error_name(r));
    else if (cfg.mode == MODE_BLE_MONITOR)
      fprintf(stderr, "  MCU %d (bus=%d addr=%d): BLE ch%d\n", i, devs[i].bus,
              devs[i].addr, dev_cfg.ble_channel ? dev_cfg.ble_channel : 37);
  }

  /* Allocate bulk read buffers – one per device */
  uint8_t *bufs[MAX_MCU_DEVICES];
  for (int i = 0; i < ndev; i++) {
    bufs[i] = NULL;
    if (devs[i].is_open) {
      bufs[i] = malloc(BULK_TRANSFER_SIZE);
      if (!bufs[i]) {
        fprintf(stderr, "Out of memory\n");
        g_stop = 1;
        break;
      }
    }
  }

  /* Expose device array to the hop thread BEFORE entering the main loop */
  g_devs_ptr = devs;
  g_ndevs = ndev;

  fprintf(stderr, "Capturing… press Ctrl+C to stop.\n");

  /*
   * Main capture loop.
   *
   * Strategy: drain each MCU's USB buffer completely before moving on.
   * This prevents the artificial 1:1:1 channel ratio caused by reading
   * exactly one bulk transfer per MCU per loop iteration.
   *
   * DRAIN_POLL_MS: short timeout used to drain buffered packets quickly.
   *   Returning 0 (timeout) means the MCU's kernel buffer is empty.
   *
   * IDLE_WAIT_MS: longer timeout used when all MCUs are quiet to avoid
   *   busy-looping while still waking up promptly when traffic arrives.
   */
#define DRAIN_POLL_MS 5 /* quick drain: check for already-buffered data  */
#define IDLE_WAIT_MS                                                           \
  100 /* idle wait: block until traffic arrives (per MCU)                      \
       */

  while (!g_stop) {
    bool any_data = false;

    /* Phase 1: drain all MCUs round-robin until their buffers are empty */
    do {
      any_data = false;
      for (int i = 0; i < ndev && !g_stop; i++) {
        if (!devs[i].is_open || !bufs[i])
          continue;
        struct cb_ctx cctx = {&devs[i], devs, ndev, &cfg};
        int n = wch_read_packets(&devs[i], bufs[i], on_packet, &cctx,
                                 DRAIN_POLL_MS);
        if (n > 0) {
          any_data = true;
        }
      }
    } while (any_data && !g_stop);

    /* After draining all MCUs, check if a CONNECT_IND was detected.
     * Reconfig all MCUs here (outside any bulk_read context) so USB
     * access is safe and not re-entrant. */
    if (g_need_reconfig && !g_stop) {
      g_need_reconfig = false;
      if (!g_following) {
        /* Only retune from main loop when no hop thread is running.
         * When g_following is true the pthread manages all retunes.
         * NOTE: on_packet() sets g_following before g_need_reconfig, so this
         * branch is currently unreachable. The follower filter below is kept
         * in sync with hop_thread_func() in case that ordering ever changes. */
        fprintf(stderr, "[wch] Reconfiguring MCUs for connection follow...\n");
        for (int i = 0; i < ndev; i++) {
          if (!devs[i].is_open)
            continue;
          if (!g_follow_all_radios && i != g_follow_dev_idx)
            continue;
          wch_reconfig_capture(&devs[i], &g_active_cfg);
        }
      }
    }

    /* A followed connection ended: hand the follower back to advertising. */
    if (g_need_repark && !g_stop)
      repark_follower(devs, ndev);

    /* Phase 2: when all MCUs are idle, do a longer blocking wait
     * on each MCU to reduce CPU usage until traffic resumes. */
    if (!any_data && !g_stop) {
      for (int i = 0; i < ndev && !g_stop; i++) {
        if (!devs[i].is_open || !bufs[i])
          continue;
        struct cb_ctx cctx = {&devs[i], devs, ndev, &cfg};
        wch_read_packets(&devs[i], bufs[i], on_packet, &cctx, IDLE_WAIT_MS);
      }
    }
  }

  /* Hand back a still-active follow before shutting down, so the follower is
   * not left deaf for the next session. */
  if (g_following || g_follow_dev_idx >= 0)
    repark_follower(devs, ndev);

  /* Stop and clean up */
  fprintf(stderr, "\nStopping capture (%llu packets)…\n",
          (unsigned long long)g_pkt_count);
  if (g_relay_ll_updates)
    fprintf(stderr, "  AA82 relays sent: %llu\n",
            (unsigned long long)g_relay_count);

  for (int i = 0; i < ndev; i++) {
    if (!devs[i].is_open)
      continue;
    wch_stop_capture(&devs[i]);
    fprintf(stderr, "  bus=%d addr=%d: rx=%llu err=%llu\n", devs[i].bus,
            devs[i].addr, (unsigned long long)devs[i].rx_count,
            (unsigned long long)devs[i].err_count);
    wch_close_device(&devs[i]);
    free(bufs[i]);
  }

  if (g_pcap_file) {
    fflush(g_pcap_file);
    fclose(g_pcap_file);
    fprintf(stderr, "PCAP written to %s\n", pcap_path);
  }

  wch_exit(ctx);
  return 0;
}
