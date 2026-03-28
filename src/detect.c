#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sampass.h"

/* USB product IDs for Samsung Galaxy modes */
#define SAMSUNG_VID         "0x04e8"
#define PID_MTP             "0x6860"  /* Normal MTP mode */
#define PID_ADB             "0x6860"  /* ADB + MTP shares PID */
#define PID_DOWNLOAD        "0x6601"  /* Odin/Download mode */
#define PID_RECOVERY        "0x6862"  /* Recovery mode */
#define PID_MODEM           "0x6862"  /* CDC/Modem */

typedef struct {
    char product_id[16];
    char vendor_id[16];
    char serial[64];
    char manufacturer[64];
    char product_name[64];
    char speed[32];
    int  current_ma;
    bool found;
} usb_device_t;

typedef enum {
    STATE_NORMAL_MTP = 0,
    STATE_DOWNLOAD,
    STATE_RECOVERY,
    STATE_UNKNOWN
} device_state_t;

/* run a command and capture its output */
static char *run_cmd(const char *cmd)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    size_t cap = 4096;
    char *buf = malloc(cap);
    if (!buf) { pclose(fp); return NULL; }

    size_t len = 0;
    size_t n;
    while ((n = fread(buf + len, 1, cap - len - 1, fp)) > 0) {
        len += n;
        if (len >= cap - 1) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) break;
            buf = tmp;
        }
    }
    buf[len] = '\0';
    pclose(fp);
    return buf;
}

/* extract a value after "key: " from system_profiler output */
static bool extract_field(const char *data, const char *key, char *out, size_t out_sz)
{
    char search[128];
    snprintf(search, sizeof(search), "%s: ", key);
    const char *p = strstr(data, search);
    if (!p) return false;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '\n' && i < out_sz - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    /* trim trailing whitespace */
    while (i > 0 && isspace((unsigned char)out[i - 1]))
        out[--i] = '\0';
    return i > 0;
}

static bool scan_usb(usb_device_t *dev)
{
    memset(dev, 0, sizeof(*dev));

    char *usb_data = run_cmd("system_profiler SPUSBDataType 2>/dev/null");
    if (!usb_data) return false;

    /* find Samsung section */
    const char *samsung = strstr(usb_data, "SAMSUNG");
    if (!samsung) samsung = strstr(usb_data, "samsung");
    if (!samsung) samsung = strstr(usb_data, "Samsung");
    if (!samsung) {
        /* also check by vendor ID */
        samsung = strstr(usb_data, "0x04e8");
    }

    if (!samsung) {
        free(usb_data);
        return false;
    }

    dev->found = true;
    extract_field(samsung, "Product ID", dev->product_id, sizeof(dev->product_id));
    extract_field(samsung, "Vendor ID", dev->vendor_id, sizeof(dev->vendor_id));
    extract_field(samsung, "Serial Number", dev->serial, sizeof(dev->serial));
    extract_field(samsung, "Manufacturer", dev->manufacturer, sizeof(dev->manufacturer));
    extract_field(samsung, "Speed", dev->speed, sizeof(dev->speed));

    char current[16];
    if (extract_field(samsung, "Current Required (mA)", current, sizeof(current)))
        dev->current_ma = atoi(current);

    free(usb_data);
    return true;
}

static device_state_t identify_state(const usb_device_t *dev)
{
    if (strstr(dev->product_id, "6601"))
        return STATE_DOWNLOAD;
    if (strstr(dev->product_id, "6862"))
        return STATE_RECOVERY;
    if (strstr(dev->product_id, "6860"))
        return STATE_NORMAL_MTP;
    return STATE_UNKNOWN;
}

static const char *state_str(device_state_t s)
{
    switch (s) {
    case STATE_NORMAL_MTP: return "Normal (MTP/Charging)";
    case STATE_DOWNLOAD:   return "Download Mode (Odin)";
    case STATE_RECOVERY:   return "Recovery Mode";
    case STATE_UNKNOWN:    return "Unknown";
    }
    return "Unknown";
}

/* try ADB and parse device properties if available */
static bool try_adb(char *model_out, size_t model_sz,
                    char *patch_out, size_t patch_sz,
                    char *android_ver, size_t ver_sz)
{
    char *devices = run_cmd("adb devices 2>/dev/null");
    if (!devices) return false;

    /* check if any device is listed (not just the header line) */
    const char *line2 = strchr(devices, '\n');
    bool has_device = false;
    if (line2) {
        line2++;
        /* skip empty lines */
        while (*line2 == '\n') line2++;
        if (*line2 && *line2 != '\0')
            has_device = true;
    }
    free(devices);

    if (!has_device) return false;

    /* pull device properties */
    char *m = run_cmd("adb shell getprop ro.product.model 2>/dev/null");
    if (m && strlen(m) > 1) {
        m[strcspn(m, "\r\n")] = '\0';
        snprintf(model_out, model_sz, "%s", m);
    }
    free(m);

    char *p = run_cmd("adb shell getprop ro.build.version.security_patch 2>/dev/null");
    if (p && strlen(p) > 1) {
        p[strcspn(p, "\r\n")] = '\0';
        snprintf(patch_out, patch_sz, "%s", p);
    }
    free(p);

    char *v = run_cmd("adb shell getprop ro.build.version.release 2>/dev/null");
    if (v && strlen(v) > 1) {
        v[strcspn(v, "\r\n")] = '\0';
        snprintf(android_ver, ver_sz, "%s", v);
    }
    free(v);

    return model_out[0] != '\0';
}

/* decode Samsung serial for manufacturing info */
static void decode_serial(const char *serial)
{
    if (strlen(serial) < 4) return;

    printf("  " CLR_BOLD "Serial Decode:" CLR_RESET "\n");

    /* first char: R = Samsung mobile */
    if (serial[0] == 'R')
        printf("    Prefix:   R (Samsung mobile device)\n");

    /* second char: factory code */
    char factory = serial[1];
    const char *factory_name = "Unknown";
    switch (factory) {
    case 'F': factory_name = "Samsung Vietnam (Thai Nguyen)"; break;
    case '1': factory_name = "Samsung Korea (Gumi)"; break;
    case '2': factory_name = "Samsung Korea (Hwaseong)"; break;
    case 'V': factory_name = "Samsung Vietnam (SEVT)"; break;
    case 'W': factory_name = "Samsung China"; break;
    case 'X': factory_name = "Samsung India"; break;
    case 'M': factory_name = "Samsung India (Noida)"; break;
    }
    printf("    Factory:  %c (%s)\n", factory, factory_name);

    /* year + month encoding */
    char year_c = serial[2];
    char month_c = serial[3];

    int year = 2000;
    if (year_c >= '0' && year_c <= '9')
        year = 2010 + (year_c - '0');
    else if (year_c >= 'A' && year_c <= 'Z')
        year = 2020 + (year_c - 'A');

    const char *months[] = {
        "", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    int month = 0;
    if (month_c >= '1' && month_c <= '9')
        month = month_c - '0';
    else if (month_c == 'A') month = 10;
    else if (month_c == 'B') month = 11;
    else if (month_c == 'C') month = 12;

    if (month >= 1 && month <= 12)
        printf("    Manufactured: %s %d\n", months[month], year);

    printf("    Unit ID:  %s\n", serial + 4);
}

int detect_device(void)
{
    print_section_header("DEVICE DETECTION & RECONNAISSANCE");

    /* step 1: USB scan */
    printf(CLR_BOLD "  [PHASE 1] USB Bus Scan\n" CLR_RESET);
    print_separator();

    usb_device_t dev;
    if (!scan_usb(&dev)) {
        color_print(CLR_RED, "\n  No Samsung device found on USB.\n");
        printf("  Ensure the phone is connected via USB cable.\n\n");
        printf("  " CLR_BOLD "Troubleshooting:" CLR_RESET "\n");
        printf("   - Try a different USB cable (some are charge-only)\n");
        printf("   - Try a different USB port\n");
        printf("   - Check if the phone is powered on\n\n");
        return 1;
    }

    printf("\n  " CLR_GREEN "Samsung device detected on USB bus." CLR_RESET "\n\n");
    printf("  " CLR_BOLD "Vendor:" CLR_RESET "       %s (Samsung Electronics)\n", dev.vendor_id);
    printf("  " CLR_BOLD "Product ID:" CLR_RESET "   %s\n", dev.product_id);
    printf("  " CLR_BOLD "Serial:" CLR_RESET "       %s\n", dev.serial);
    printf("  " CLR_BOLD "USB Speed:" CLR_RESET "    %s\n", dev.speed);

    device_state_t state = identify_state(&dev);
    printf("  " CLR_BOLD "Device State:" CLR_RESET " ");
    switch (state) {
    case STATE_NORMAL_MTP:
        color_print(CLR_GREEN, "%s\n", state_str(state));
        break;
    case STATE_DOWNLOAD:
        color_print(CLR_CYAN, "%s\n", state_str(state));
        break;
    case STATE_RECOVERY:
        color_print(CLR_YELLOW, "%s\n", state_str(state));
        break;
    default:
        printf("%s\n", state_str(state));
    }

    /* serial decode */
    if (dev.serial[0]) {
        printf("\n");
        decode_serial(dev.serial);
    }

    /* step 2: determine AFU/BFU from USB state */
    printf("\n" CLR_BOLD "  [PHASE 2] Device State Analysis\n" CLR_RESET);
    print_separator();

    if (state == STATE_NORMAL_MTP) {
        printf("\n  USB PID 0x6860 = normal Android MTP/charging mode.\n");
        printf("  Device has fully booted into Android OS.\n\n");

        printf("  " CLR_BOLD "AFU/BFU Assessment:" CLR_RESET "\n");
        printf("  Device is in " CLR_YELLOW "NORMAL" CLR_RESET " operating mode (not recovery/download).\n");
        printf("  If the user has unlocked the device at least once since boot:\n");
        printf("    -> " CLR_RED "AFU state: CE encryption keys in memory" CLR_RESET "\n");
        printf("    -> ~95%% of user data accessible via forensic extraction\n\n");
        printf("  " CLR_DIM "Indicators of AFU: notifications on lock screen, background\n"
               "  sync activity, push notifications arriving." CLR_RESET "\n");
    } else if (state == STATE_DOWNLOAD) {
        printf("\n  " CLR_CYAN "Device is in Download (Odin) mode." CLR_RESET "\n");
        printf("  This is the firmware flashing interface.\n");
        printf("  Potential for bootloader-level interaction.\n");
    } else if (state == STATE_RECOVERY) {
        printf("\n  " CLR_YELLOW "Device is in Recovery mode." CLR_RESET "\n");
        printf("  Stock Samsung recovery has limited functionality.\n");
    }

    /* step 3: try ADB */
    printf("\n" CLR_BOLD "  [PHASE 3] ADB Probe\n" CLR_RESET);
    print_separator();

    char adb_model[64] = {0};
    char adb_patch[32] = {0};
    char adb_android[16] = {0};
    bool adb_ok = try_adb(adb_model, sizeof(adb_model),
                          adb_patch, sizeof(adb_patch),
                          adb_android, sizeof(adb_android));

    if (adb_ok) {
        printf("\n  " CLR_GREEN "ADB connection established!" CLR_RESET "\n\n");
        printf("  " CLR_BOLD "Model:" CLR_RESET "           %s\n", adb_model);
        printf("  " CLR_BOLD "Android:" CLR_RESET "         %s\n", adb_android[0] ? adb_android : "unknown");
        printf("  " CLR_BOLD "Security Patch:" CLR_RESET "  %s\n", adb_patch[0] ? adb_patch : "unknown");

        /* auto-run CVE scan if we got model and patch */
        if (adb_model[0] && adb_patch[0]) {
            printf("\n  " CLR_GREEN "Auto-running CVE scan and assessment..." CLR_RESET "\n");
            printf("\n");
            cve_scan(adb_model, adb_patch);
            printf("\n");
            assess_device(adb_model, adb_patch);
            return 0;
        }
    } else {
        printf("\n  " CLR_YELLOW "ADB not available." CLR_RESET "\n");
        printf("  Reason: USB debugging disabled or computer not authorized.\n");
        printf("  " CLR_DIM "This is expected for a locked device." CLR_RESET "\n");
    }

    /* step 4: summary and recommendations */
    printf("\n" CLR_BOLD "  [PHASE 4] Reconnaissance Summary\n" CLR_RESET);
    print_separator();

    printf("\n  " CLR_BOLD "Confirmed:" CLR_RESET "\n");
    printf("    - Samsung device on USB (VID 0x04e8)\n");
    printf("    - Serial: %s\n", dev.serial);
    printf("    - USB mode: %s\n", state_str(state));

    if (state == STATE_NORMAL_MTP)
        printf("    - Device has booted into Android (likely AFU)\n");

    if (!adb_ok) {
        printf("\n  " CLR_BOLD "Not available without ADB:" CLR_RESET "\n");
        printf("    - Exact model number\n");
        printf("    - Security patch level\n");
        printf("    - Android version\n");
        printf("    - Knox warranty fuse state\n");

        printf("\n  " CLR_BOLD "To proceed, provide model manually:" CLR_RESET "\n");
        printf("    sampass assess <model> <patch-date>\n");
        printf("    sampass cve-scan <model> <patch-date>\n");

        printf("\n  " CLR_BOLD "Alternative recon methods:" CLR_RESET "\n");
        printf("    1. " CLR_CYAN "Physical inspection" CLR_RESET " — model on SIM tray or back label\n");
        printf("    2. " CLR_CYAN "IMEI via dialer" CLR_RESET " — *#06# on emergency dial screen\n");
        printf("       -> cross-reference IMEI at imei.info for model/specs\n");
        printf("    3. " CLR_CYAN "Download Mode" CLR_RESET " — Vol Down + Power (off) + USB\n");
        printf("       -> shows model, bootloader version, Knox status on screen\n");
        printf("       " CLR_RED "WARNING:" CLR_RESET " requires power cycle (device returns to BFU!)\n");
        printf("    4. " CLR_CYAN "Emergency dialer" CLR_RESET " — some firmware shows model in\n");
        printf("       About Phone accessible from emergency screen\n");
    }

    printf("\n");
    return 0;
}
