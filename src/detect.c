#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libusb-1.0/libusb.h>
#include "sampass.h"

/* USB product IDs for Samsung Galaxy modes */
#define SAMSUNG_VID_N       0x04E8
#define PID_MTP_N           0x6860  /* Normal MTP mode */
#define PID_DOWNLOAD_N      0x6601  /* Odin/Download mode */
#define PID_DOWNLOAD_V2_N   0x685D  /* Odin/Download mode (SM8250+) */
#define PID_RECOVERY_N      0x6862  /* Recovery mode */
#define QC_VID_N            0x05C6
#define PID_EDL_N           0x9008  /* Qualcomm EDL mode */

typedef struct {
    uint16_t vid;
    uint16_t pid;
    char serial[64];
    char manufacturer[64];
    char product_name[64];
    bool found;
} usb_device_t;

typedef enum {
    STATE_NORMAL_MTP = 0,
    STATE_DOWNLOAD,
    STATE_DOWNLOAD_V2,
    STATE_RECOVERY,
    STATE_EDL,
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

/* scan USB bus using libusb (cross-platform) */
static bool scan_usb_libusb(usb_device_t *dev)
{
    memset(dev, 0, sizeof(*dev));

    int rc = libusb_init(NULL);
    if (rc != 0) return false;

    libusb_device **devs;
    ssize_t cnt = libusb_get_device_list(NULL, &devs);
    if (cnt < 0) {
        libusb_exit(NULL);
        return false;
    }

    /* Samsung PIDs to look for, in priority order */
    struct { uint16_t vid; uint16_t pid; } targets[] = {
        {QC_VID_N,     PID_EDL_N},
        {SAMSUNG_VID_N, PID_DOWNLOAD_N},
        {SAMSUNG_VID_N, PID_DOWNLOAD_V2_N},
        {SAMSUNG_VID_N, PID_MTP_N},
        {SAMSUNG_VID_N, PID_RECOVERY_N},
        {0, 0}
    };

    for (ssize_t i = 0; i < cnt && !dev->found; i++) {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(devs[i], &desc) != 0)
            continue;

        for (int t = 0; targets[t].vid != 0; t++) {
            if (desc.idVendor == targets[t].vid && desc.idProduct == targets[t].pid) {
                dev->found = true;
                dev->vid = desc.idVendor;
                dev->pid = desc.idProduct;

                libusb_device_handle *h;
                if (libusb_open(devs[i], &h) == 0) {
                    if (desc.iManufacturer)
                        libusb_get_string_descriptor_ascii(h, desc.iManufacturer,
                            (uint8_t *)dev->manufacturer, sizeof(dev->manufacturer));
                    if (desc.iProduct)
                        libusb_get_string_descriptor_ascii(h, desc.iProduct,
                            (uint8_t *)dev->product_name, sizeof(dev->product_name));
                    if (desc.iSerialNumber)
                        libusb_get_string_descriptor_ascii(h, desc.iSerialNumber,
                            (uint8_t *)dev->serial, sizeof(dev->serial));
                    libusb_close(h);
                }
                break;
            }
        }
    }

    libusb_free_device_list(devs, 1);
    libusb_exit(NULL);
    return dev->found;
}

static device_state_t identify_state(const usb_device_t *dev)
{
    if (dev->vid == QC_VID_N && dev->pid == PID_EDL_N)
        return STATE_EDL;
    if (dev->pid == PID_DOWNLOAD_N)
        return STATE_DOWNLOAD;
    if (dev->pid == PID_DOWNLOAD_V2_N)
        return STATE_DOWNLOAD_V2;
    if (dev->pid == PID_RECOVERY_N)
        return STATE_RECOVERY;
    if (dev->pid == PID_MTP_N)
        return STATE_NORMAL_MTP;
    return STATE_UNKNOWN;
}

static const char *state_str(device_state_t s)
{
    switch (s) {
    case STATE_NORMAL_MTP:   return "Normal (MTP/Charging)";
    case STATE_DOWNLOAD:     return "Download Mode (Odin)";
    case STATE_DOWNLOAD_V2:  return "Download Mode (Odin v2 / SM8250+)";
    case STATE_RECOVERY:     return "Recovery Mode";
    case STATE_EDL:          return "EDL (Qualcomm QDLoader 9008)";
    case STATE_UNKNOWN:      return "Unknown";
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

    const char *line2 = strchr(devices, '\n');
    bool has_device = false;
    if (line2) {
        line2++;
        while (*line2 == '\n') line2++;
        if (*line2 && *line2 != '\0')
            has_device = true;
    }
    free(devices);

    if (!has_device) return false;

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

    if (serial[0] == 'R')
        printf("    Prefix:   R (Samsung mobile device)\n");

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
    if (!scan_usb_libusb(&dev)) {
        color_print(CLR_RED, "\n  No Samsung device found on USB.\n");
        printf("  Ensure the phone is connected via USB cable.\n\n");
        printf("  " CLR_BOLD "Troubleshooting:" CLR_RESET "\n");
        printf("   - Try a different USB cable (some are charge-only)\n");
        printf("   - Try a different USB port\n");
        printf("   - Check if the phone is powered on\n");
        printf("   - On Linux, you may need root or udev rules for USB access\n\n");
        return 1;
    }

    printf("\n  " CLR_GREEN "Samsung device detected on USB bus." CLR_RESET "\n\n");
    printf("  " CLR_BOLD "Vendor:" CLR_RESET "       %04x (%s)\n", dev.vid,
           dev.manufacturer[0] ? dev.manufacturer : "Samsung Electronics");
    printf("  " CLR_BOLD "Product ID:" CLR_RESET "   %04x", dev.pid);
    if (dev.product_name[0]) printf(" (%s)", dev.product_name);
    printf("\n");
    printf("  " CLR_BOLD "Serial:" CLR_RESET "       %s\n", dev.serial[0] ? dev.serial : "(unavailable)");

    device_state_t state = identify_state(&dev);
    printf("  " CLR_BOLD "Device State:" CLR_RESET " ");
    switch (state) {
    case STATE_NORMAL_MTP:
        color_print(CLR_GREEN, "%s\n", state_str(state));
        break;
    case STATE_DOWNLOAD:
    case STATE_DOWNLOAD_V2:
        color_print(CLR_CYAN, "%s\n", state_str(state));
        break;
    case STATE_EDL:
        color_print(CLR_RED, "%s\n", state_str(state));
        break;
    case STATE_RECOVERY:
        color_print(CLR_YELLOW, "%s\n", state_str(state));
        break;
    default:
        printf("%s\n", state_str(state));
    }

    if (dev.serial[0]) {
        printf("\n");
        decode_serial(dev.serial);
    }

    /* step 2: determine state analysis */
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
    } else if (state == STATE_DOWNLOAD || state == STATE_DOWNLOAD_V2) {
        printf("\n  " CLR_CYAN "Device is in Download (Odin) mode." CLR_RESET "\n");
        printf("  This is the firmware flashing interface.\n");
        printf("  Run " CLR_BOLD "sampass odin" CLR_RESET " to initiate handshake.\n");
    } else if (state == STATE_EDL) {
        printf("\n  " CLR_RED "Device is in Qualcomm EDL mode (QDLoader 9008)." CLR_RESET "\n");
        printf("  This is the most powerful access mode.\n");
        printf("  Run " CLR_BOLD "sampass edl" CLR_RESET " to initiate Sahara protocol.\n");
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

    /* step 4: next steps */
    printf("\n" CLR_BOLD "  [PHASE 4] Recommended Next Steps\n" CLR_RESET);
    print_separator();

    printf("\n  " CLR_BOLD "Confirmed:" CLR_RESET "\n");
    printf("    - Device on USB (VID %04x, PID %04x)\n", dev.vid, dev.pid);
    if (dev.serial[0])
        printf("    - Serial: %s\n", dev.serial);
    printf("    - USB mode: %s\n", state_str(state));

    if (state == STATE_NORMAL_MTP) {
        printf("\n  " CLR_BOLD "Next:" CLR_RESET "\n");
        printf("    " CLR_CYAN "sampass extract" CLR_RESET "             — probe AT modem + MTP from lock screen\n");
        printf("    " CLR_CYAN "sampass fullchain SM-G780G" CLR_RESET "  — automated attack sequence\n");
        printf("    " CLR_CYAN "sampass gadget-setup ./pi" CLR_RESET "   — generate USB exploit scripts for Pi Zero\n");
    } else if (state == STATE_DOWNLOAD || state == STATE_DOWNLOAD_V2) {
        printf("\n  " CLR_BOLD "Next:" CLR_RESET "\n");
        printf("    " CLR_CYAN "sampass odin" CLR_RESET "               — Odin handshake + PIT dump\n");
        printf("    " CLR_CYAN "sampass fullchain SM-G780G" CLR_RESET "  — auto: odin -> crash -> EDL -> exploit\n");
    } else if (state == STATE_EDL) {
        printf("\n  " CLR_BOLD "Next:" CLR_RESET "\n");
        printf("    " CLR_CYAN "sampass edl" CLR_RESET "                — Sahara protocol handshake\n");
        printf("    " CLR_CYAN "sampass exploit-gen" CLR_RESET "        — generate PBL overflow payload\n");
        printf("    " CLR_CYAN "sampass edl-push payload" CLR_RESET "   — push exploit via Sahara\n");
    } else if (!adb_ok) {
        printf("\n  " CLR_BOLD "To proceed, provide model manually:" CLR_RESET "\n");
        printf("    sampass assess <model> <patch-date>\n");
        printf("    sampass fullchain <model>\n");
    }

    printf("\n");
    return 0;
}
