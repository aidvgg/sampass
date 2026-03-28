#include <stdio.h>
#include <string.h>
#include "sampass.h"

/* check if device patch level is before a given date */
static bool is_before(const char *device_patch, const char *threshold)
{
    return strcmp(device_patch, threshold) < 0;
}

int assess_device(const char *model, const char *patch_date)
{
    chipset_t chip = model_to_chipset(model);

    if (chip == CHIP_UNKNOWN) {
        color_print(CLR_YELLOW, "  warning: unrecognized model '%s', assuming Exynos\n\n", model);
        chip = CHIP_EXYNOS;
    }

    print_section_header("ATTACK PATH ASSESSMENT — Photo Extraction");

    printf("  " CLR_BOLD "Target:" CLR_RESET "     %s (%s)\n", model, chipset_str(chip));
    printf("  " CLR_BOLD "Patch:" CLR_RESET "      %s\n", patch_date);
    printf("  " CLR_BOLD "Objective:" CLR_RESET "   Extract user photos from locked device\n");
    printf("  " CLR_BOLD "Constraint:" CLR_RESET "  Physical access to device (professor-provided)\n");

    /* count applicable paths */
    int path_num = 0;

    /* PATH 1: AFU forensic extraction — always the first check */
    print_section_header("PATH 1: AFU State Exploitation (Highest Priority)");
    path_num++;

    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    color_print(CLR_GREEN, "HIGH");
    printf(" (if device is in AFU state)\n");
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " File-Based Encryption (CE key domain)\n");
    printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n\n");

    printf("  " CLR_BOLD "Rationale:" CLR_RESET "\n");
    printf("  If the S20 FE has been unlocked at least once since last boot,\n");
    printf("  CE encryption keys are cached in kernel memory. ~95%% of user\n");
    printf("  data — including " CLR_YELLOW "all photos" CLR_RESET " — is accessible via forensic extraction.\n\n");

    printf("  " CLR_BOLD "Steps:" CLR_RESET "\n");
    printf("   1. Verify device is powered on and has been unlocked since boot\n");
    printf("      (check: notifications visible on lock screen = AFU)\n");
    printf("   2. Connect via ADB if USB debugging was enabled, or\n");
    printf("   3. Use forensic tool with AFU extraction capability\n");
    printf("   4. CE keys in memory allow decryption of /data/media/0/DCIM/*\n\n");

    printf("  " CLR_BOLD "Tools:" CLR_RESET " Cellebrite UFED (FFS), GrayKey, or MSAB XRY Pro\n");
    printf("  " CLR_BOLD "Photos at:" CLR_RESET " /data/media/0/DCIM/Camera/\n");
    printf("  " CLR_BOLD "Also:" CLR_RESET "      /data/media/0/Pictures/, app-specific media dirs\n");

    /* PATH 2: Keymaster IV reuse */
    bool km_vuln = is_before(patch_date, "2021-08-01");
    print_section_header("PATH 2: Keymaster IV Reuse (CVE-2021-25444/25490)");
    path_num++;

    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    if (km_vuln) {
        color_print(CLR_GREEN, "HIGH");
        printf(" (device patch %s is before 2021-08-01 fix)\n", patch_date);
    } else {
        color_print(CLR_RED, "BLOCKED");
        printf(" (patched at %s, fix was 2021-08-01)\n", patch_date);
    }
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " TrustZone TEE (Keymaster TA)\n");
    printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n\n");

    if (km_vuln) {
        printf("  " CLR_RED "THIS DEVICE IS VULNERABLE." CLR_RESET "\n\n");
        printf("  " CLR_BOLD "Attack Strategy:" CLR_RESET "\n");
        printf("   1. Extract encrypted key blobs from /data/misc/keystore/\n");
        printf("   2. Identify blobs encrypted with the same IV (deterministic derivation)\n");
        printf("   3. XOR ciphertexts to obtain P1 XOR P2\n");
        printf("   4. Use known key blob header structure to recover plaintext key material\n");
        printf("   5. Recover GHASH key H from tag comparison for forgery capability\n");
        printf("   6. Decrypt CE file encryption keys -> access all user photos\n\n");

        printf("  " CLR_BOLD "Downgrade option (CVE-2021-25490):" CLR_RESET "\n");
        printf("   Force Keymaster to generate legacy v15 format blobs even if newer\n");
        printf("   format is default. v15 blobs use the vulnerable IV derivation.\n\n");

        printf("  " CLR_YELLOW "Run 'sampass keymaster-demo' to see the cryptographic proof." CLR_RESET "\n");
    } else {
        printf("  Samsung removed the legacy v15 blob implementation entirely.\n");
        printf("  IV reuse is no longer possible on this patch level.\n");
    }

    /* PATH 3: Baseband RCE (Exynos only) */
    if (chip == CHIP_EXYNOS) {
        bool bb_vuln = is_before(patch_date, "2023-03-01");
        print_section_header("PATH 3: Baseband RCE (CVE-2023-24033) [Exynos Only]");
        path_num++;

        printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
        if (bb_vuln) {
            color_print(CLR_ORANGE, "MEDIUM-HIGH");
            printf(" (requires baseband exploit development)\n");
        } else {
            color_print(CLR_RED, "BLOCKED");
            printf(" (patched at %s)\n", patch_date);
        }
        printf("  " CLR_BOLD "Target Layer:" CLR_RESET " Baseband (Exynos Modem 5123)\n");
        printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n\n");

        if (bb_vuln) {
            printf("  " CLR_RED "THIS DEVICE IS VULNERABLE." CLR_RESET "\n\n");
            printf("  The Shannon baseband has NO ASLR and STATIC stack cookies.\n\n");
            printf("  " CLR_BOLD "Attack Chain:" CLR_RESET "\n");
            printf("   1. Send crafted SIP/SDP packets to device's phone number\n");
            printf("   2. Trigger buffer overflow in baseband processor (zero-click)\n");
            printf("   3. Achieve code execution in baseband context\n");
            printf("   4. Pivot from baseband to application processor via shared memory\n");
            printf("   5. Escalate to kernel -> access CE-encrypted storage\n\n");
            printf("  " CLR_YELLOW "NOTE: This is a REMOTE attack — doesn't even require physical access.\n" CLR_RESET);
        } else {
            printf("  Baseband vulnerabilities patched at this firmware level.\n");
        }
    }

    /* PATH 4: TA Rollback attack */
    path_num++;
    {
        char hdr[64];
        snprintf(hdr, sizeof(hdr), "PATH %d: Trusted Application Rollback", path_num);
        print_section_header(hdr);
    }

    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    color_print(CLR_ORANGE, "MEDIUM");
    printf(" (rollback counter NEVER incremented on S20)\n");
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " TrustZone TEE (TA loading mechanism)\n");
    printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n\n");

    printf("  " CLR_RED "CONFIRMED VULNERABLE" CLR_RESET " — USENIX Security 2024 verified S20 WVDRM TA\n");
    printf("  rollback counter was never incremented by Samsung.\n\n");

    printf("  " CLR_BOLD "Attack Strategy:" CLR_RESET "\n");
    printf("   1. Obtain older vulnerable TA binaries (pre-patch versions)\n");
    printf("   2. TA binaries are stored in Normal World (/vendor/tee, /system/tee)\n");
    printf("   3. Replace current TA with older vulnerable version on filesystem\n");
    printf("   4. TEE loads old TA without rollback check\n");
    printf("   5. Exploit known vulnerability in loaded TA\n\n");

    printf("  " CLR_BOLD "Chain with:" CLR_RESET "\n");
    printf("   - Roll back Keymaster TA -> exploit CVE-2021-25444 (IV reuse)\n");
    printf("   - Roll back HDCP TA -> exploit Riscure TEE compromise chain\n");
    printf("   " CLR_YELLOW "Requires filesystem write access (root or recovery mode).\n" CLR_RESET);

    /* PATH 5: Bootloader unlock (destructive) */
    path_num++;
    {
        char hdr[64];
        snprintf(hdr, sizeof(hdr), "PATH %d: Bootloader Unlock + Custom Recovery", path_num);
        print_section_header(hdr);
    }

    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    if (chip == CHIP_SNAPDRAGON) {
        bool is_us = (strncasecmp(model + 7, "U", 1) == 0);
        if (is_us) {
            color_print(CLR_RED, "BLOCKED");
            printf(" (US carrier Snapdragon — permanently locked)\n");
        } else {
            color_print(CLR_YELLOW, "LOW");
            printf(" (Snapdragon — check OEM unlock availability)\n");
        }
    } else {
        color_print(CLR_YELLOW, "LOW-MEDIUM");
        printf(" (Exynos international — OEM unlock typically available)\n");
    }
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " Bootloader / Recovery\n");
    printf("  " CLR_RED "  Destructive:  YES — mandatory factory reset + potential Knox fuse trip\n" CLR_RESET "\n");

    printf("  " CLR_BOLD "Steps:" CLR_RESET "\n");
    printf("   1. Enable OEM Unlock in Developer Options (requires device unlock!)\n");
    printf("   2. Boot to Download Mode (Vol Down + Power + USB)\n");
    printf("   3. Unlock bootloader -> " CLR_RED "MANDATORY FACTORY RESET" CLR_RESET "\n");
    printf("   4. Flash custom recovery (TWRP) -> " CLR_RED "KNOX FUSE TRIPPED" CLR_RESET "\n");
    printf("   5. Mount /data partition from recovery\n\n");

    printf("  " CLR_RED "PROBLEM: Factory reset performs CRYPTOGRAPHIC ERASURE." CLR_RESET "\n");
    printf("  All encryption keys are destroyed. Photos are gone.\n");
    printf("  " CLR_RED "This path DESTROYS the data we're trying to extract." CLR_RESET "\n");
    printf("  Only useful if device was already unlocked and unencrypted.\n");

    /* PATH 6: Secure Element exploitation */
    path_num++;
    {
        char hdr[64];
        snprintf(hdr, sizeof(hdr), "PATH %d: Secure Element Exploitation (\"Chip Chop\")", path_num);
        print_section_header(hdr);
    }

    bool se_vuln = is_before(patch_date, "2025-06-01");
    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    if (se_vuln) {
        color_print(CLR_ORANGE, "MEDIUM");
        printf(" (requires REE root + SE exploit tooling)\n");
    } else {
        color_print(CLR_RED, "BLOCKED");
        printf(" (patched after responsible disclosure)\n");
    }
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " Secure Element (S3K250AF)\n");
    printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n\n");

    if (se_vuln) {
        printf("  " CLR_BOLD "Attack Chain:" CLR_RESET "\n");
        printf("   1. Gain root in Rich Execution Environment (via kernel exploit)\n");
        printf("   2. Send crafted commands to S3K250AF secure element\n");
        printf("   3. Trigger buffer overflow in SE firmware\n");
        printf("   4. Bypass PIN verification logic\n");
        printf("   5. Transition device from BFU -> AFU in ~90 seconds\n");
        printf("   6. CE keys become available -> extract photos\n\n");
        printf("  " CLR_YELLOW "Bypasses the lock screen entirely without knowing credentials.\n" CLR_RESET);
    } else {
        printf("  Samsung patched the SE buffer overflow after responsible disclosure.\n");
    }

    /* PATH: USB Kernel Exploit Chain (Cellebrite method) */
    path_num++;
    {
        char hdr[80];
        snprintf(hdr, sizeof(hdr), "PATH %d: USB Kernel Exploit Chain (Cellebrite Method)", path_num);
        print_section_header(hdr);
    }

    bool usb_uvc_vuln = is_before(patch_date, "2025-02-01");
    bool usb_alsa_vuln = is_before(patch_date, "2025-04-01");
    bool usb_hid_vuln = is_before(patch_date, "2025-03-01");
    /* Samsung S20 FE near end-of-life — April 2025 kernel patch may lag */
    bool usb_chain_possible = usb_uvc_vuln || usb_alsa_vuln || usb_hid_vuln;

    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    if (usb_chain_possible) {
        color_print(CLR_GREEN, "HIGH");
        printf(" (%s unpatched)\n",
               usb_alsa_vuln ? "USB audio CVE-2024-53197" :
               usb_hid_vuln  ? "USB HID CVE-2024-50302" :
                               "USB UVC CVE-2024-53104");
    } else {
        color_print(CLR_YELLOW, "UNCERTAIN");
        printf(" (Samsung may not have backported April 2025 kernel patches)\n");
    }
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " Linux Kernel USB drivers (UVC + ALSA + HID)\n");
    printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n");
    printf("  " CLR_BOLD "Access:" CLR_RESET "       Physical USB-C connection (no unlock needed)\n\n");

    printf("  " CLR_BOLD "Background:" CLR_RESET "\n");
    printf("  In December 2024, Cellebrite used this exact chain to unlock a\n");
    printf("  Samsung Galaxy A32 belonging to a Serbian student activist.\n");
    printf("  Amnesty International documented the attack. PoC code is public.\n\n");

    printf("  " CLR_BOLD "CVE Chain:" CLR_RESET "\n");
    printf("   " CLR_CYAN "CVE-2024-53104" CLR_RESET " UVC driver heap overflow     patch: Feb 2025  %s\n",
           usb_uvc_vuln ? CLR_RED "UNPATCHED" CLR_RESET : CLR_GREEN "patched" CLR_RESET);
    printf("   " CLR_CYAN "CVE-2024-53197" CLR_RESET " ALSA audio corruption        patch: Apr 2025  %s\n",
           usb_alsa_vuln ? CLR_RED "UNPATCHED" CLR_RESET : CLR_YELLOW "uncertain" CLR_RESET);
    printf("   " CLR_CYAN "CVE-2024-50302" CLR_RESET " HID kernel memory leak       patch: Mar 2025  %s\n\n",
           usb_hid_vuln ? CLR_RED "UNPATCHED" CLR_RESET : CLR_GREEN "patched" CLR_RESET);

    printf("  " CLR_BOLD "Attack Steps:" CLR_RESET "\n");
    printf("   1. Connect USB-C OTG adapter to phone\n");
    printf("   2. Attach device emulating malicious USB peripherals:\n");
    printf("      - Chicony CNF7129 UVC Webcam  -> triggers heap overflow\n");
    printf("      - Creative Extigy SoundBlaster -> corrupts kernel memory\n");
    printf("      - Anton Touch Pad              -> leaks kernel heap (keys)\n");
    printf("   3. Phone kernel auto-enumerates devices " CLR_RED "(even while locked)" CLR_RESET "\n");
    printf("   4. Chain achieves: heap overflow -> memory corruption -> info leak\n");
    printf("   5. Result: " CLR_RED "root shell in ~10 seconds" CLR_RESET "\n");
    printf("   6. Disable lock screen, mount /data, extract photos\n\n");

    printf("  " CLR_BOLD "Hardware Required:" CLR_RESET "\n");
    printf("   - USB-C OTG adapter (~$5)\n");
    printf("   - Raspberry Pi Zero W with USB gadget mode (~$10), OR\n");
    printf("   - Facedancer/Cynthion USB emulation board (~$85)\n\n");

    printf("  " CLR_BOLD "Software:" CLR_RESET "\n");
    printf("   - CVE-2024-53104 PoC: 6 public exploits on GitHub\n");
    printf("   - USB gadget framework for peripheral emulation\n");
    printf("   - Linux configfs for USB device descriptor crafting\n");

    /* PATH: Post-firmware CVEs */
    bool has_post_firmware = is_before(patch_date, "2025-12-01");
    if (has_post_firmware) {
        path_num++;
        char hdr[80];
        snprintf(hdr, sizeof(hdr), "PATH %d: Post-Firmware Unpatched CVEs (10+ months)", path_num);
        print_section_header(hdr);

        printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
        color_print(CLR_ORANGE, "MEDIUM");
        printf(" (requires initial code execution for chaining)\n");
        printf("  " CLR_BOLD "Target Layer:" CLR_RESET " Android Framework + Qualcomm GPU\n");
        printf("  " CLR_BOLD "Destructive:" CLR_RESET "  No\n\n");

        printf("  Device firmware is from %s. CVEs discovered since then are\n", patch_date);
        printf("  " CLR_RED "DEFINITELY UNPATCHED" CLR_RESET ":\n\n");

        printf("  " CLR_CYAN "CVE-2025-48572" CLR_RESET "  Dec 2025  Framework EoP   Android 13  " CLR_RED "ACTIVE EXPLOITATION" CLR_RESET "\n");
        printf("  " CLR_CYAN "CVE-2025-48633" CLR_RESET "  Dec 2025  Framework Leak  Android 13  " CLR_RED "ACTIVE EXPLOITATION" CLR_RESET "\n");
        printf("  " CLR_CYAN "CVE-2026-21385" CLR_RESET "  Mar 2026  Adreno GPU      SD865       " CLR_RED "ACTIVE EXPLOITATION" CLR_RESET "\n\n");

        printf("  " CLR_BOLD "Chain Strategy:" CLR_RESET "\n");
        printf("   USB kernel exploit (root) -> CVE-2026-21385 (GPU persistence)\n");
        printf("   -> CVE-2025-48572 (framework escalation) -> full device access\n");
    }

    /* PATH: EDL + Firehose */
    if (chip == CHIP_SNAPDRAGON) {
        path_num++;
        char hdr[80];
        snprintf(hdr, sizeof(hdr), "PATH %d: Qualcomm EDL + Firehose Partition Dump", path_num);
        print_section_header(hdr);

        printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
        color_print(CLR_YELLOW, "LOW-MEDIUM");
        printf(" (requires disassembly + signed loader + FBE still blocks data)\n");
        printf("  " CLR_BOLD "Target Layer:" CLR_RESET " Qualcomm PBL (Sahara/Firehose protocol)\n");
        printf("  " CLR_BOLD "Destructive:" CLR_RESET "  Requires opening device\n\n");

        printf("  " CLR_BOLD "Steps:" CLR_RESET "\n");
        printf("   1. Open device, locate EDL test points on PCB (documented)\n");
        printf("   2. Short test points while connecting USB -> QDLoader 9008\n");
        printf("   3. Load SM-G780G firehose programmer via Sahara protocol\n");
        printf("   4. Issue Firehose XML commands to dump partitions\n\n");

        printf("  " CLR_RED "Limitation:" CLR_RESET " Raw partition dump is FBE-encrypted.\n");
        printf("  Without CE keys (which require passcode + hardware key derivation),\n");
        printf("  the dumped photos are AES-256-XTS encrypted blobs.\n");
        printf("  " CLR_YELLOW "Useful for: metadata analysis, partition layout, non-encrypted areas.\n" CLR_RESET);
    }

    /* PATH: Chip-off (always ineffective) */
    path_num++;
    {
        char hdr[64];
        snprintf(hdr, sizeof(hdr), "PATH %d: Chip-Off (Physical NAND Extraction)", path_num);
        print_section_header(hdr);
    }

    printf("  " CLR_BOLD "Feasibility:" CLR_RESET "  ");
    color_print(CLR_RED, "INEFFECTIVE\n");
    printf("  " CLR_BOLD "Target Layer:" CLR_RESET " UFS NAND Flash\n");
    printf("  " CLR_BOLD "Destructive:" CLR_RESET "  Yes (desoldering destroys device)\n\n");

    printf("  " CLR_RED "DO NOT ATTEMPT." CLR_RESET " Samsung S20 FE uses File-Based Encryption.\n");
    printf("  Removing the UFS chip separates it from the TEE and Secure Element\n");
    printf("  hardware required for decryption. The data is unreadable.\n");

    /* RECOMMENDATION */
    print_section_header("RECOMMENDED APPROACH FOR PHOTO EXTRACTION");

    printf(CLR_BOLD "  Priority 1: USB Kernel Exploit Chain (Cellebrite Method)\n" CLR_RESET);
    printf("  Connect malicious USB peripherals via USB-C OTG. Phone kernel\n");
    printf("  auto-enumerates devices even while locked. Three chained CVEs\n");
    printf("  achieve root shell in ~10 seconds. PoC code is publicly available.\n");
    printf("  " CLR_GREEN "Best path: works on locked device, non-destructive, cheap hardware." CLR_RESET "\n\n");

    printf(CLR_BOLD "  Priority 2: Check AFU State\n" CLR_RESET);
    printf("  If device has been unlocked since last boot, CE keys are in RAM.\n");
    printf("  USB exploit gives root -> read CE keys from memory -> decrypt photos.\n\n");

    if (km_vuln) {
        printf(CLR_BOLD "  Priority 3: Keymaster IV Reuse (CVE-2021-25444)\n" CLR_RESET);
        printf("  Device patch level (%s) is BEFORE the fix.\n", patch_date);
        printf("  Extract key blobs, exploit nonce reuse, decrypt CE keys.\n\n");
    } else {
        printf(CLR_BOLD "  Priority 3: TA Rollback + Keymaster IV Reuse\n" CLR_RESET);
        printf("  S20's TA rollback counter was never incremented (USENIX 2024).\n");
        printf("  With root from USB exploit: replace Keymaster TA with pre-patch\n");
        printf("  version -> exploit IV reuse -> decrypt CE keys -> photos.\n\n");
    }

    if (se_vuln) {
        printf(CLR_BOLD "  Fallback: Chip Chop (SE Exploitation)\n" CLR_RESET);
        printf("  BFU->AFU bypass via secure element buffer overflow.\n");
        printf("  Use if device is in BFU state and other paths are blocked.\n\n");
    }

    printf(CLR_RED "  AVOID: Bootloader unlock (destroys data) and chip-off (ineffective).\n" CLR_RESET);
    printf("\n");

    return 0;
}
