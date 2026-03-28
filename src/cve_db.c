#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "sampass.h"

static cve_entry_t cve_database[] = {
    {
        .cve_id          = "CVE-2021-25444",
        .title           = "Keymaster IV Reuse — AES-GCM Nonce Reuse",
        .cvss            = 9.8f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "TrustZone TEE (Keymaster TA)",
        .patch_date      = "2021-08-01",
        .description     = "Samsung's Keymaster TA wrapped key blobs using AES-GCM-256 with a\n"
                           "    reused initialization vector. The IV was derived deterministically,\n"
                           "    causing nonce reuse across different key blob encryptions. AES-GCM\n"
                           "    with a reused nonce is catastrophically broken: XORing two ciphertexts\n"
                           "    yields the XOR of their plaintexts, and tag comparison leaks the\n"
                           "    GHASH key H, enabling authentication forgery.",
        .impact          = "Full decryption of hardware-protected key blobs. ~100 million devices.",
        .exploitation    = "Extract encrypted key blobs from filesystem, exploit IV reuse to\n"
                           "    recover plaintext key material without TEE access."
    },
    {
        .cve_id          = "CVE-2021-25490",
        .title           = "Keymaster Downgrade Attack",
        .cvss            = 7.8f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "TrustZone TEE (Keymaster TA)",
        .patch_date      = "2021-10-01",
        .description     = "The Keymaster TA supported legacy v15 key blob format alongside newer\n"
                           "    formats. An attacker could force key generation using the vulnerable\n"
                           "    v15 format on S10/S20/S21 devices, even if the current firmware\n"
                           "    would normally use a patched format.",
        .impact          = "Enables CVE-2021-25444 exploitation on patched devices via downgrade.",
        .exploitation    = "Trigger legacy blob generation through TA interface, then apply IV\n"
                           "    reuse attack on the resulting v15 blobs."
    },
    {
        .cve_id          = "CVE-2023-24033",
        .title           = "Exynos Modem — Internet-to-Baseband RCE",
        .cvss            = 9.8f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "Baseband (Exynos Modem 5123)",
        .patch_date      = "2023-03-01",
        .description     = "Buffer overflow in SDP (Session Description Protocol) handling in\n"
                           "    Samsung's Shannon baseband. Allows remote code execution in the\n"
                           "    baseband processor requiring only the victim's phone number.\n"
                           "    Zero user interaction needed. One of 18 zero-days found by\n"
                           "    Google Project Zero in Exynos modems.",
        .impact          = "Full baseband compromise. Zero-click RCE via phone number only.",
        .exploitation    = "Send crafted SIP/SDP packets to target phone number. Baseband\n"
                           "    lacks ASLR and uses static stack cookies — exploitation is\n"
                           "    straightforward once the bug is reached."
    },
    {
        .cve_id          = "CVE-2023-26496",
        .title           = "Exynos Modem — Baseband RCE #2",
        .cvss            = 9.8f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "Baseband (Exynos Modem 5123)",
        .patch_date      = "2023-03-01",
        .description     = "Second of four critical zero-click RCE vulnerabilities in Samsung\n"
                           "    Shannon baseband. Part of the 18 zero-day set disclosed by\n"
                           "    Google Project Zero with delayed publication due to severity.",
        .impact          = "Remote baseband code execution. Zero-click.",
        .exploitation    = "Remote network-based exploitation via crafted signaling messages."
    },
    {
        .cve_id          = "CVE-2023-26497",
        .title           = "Exynos Modem — Baseband RCE #3",
        .cvss            = 9.8f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "Baseband (Exynos Modem 5123)",
        .patch_date      = "2023-03-01",
        .description     = "Third critical zero-click RCE in Shannon baseband. Google Project\n"
                           "    Zero delayed disclosure due to exceptional severity.",
        .impact          = "Remote baseband code execution. Zero-click.",
        .exploitation    = "Remote network-based exploitation."
    },
    {
        .cve_id          = "CVE-2023-26498",
        .title           = "Exynos Modem — Baseband RCE #4",
        .cvss            = 9.8f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "Baseband (Exynos Modem 5123)",
        .patch_date      = "2023-03-01",
        .description     = "Fourth critical zero-click RCE in Shannon baseband.",
        .impact          = "Remote baseband code execution. Zero-click.",
        .exploitation    = "Remote network-based exploitation."
    },
    {
        .cve_id          = "CVE-2024-44068",
        .title           = "Exynos 990 Use-After-Free — In-the-Wild Exploit",
        .cvss            = 8.1f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "Kernel (Exynos GPU driver)",
        .patch_date      = "2024-10-01",
        .description     = "Use-after-free in Exynos processors (including Exynos 990) discovered\n"
                           "    by Google TAG as actively exploited in the wild. Part of an\n"
                           "    advanced multi-stage attack chain.",
        .impact          = "Privilege escalation from app to kernel. Active exploitation confirmed.",
        .exploitation    = "Trigger UAF in GPU driver, spray controlled objects into freed\n"
                           "    allocation, pivot to arbitrary kernel read/write."
    },
    {
        .cve_id          = "CVE-2021-25337",
        .title           = "Samsung Clipboard Provider — Arbitrary File Read",
        .cvss            = 5.9f,
        .severity        = SEV_MEDIUM,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Android Framework",
        .patch_date      = "2021-03-01",
        .description     = "Part of a three-bug in-the-wild chain attributed to a commercial\n"
                           "    surveillance vendor. Samsung clipboard provider allowed arbitrary\n"
                           "    file read as system user.",
        .impact          = "Chain with CVE-2021-25369/25370 for full compromise. Surveillance use.",
        .exploitation    = "Craft intent to clipboard provider, read arbitrary files, chain\n"
                           "    with privilege escalation bugs for full access."
    },
    {
        .cve_id          = "CVE-2021-25369",
        .title           = "Samsung sec_log — Kernel Address Leak",
        .cvss            = 5.5f,
        .severity        = SEV_MEDIUM,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Kernel (Samsung driver)",
        .patch_date      = "2021-03-01",
        .description     = "Information disclosure through Samsung's sec_log exposed kernel\n"
                           "    addresses, defeating KASLR. Part of the surveillance vendor\n"
                           "    exploit chain (Maddie Stone, Project Zero 2022).",
        .impact          = "KASLR bypass enabling reliable kernel exploitation.",
        .exploitation    = "Read sec_log to obtain kernel base address, use to build ROP chain."
    },
    {
        .cve_id          = "CVE-2021-25370",
        .title           = "Samsung DSI Driver — Use-After-Free",
        .cvss            = 6.7f,
        .severity        = SEV_MEDIUM,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Kernel (Samsung display driver)",
        .patch_date      = "2021-03-01",
        .description     = "Use-after-free in Samsung's DSI display driver. Final link in the\n"
                           "    three-bug surveillance chain enabling full device compromise\n"
                           "    from an Android app.",
        .impact          = "Kernel code execution, completes the app-to-kernel chain.",
        .exploitation    = "Trigger UAF via display driver ioctl, use KASLR leak from\n"
                           "    CVE-2021-25369 to build reliable exploit."
    },
    {
        .cve_id          = "RISCURE-2020-TEE",
        .title           = "TEEGRIS Full TEE Compromise Chain (Riscure)",
        .cvss            = 9.0f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "TrustZone TEE (TEEGRIS + RKP Hypervisor)",
        .patch_date      = NULL,
        .description     = "Riscure demonstrated a full TEE compromise on Galaxy S10 (same\n"
                           "    TEEGRIS as S20): HDCP TA exploit -> ASLR bypass -> stack canary\n"
                           "    bypass -> kernel driver abuse for physical memory mapping ->\n"
                           "    TZASC register manipulation -> TEE memory unprotection ->\n"
                           "    hypervisor page table modification -> full TEE read/write.\n"
                           "    Root cause: coarse-grained permissions in HDCP TA.",
        .impact          = "Complete TEE memory read/write from an Android app.",
        .exploitation    = "Chain: HDCP TA bug -> physical memory map -> TZASC registers ->\n"
                           "    unprotect TEE memory -> modify hypervisor page tables."
    },
    {
        .cve_id          = "SVE-2019-15230",
        .title           = "S-Boot Code Execution via USB Download Mode",
        .cvss            = 7.5f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_EXYNOS,
        .affected_layer  = "Bootloader (S-Boot)",
        .patch_date      = "2020-01-01",
        .description     = "Quarkslab demonstrated arbitrary code execution in Samsung's\n"
                           "    S-Boot bootloader via USB download mode (Odin mode) on\n"
                           "    Galaxy S8/S9/S10. Presented at Black Hat USA 2020.",
        .impact          = "Code execution at bootloader level, below kernel and TEE init.",
        .exploitation    = "Connect via USB in download mode, send crafted Odin protocol\n"
                           "    packets to trigger buffer overflow in S-Boot."
    },
    {
        .cve_id          = "TA-ROLLBACK-S20",
        .title           = "Trusted Application Rollback — Anti-Rollback Not Enforced",
        .cvss            = 7.0f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "TrustZone TEE (TA Loading)",
        .patch_date      = NULL,
        .description     = "USENIX Security 2024 confirmed that the WVDRM TA rollback counter\n"
                           "    on the S20 was NEVER incremented. Old vulnerable TAs can be\n"
                           "    loaded even after patching. Samsung stores TA binaries in the\n"
                           "    Normal World filesystem, enabling replacement with older versions.",
        .impact          = "Bypass all TA patches by loading old vulnerable TA versions.",
        .exploitation    = "Replace TA binary on filesystem with older vulnerable version,\n"
                           "    TEE loads it without rollback check. Chain with known TA vulns."
    },
    {
        .cve_id          = "CHIP-CHOP-2025",
        .title           = "Secure Element Buffer Overflow — BFU-to-AFU Bypass",
        .cvss            = 8.5f,
        .severity        = SEV_CRITICAL,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Secure Element (S3K250AF)",
        .patch_date      = "2025-06-01",
        .description     = "\"Chip Chop\" research: single buffer overflow in the CC EAL5+\n"
                           "    certified S3K250AF secure element chip. Two-phase attack:\n"
                           "    (1) compromise REE to gain root, (2) exploit SE buffer overflow\n"
                           "    to bypass PIN verification and transition BFU -> AFU in ~90 sec\n"
                           "    without knowing user credentials.",
        .impact          = "Full device unlock from BFU state. All user data accessible.",
        .exploitation    = "Gain root via REE exploit, then send crafted commands to SE to\n"
                           "    trigger buffer overflow and bypass PIN verification logic."
    },
    /* === CELLEBRITE USB KERNEL EXPLOIT CHAIN (Dec 2024) === */
    {
        .cve_id          = "CVE-2024-53104",
        .title           = "USB Video Class (UVC) Heap Overflow — Cellebrite Chain #1",
        .cvss            = 7.8f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Kernel (USB UVC driver)",
        .patch_date      = "2025-02-01",
        .description     = "Out-of-bounds write in Linux kernel UVC driver (uvc_parse_format).\n"
                           "    Improper parsing of UVC_VS_UNDEFINED frames causes heap buffer\n"
                           "    overflow. Triggered by connecting a malicious USB video device\n"
                           "    to the phone via USB-C OTG. Kernel 2.6.26+ affected (incl 4.19).\n"
                           "    Part of Cellebrite's 3-CVE chain used to unlock a Samsung Galaxy\n"
                           "    A32 in Serbia (Dec 2024). PoC publicly available on GitHub.",
        .impact          = "Kernel code execution from physical USB access. Device unlock.",
        .exploitation    = "Connect Cellebrite Turbo Link (or emulated Chicony CNF7129 webcam)\n"
                           "    via USB-C. Malformed UVC descriptor triggers heap overflow.\n"
                           "    Chain with CVE-2024-53197 + CVE-2024-50302 for full root."
    },
    {
        .cve_id          = "CVE-2024-53197",
        .title           = "USB Audio (ALSA) Memory Corruption — Cellebrite Chain #2",
        .cvss            = 7.8f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Kernel (USB ALSA audio driver)",
        .patch_date      = "2025-04-01",
        .description     = "Out-of-bounds access in ALSA USB-audio driver for Extigy/Mbox\n"
                           "    devices. Insufficient validation of bLength in descriptor headers\n"
                           "    allows memory corruption during sound card initialization.\n"
                           "    Emulated Creative Extigy SoundBlaster triggers the bug.\n"
                           "    CISA KEV added April 2025. Samsung patch uncertain for older models.",
        .impact          = "Kernel memory corruption enabling privilege escalation chain.",
        .exploitation    = "Emulate Creative Extigy SoundBlaster via USB. Malformed audio\n"
                           "    descriptor corrupts kernel memory during ALSA initialization."
    },
    {
        .cve_id          = "CVE-2024-50302",
        .title           = "USB HID Kernel Memory Leak — Cellebrite Chain #3",
        .cvss            = 5.5f,
        .severity        = SEV_MEDIUM,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Kernel (USB HID driver)",
        .patch_date      = "2025-03-01",
        .description     = "Uninitialized memory in hid_alloc_report_buf (hid-core.c) leaks\n"
                           "    kernel memory contents to USB HID devices. Emulated Anton Touch\n"
                           "    Pad extracts uninitialized kernel heap data via HID reports.\n"
                           "    Leaks encryption keys, lock-screen credentials, kernel pointers.",
        .impact          = "Kernel information disclosure: encryption keys and credentials.",
        .exploitation    = "Emulate Anton Touch Pad via USB. Read HID reports containing\n"
                           "    uninitialized kernel heap — extract CE keys or lock credentials.\n"
                           "    Combined with CVE-2024-53104: root shell in ~10 seconds."
    },
    /* === POST-MAY-2025 (UNPATCHED on target device) === */
    {
        .cve_id          = "CVE-2025-48633",
        .title           = "Android Framework Info Disclosure — Active Exploitation",
        .cvss            = 7.5f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Android Framework",
        .patch_date      = "2025-12-01",
        .description     = "Information disclosure vulnerability in Android Framework.\n"
                           "    Affects Android 13 through 16. Google: 'indications of limited,\n"
                           "    targeted exploitation.' Exact technical details under embargo.",
        .impact          = "Sensitive information disclosure. Active exploitation confirmed.",
        .exploitation    = "Details not yet public. Requires local access or app execution."
    },
    {
        .cve_id          = "CVE-2025-48572",
        .title           = "Android Framework Privilege Escalation — Active Exploitation",
        .cvss            = 7.8f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_BOTH,
        .affected_layer  = "Android Framework",
        .patch_date      = "2025-12-01",
        .description     = "Elevation of privilege in Android Framework. Affects Android 13-16.\n"
                           "    Google: 'limited, targeted exploitation.' Part of December 2025\n"
                           "    Android Security Bulletin alongside CVE-2025-48633.",
        .impact          = "Local privilege escalation to system level.",
        .exploitation    = "Details not yet public. Requires prior code execution on device."
    },
    {
        .cve_id          = "CVE-2026-21385",
        .title           = "Qualcomm Adreno GPU Integer Overflow — Active Exploitation",
        .cvss            = 7.8f,
        .severity        = SEV_HIGH,
        .affected_chipset = CHIP_SNAPDRAGON,
        .affected_layer  = "GPU Driver (Adreno 650)",
        .patch_date      = "2026-03-01",
        .description     = "Integer overflow in Qualcomm Adreno GPU driver causes memory\n"
                           "    corruption. Affects 230+ Qualcomm chipsets including Snapdragon\n"
                           "    865 (Adreno 650). CISA KEV added March 2026. Google confirms\n"
                           "    'limited, targeted exploitation.' Malicious app can trigger\n"
                           "    controlled memory overflow to escalate from app to kernel.",
        .impact          = "Kernel privilege escalation via GPU driver. Active exploitation.",
        .exploitation    = "Craft GPU ioctl with overflow-inducing parameters. Allocate tiny\n"
                           "    buffer for large data, overflow into kernel heap. Chain with\n"
                           "    initial code exec (e.g., USB exploit) for full compromise."
    },
};

static const int CVE_COUNT = sizeof(cve_database) / sizeof(cve_database[0]);

int cve_db_count(void)
{
    return CVE_COUNT;
}

cve_entry_t *cve_db_get_all(void)
{
    return cve_database;
}

chipset_t model_to_chipset(const char *model)
{
    if (!model) return CHIP_UNKNOWN;

    /* SM-G780F = Exynos 990 (4G, international) */
    if (strcasecmp(model, "SM-G780F") == 0) return CHIP_EXYNOS;

    /* SM-G780G = Snapdragon 865 (4G, revised) */
    if (strcasecmp(model, "SM-G780G") == 0) return CHIP_SNAPDRAGON;

    /* SM-G781B/U/W = Snapdragon 865 (5G) */
    if (strncasecmp(model, "SM-G781", 7) == 0) return CHIP_SNAPDRAGON;

    return CHIP_UNKNOWN;
}

/* compare "YYYY-MM-DD" date strings. returns <0, 0, >0 */
static int date_cmp(const char *a, const char *b)
{
    return strcmp(a, b);
}

int cve_scan(const char *model, const char *patch_date)
{
    chipset_t chip = model_to_chipset(model);

    if (chip == CHIP_UNKNOWN) {
        color_print(CLR_YELLOW, "  warning: unrecognized model '%s', showing all CVEs\n\n", model);
        chip = CHIP_BOTH;
    }

    printf("  " CLR_BOLD "Device:" CLR_RESET "       %s\n", model);
    printf("  " CLR_BOLD "Chipset:" CLR_RESET "      %s\n", chipset_str(chip));
    printf("  " CLR_BOLD "Patch Level:" CLR_RESET "  %s\n", patch_date);
    print_separator();

    int found = 0;
    int critical = 0, high = 0, medium = 0;

    for (int i = 0; i < CVE_COUNT; i++) {
        cve_entry_t *e = &cve_database[i];

        /* filter by chipset */
        if (e->affected_chipset != CHIP_BOTH && e->affected_chipset != chip && chip != CHIP_BOTH)
            continue;

        /* filter by patch date: show if unpatched or device patch < CVE patch */
        if (e->patch_date != NULL && date_cmp(patch_date, e->patch_date) >= 0)
            continue;

        found++;
        switch (e->severity) {
        case SEV_CRITICAL: critical++; break;
        case SEV_HIGH:     high++;     break;
        case SEV_MEDIUM:   medium++;   break;
        default: break;
        }

        const char *sc = severity_color(e->severity);

        printf("\n  %s[%s]" CLR_RESET " %s%-8s" CLR_RESET " CVSS %.1f\n",
               sc, severity_str(e->severity), CLR_CYAN, e->cve_id, e->cvss);
        printf("  " CLR_BOLD "%s" CLR_RESET "\n", e->title);
        printf("  Layer:  %s\n", e->affected_layer);
        printf("  Chip:   %s\n", chipset_str(e->affected_chipset));
        if (e->patch_date)
            printf("  Patch:  %s " CLR_DIM "(device is UNPATCHED)" CLR_RESET "\n", e->patch_date);
        else
            printf("  Patch:  " CLR_RED "NO PATCH AVAILABLE" CLR_RESET "\n");
        printf("  Desc:   %s\n", e->description);
        printf("  Impact: " CLR_YELLOW "%s" CLR_RESET "\n", e->impact);
    }

    printf("\n");
    print_separator();
    printf("  " CLR_BOLD "SCAN SUMMARY" CLR_RESET "\n");
    print_separator();
    printf("  Total applicable:  " CLR_BOLD "%d" CLR_RESET " CVEs\n", found);
    if (critical > 0)
        printf("  " CLR_RED "Critical:" CLR_RESET "          %d\n", critical);
    if (high > 0)
        printf("  " CLR_ORANGE "High:" CLR_RESET "              %d\n", high);
    if (medium > 0)
        printf("  " CLR_YELLOW "Medium:" CLR_RESET "            %d\n", medium);

    if (found == 0) {
        printf("\n  " CLR_GREEN "No known unpatched CVEs for this configuration." CLR_RESET "\n");
    } else {
        printf("\n  " CLR_RED "This device has %d known unpatched vulnerabilities." CLR_RESET "\n", found);
    }
    printf("\n");

    return 0;
}
