#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "sampass.h"

void print_banner(void)
{
    printf("\n");
    printf(CLR_GREEN "  ███████╗ █████╗ ███╗   ███╗██████╗  █████╗ ███████╗███████╗\n");
    printf("  ██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔════╝██╔════╝\n");
    printf("  ███████╗███████║██╔████╔██║██████╔╝███████║███████╗███████╗\n");
    printf("  ╚════██║██╔══██║██║╚██╔╝██║██╔═══╝ ██╔══██║╚════██║╚════██║\n");
    printf("  ███████║██║  ██║██║ ╚═╝ ██║██║     ██║  ██║███████║███████║\n");
    printf("  ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝\n" CLR_RESET);
    printf(CLR_DIM "  Samsung S20 FE Security Analysis Toolkit v%s\n" CLR_RESET, SAMPASS_VERSION);
    printf(CLR_DIM "  sub-OS security research & attack-path assessment\n\n" CLR_RESET);
}

void print_usage(void)
{
    print_banner();
    printf(CLR_BOLD "USAGE:" CLR_RESET "\n");
    printf("  sampass <command> [arguments]\n\n");
    printf(CLR_BOLD "COMMANDS:" CLR_RESET "\n");
    printf("  " CLR_CYAN "detect" CLR_RESET "                        "
           "Auto-detect connected Samsung device\n");
    printf("  " CLR_CYAN "info" CLR_RESET "                          "
           "S20 FE security architecture overview\n");
    printf("  " CLR_CYAN "cve-scan" CLR_RESET " <model> <patch-date>  "
           "Scan for applicable CVEs\n");
    printf("  " CLR_CYAN "keymaster-demo" CLR_RESET "                 "
           "AES-GCM IV-reuse PoC (CVE-2021-25444)\n");
    printf("  " CLR_CYAN "assess" CLR_RESET " <model> <patch-date>    "
           "Full attack-path assessment\n");
    printf("  " CLR_CYAN "firmware" CLR_RESET " <file>                "
           "Parse Samsung firmware / boot image\n");
    printf("  " CLR_CYAN "bootchain" CLR_RESET " <boot.img>           "
           "Analyze secure boot chain\n");
    printf("\n" CLR_BOLD "EXPLOIT:" CLR_RESET "\n");
    printf("  " CLR_RED "odin" CLR_RESET "                          "
           "Connect to Samsung Download Mode (Odin)\n");
    printf("  " CLR_RED "edl" CLR_RESET "                           "
           "Connect to Qualcomm EDL (QDLoader 9008)\n");
    printf("  " CLR_RED "exploit-gen" CLR_RESET " [output]           "
           "Generate CVE-2025-47372 PBL overflow payload\n");
    printf("  " CLR_RED "edl-push" CLR_RESET " <payload.elf>        "
           "Push payload to device via Sahara protocol\n");
    printf("  " CLR_RED "probe" CLR_RESET "                          "
           "Deep USB fingerprinting (no auth needed)\n");
    printf("  " CLR_RED "extract" CLR_RESET "                        "
           "Probe locked device via AT modem + USB\n");
    printf("  " CLR_RED "fullchain" CLR_RESET " <model>              "
           "Automated end-to-end attack sequence\n");
    printf("\n" CLR_BOLD "UNLOCK:" CLR_RESET "\n");
    printf("  " CLR_GREEN "gadget-setup" CLR_RESET " [output-dir]     "
           "Generate Pi Zero USB exploit scripts\n");
    printf("  " CLR_GREEN "pull" CLR_RESET " [output-dir]             "
           "Extract photos via ADB (after exploit)\n");
    printf("\n");
    printf(CLR_BOLD "QUICK START:" CLR_RESET "\n");
    printf("  sampass detect                     # detect device on USB\n");
    printf("  sampass extract                    # probe locked device\n");
    printf("  sampass gadget-setup ./pi_scripts  # generate Pi Zero exploit\n");
    printf("  sampass fullchain SM-G780G         # automated attack\n");
    printf("  sampass pull ./photos              # extract after unlock\n");
    printf("\n");
    printf(CLR_BOLD "EXAMPLES:" CLR_RESET "\n");
    printf("  sampass cve-scan SM-G780F 2021-11-01\n");
    printf("  sampass assess SM-G781B 2022-01-01\n");
    printf("  sampass firmware AP_G780FXXU9HWA1.tar.md5\n");
    printf("  sampass bootchain boot.img\n");
    printf("\n");
    printf(CLR_BOLD "MODELS:" CLR_RESET "\n");
    printf("  SM-G780F   S20 FE 4G (Exynos 990)\n");
    printf("  SM-G780G   S20 FE 4G rev2 (Snapdragon 865)\n");
    printf("  SM-G781B   S20 FE 5G (Snapdragon 865)\n");
    printf("  SM-G781U   S20 FE 5G US (Snapdragon 865)\n");
    printf("\n");
}

void color_print(const char *color, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("%s", color);
    vprintf(fmt, ap);
    printf(CLR_RESET);
    va_end(ap);
}

void hex_dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf(CLR_DIM "  %04zx  " CLR_RESET, i);

        /* hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf(CLR_GREEN "%02x " CLR_RESET, data[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }

        /* ascii */
        printf(" " CLR_DIM "|" CLR_RESET);
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf(CLR_DIM "|" CLR_RESET "\n");
    }
}

void print_separator(void)
{
    printf(CLR_DIM "  ──────────────────────────────────────────────────────────────\n" CLR_RESET);
}

void print_section_header(const char *title)
{
    printf("\n");
    print_separator();
    color_print(CLR_BOLD, "  %s\n", title);
    print_separator();
    printf("\n");
}

const char *severity_str(severity_t s)
{
    switch (s) {
    case SEV_CRITICAL: return "CRITICAL";
    case SEV_HIGH:     return "HIGH";
    case SEV_MEDIUM:   return "MEDIUM";
    case SEV_LOW:      return "LOW";
    case SEV_INFO:     return "INFO";
    }
    return "UNKNOWN";
}

const char *severity_color(severity_t s)
{
    switch (s) {
    case SEV_CRITICAL: return CLR_RED;
    case SEV_HIGH:     return CLR_ORANGE;
    case SEV_MEDIUM:   return CLR_YELLOW;
    case SEV_LOW:      return CLR_CYAN;
    case SEV_INFO:     return CLR_DIM;
    }
    return CLR_RESET;
}

const char *chipset_str(chipset_t c)
{
    switch (c) {
    case CHIP_EXYNOS:     return "Exynos 990";
    case CHIP_SNAPDRAGON: return "Snapdragon 865";
    case CHIP_BOTH:       return "Both";
    case CHIP_UNKNOWN:    return "Unknown";
    }
    return "Unknown";
}
