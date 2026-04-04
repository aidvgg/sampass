#include <stdio.h>
#include <string.h>
#include "sampass.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage();
        return 0;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "detect") == 0) {
        print_banner();
        return detect_device();
    }

    if (strcmp(cmd, "info") == 0) {
        print_banner();
        return knox_info();
    }

    if (strcmp(cmd, "cve-scan") == 0) {
        if (argc < 4) {
            color_print(CLR_RED, "  error: cve-scan requires <model> <patch-date>\n");
            printf("  usage: sampass cve-scan SM-G780F 2021-11-01\n\n");
            return 1;
        }
        print_banner();
        return cve_scan(argv[2], argv[3]);
    }

    if (strcmp(cmd, "keymaster-demo") == 0) {
        print_banner();
        return keymaster_demo();
    }

    if (strcmp(cmd, "assess") == 0) {
        if (argc < 4) {
            color_print(CLR_RED, "  error: assess requires <model> <patch-date>\n");
            printf("  usage: sampass assess SM-G780F 2021-11-01\n\n");
            return 1;
        }
        print_banner();
        return assess_device(argv[2], argv[3]);
    }

    if (strcmp(cmd, "firmware") == 0) {
        if (argc < 3) {
            color_print(CLR_RED, "  error: firmware requires <file>\n");
            printf("  usage: sampass firmware boot.img\n\n");
            return 1;
        }
        print_banner();
        return firmware_analyze(argv[2]);
    }

    if (strcmp(cmd, "bootchain") == 0) {
        if (argc < 3) {
            color_print(CLR_RED, "  error: bootchain requires <boot.img>\n");
            printf("  usage: sampass bootchain boot.img\n\n");
            return 1;
        }
        print_banner();
        return bootchain_analyze(argv[2]);
    }

    if (strcmp(cmd, "odin") == 0) {
        print_banner();
        return exploit_odin();
    }

    if (strcmp(cmd, "edl") == 0) {
        print_banner();
        return exploit_edl();
    }

    if (strcmp(cmd, "exploit-gen") == 0) {
        print_banner();
        return exploit_gen(argc >= 3 ? argv[2] : NULL);
    }

    if (strcmp(cmd, "edl-push") == 0) {
        if (argc < 3) {
            color_print(CLR_RED, "  error: edl-push requires <payload.elf>\n");
            printf("  usage: sampass edl-push exploit_payload.bin\n\n");
            return 1;
        }
        print_banner();
        return exploit_edl_push(argv[2]);
    }

    if (strcmp(cmd, "probe") == 0) {
        print_banner();
        return exploit_probe();
    }

    if (strcmp(cmd, "extract") == 0) {
        print_banner();
        return exploit_extract();
    }

    if (strcmp(cmd, "fullchain") == 0) {
        if (argc < 3) {
            color_print(CLR_RED, "  error: fullchain requires <model>\n");
            printf("  usage: sampass fullchain SM-G780G\n\n");
            return 1;
        }
        print_banner();
        return exploit_fullchain(argv[2]);
    }

    if (strcmp(cmd, "gadget-setup") == 0) {
        print_banner();
        return gadget_setup(argc >= 3 ? argv[2] : NULL);
    }

    if (strcmp(cmd, "pull") == 0) {
        print_banner();
        return adb_pull_photos(argc >= 3 ? argv[2] : NULL);
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_usage();
        return 0;
    }

    color_print(CLR_RED, "  error: unknown command '%s'\n", cmd);
    printf("  run 'sampass help' for usage\n\n");
    return 1;
}
