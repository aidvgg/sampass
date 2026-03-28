#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sampass.h"

typedef struct {
    const char *name;
    const char *location;
    const char *verifier;
    const char *key;
    const char *on_failure;
    const char *el_level;
} boot_stage_t;

static const boot_stage_t exynos_chain[] = {
    {
        "Boot ROM (PBL)",
        "Immutable ROM on Exynos 990 SoC",
        "Hardware (self-verifying root of trust)",
        "SSBK public key in OTP fuses",
        "Device does not boot",
        "EL3 (highest privilege)"
    },
    {
        "S-Boot (Secondary Bootloader)",
        "Flash storage, signed by Samsung",
        "Boot ROM verifies signature",
        "SSBK (Samsung Secure Boot Key)",
        "Boot terminates, device bricks",
        "EL3 -> EL2 transition"
    },
    {
        "TrustZone (TEEGRIS v4.1.0.0)",
        "Loaded by S-Boot into Secure World",
        "S-Boot verifies signature chain",
        "Samsung signing key chain",
        "Secure World fails to initialize",
        "S-EL1 (Secure World kernel)"
    },
    {
        "RKP Hypervisor (uh.bin)",
        "Separate binary in bootloader partition (\"GREENTEA\" header)",
        "S-Boot verifies before loading",
        "Samsung signing key",
        "Kernel integrity protection disabled",
        "EL2 (hypervisor)"
    },
    {
        "Linux Kernel",
        "boot.img, verified by Trusted/Verified Boot",
        "Bootloader + dm-verity root hash + Knox VB",
        "RSA-2048 on boot partition",
        "Boot aborted or warning displayed",
        "EL1 (kernel)"
    },
    {
        "dm-verity (System Integrity)",
        "Merkle hash tree over system partitions",
        "Kernel verifies on block read",
        "SHA-256 block hashes, RSA-2048 root",
        "I/O error returned, system partition untrusted",
        "EL1 (kernel subsystem)"
    },
    {
        "Android Init -> Zygote",
        "System partition (/system)",
        "dm-verity guarantees integrity",
        "Protected by Merkle tree",
        "System services fail to start",
        "EL0 (user space)"
    },
};

static const boot_stage_t snapdragon_chain[] = {
    {
        "Boot ROM (PBL)",
        "Immutable ROM on Snapdragon 865 SoC",
        "Hardware (self-verifying root of trust)",
        "SSBK public key in OTP fuses",
        "Device does not boot",
        "EL3 (highest privilege)"
    },
    {
        "XBL (eXtensible Bootloader, UEFI)",
        "Flash storage, Qualcomm + Samsung signed",
        "Boot ROM verifies signature",
        "SSBK + Qualcomm signing chain",
        "Boot terminates",
        "EL3 -> EL2 transition"
    },
    {
        "TrustZone (QSEE/QTEE)",
        "Loaded by XBL into Secure World",
        "XBL verifies via qseecom + hash table",
        "eFuse-burned root certificate hash",
        "Secure World fails to initialize",
        "S-EL1 (Secure World kernel)"
    },
    {
        "RKP Hypervisor (uh.bin)",
        "Separate binary, loaded after TrustZone",
        "XBL verifies before loading",
        "Samsung signing key",
        "Kernel integrity protection disabled",
        "EL2 (hypervisor)"
    },
    {
        "ABL (Android Bootloader)",
        "Qualcomm Android Bootloader",
        "XBL verifies ABL",
        "Qualcomm + Samsung signing chain",
        "Boot aborted",
        "EL1 transition"
    },
    {
        "Linux Kernel + initramfs",
        "boot.img, verified by ABL + Knox VB",
        "ABL + dm-verity root hash",
        "RSA-2048 on boot partition",
        "Boot aborted or warning displayed",
        "EL1 (kernel)"
    },
    {
        "dm-verity (System Integrity)",
        "Merkle hash tree over system partitions",
        "Kernel verifies on block read",
        "SHA-256 block hashes, RSA-2048 root",
        "I/O error returned",
        "EL1 (kernel subsystem)"
    },
    {
        "Android Init -> Zygote",
        "System partition (/system)",
        "dm-verity guarantees integrity",
        "Protected by Merkle tree",
        "System services fail to start",
        "EL0 (user space)"
    },
};

static void print_chain(const boot_stage_t *chain, int count, const char *variant)
{
    printf("  " CLR_BOLD "SECURE BOOT CHAIN — %s\n" CLR_RESET, variant);
    print_separator();
    printf("\n");

    for (int i = 0; i < count; i++) {
        const boot_stage_t *s = &chain[i];

        /* stage number and connector */
        if (i > 0) {
            printf("  " CLR_DIM "       │" CLR_RESET "\n");
            printf("  " CLR_DIM "       │  verifies ▼ using %s" CLR_RESET "\n", s->key);
            printf("  " CLR_DIM "       │" CLR_RESET "\n");
        }

        /* stage box */
        const char *color = CLR_GREEN;
        if (i >= 4) color = CLR_YELLOW;
        if (i >= 6) color = CLR_ORANGE;

        printf("  %s  [%d]  %s" CLR_RESET "\n", color, i + 1, s->name);
        printf("  " CLR_DIM "       Location:   %s" CLR_RESET "\n", s->location);
        printf("  " CLR_DIM "       ARM Level:  %s" CLR_RESET "\n", s->el_level);
        printf("  " CLR_DIM "       On Tamper:  %s" CLR_RESET "\n", s->on_failure);
    }
    printf("\n");
}

int bootchain_analyze(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        color_print(CLR_RED, "  error: cannot open '%s'\n\n", path);
        return 1;
    }

    /* read header */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    size_t read_size = file_size < 65536 ? (size_t)file_size : 65536;
    uint8_t *buf = malloc(read_size);
    if (!buf) {
        color_print(CLR_RED, "  error: memory allocation failed\n");
        fclose(fp);
        return 1;
    }
    if (fread(buf, 1, read_size, fp) != read_size) {
        color_print(CLR_RED, "  error: read failed\n");
        free(buf);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    print_section_header("SECURE BOOT CHAIN ANALYSIS");
    printf("  " CLR_BOLD "File:" CLR_RESET " %s (%ld bytes)\n\n", path, file_size);

    /* check for boot image */
    if (memcmp(buf, "ANDROID!", 8) == 0) {
        const boot_img_hdr_v0_t *hdr = (const boot_img_hdr_v0_t *)buf;

        printf("  " CLR_GREEN "Valid Android boot image detected." CLR_RESET "\n\n");

        /* try to identify chipset from board name or cmdline */
        chipset_t chip = CHIP_UNKNOWN;
        if (hdr->name[0]) {
            /* Samsung board names often contain "exynos" or "universal" for Exynos */
            if (strstr(hdr->name, "exynos") || strstr(hdr->name, "universal") ||
                strstr(hdr->name, "SRPSL"))
                chip = CHIP_EXYNOS;
            else if (strstr(hdr->name, "msm") || strstr(hdr->name, "sdm") ||
                     strstr(hdr->name, "SM8") || strstr(hdr->name, "kona"))
                chip = CHIP_SNAPDRAGON;
        }
        if (chip == CHIP_UNKNOWN && hdr->cmdline[0]) {
            if (strstr(hdr->cmdline, "exynos"))
                chip = CHIP_EXYNOS;
            else if (strstr(hdr->cmdline, "msm") || strstr(hdr->cmdline, "qcom"))
                chip = CHIP_SNAPDRAGON;
        }

        if (chip == CHIP_EXYNOS) {
            printf("  " CLR_CYAN "Chipset identified: Exynos" CLR_RESET "\n\n");
            print_chain(exynos_chain, 7, "Exynos 990 (SM-G780F)");
        } else if (chip == CHIP_SNAPDRAGON) {
            printf("  " CLR_CYAN "Chipset identified: Snapdragon" CLR_RESET "\n\n");
            print_chain(snapdragon_chain, 8, "Snapdragon 865 (SM-G781B)");
        } else {
            printf("  " CLR_YELLOW "Chipset not identified from image. Showing both chains.\n" CLR_RESET "\n");
            print_chain(exynos_chain, 7, "Exynos 990 (SM-G780F)");
            printf("\n");
            print_chain(snapdragon_chain, 8, "Snapdragon 865 (SM-G781B)");
        }

        /* security analysis */
        print_section_header("BOOT IMAGE SECURITY ANALYSIS");

        printf("  " CLR_BOLD "Header Version:" CLR_RESET " %u\n", hdr->header_version);
        if (hdr->header_version < 2) {
            color_print(CLR_YELLOW, "  WARNING: Header v0/v1 lacks DTB size field — older format\n");
        }

        /* check kernel size for anomalies */
        if (hdr->kernel_size == 0) {
            color_print(CLR_RED, "  ANOMALY: Kernel size is 0 — possibly stripped or corrupted\n");
        } else if (hdr->kernel_size > 100 * 1024 * 1024) {
            color_print(CLR_YELLOW, "  WARNING: Kernel size >100MB — unusually large\n");
        }

        if (hdr->ramdisk_size == 0) {
            color_print(CLR_YELLOW, "  WARNING: No ramdisk — device may use system-as-root\n");
        }

        if (hdr->page_size != 2048 && hdr->page_size != 4096) {
            color_print(CLR_YELLOW, "  WARNING: Unusual page size %u (expected 2048 or 4096)\n",
                        hdr->page_size);
        }

        /* check for Samsung-specific security markers */
        printf("\n  " CLR_BOLD "Samsung Security Markers:" CLR_RESET "\n");
        if (strstr(hdr->cmdline, "androidboot.selinux=enforcing") ||
            !strstr(hdr->cmdline, "selinux=0")) {
            printf("  " CLR_GREEN "  SELinux: likely enforcing (no permissive/disabled flags)" CLR_RESET "\n");
        } else {
            color_print(CLR_RED, "  SELinux: may be disabled/permissive — non-stock image!\n");
        }

        if (strstr(hdr->cmdline, "androidboot.warranty_bit")) {
            printf("  " CLR_YELLOW "  Knox warranty bit reference found in cmdline" CLR_RESET "\n");
        }

    } else {
        printf("  " CLR_YELLOW "Not an Android boot image." CLR_RESET "\n");
        printf("  Expected 'ANDROID!' magic at offset 0.\n\n");

        printf("  " CLR_BOLD "First 64 bytes:" CLR_RESET "\n");
        hex_dump(buf, 64);
        printf("\n");

        /* show both chains as reference anyway */
        printf("  Showing reference boot chains for the S20 FE:\n\n");
        print_chain(exynos_chain, 7, "Exynos 990 (SM-G780F)");
        printf("\n");
        print_chain(snapdragon_chain, 8, "Snapdragon 865 (SM-G781B)");
    }

    /* hardware key anchors */
    print_section_header("HARDWARE KEY ANCHORS");

    printf("  Three factory-provisioned keys anchor the entire boot chain:\n\n");

    printf("  " CLR_GREEN "DUHK" CLR_RESET " — Device-Unique Hardware Key\n");
    printf("    Symmetric key, accessible ONLY by hardware crypto module.\n");
    printf("    Never exposed to any software — not even TrustZone.\n\n");

    printf("  " CLR_GREEN "SSBK" CLR_RESET " — Samsung Secure Boot Key\n");
    printf("    Asymmetric key pair. Public key burned into OTP fuses.\n");
    printf("    Samsung holds private key, signs all boot components.\n\n");

    printf("  " CLR_GREEN "SAK" CLR_RESET "  — Samsung Attestation Key\n");
    printf("    ECDSA key pair, encrypted by DUHK.\n");
    printf("    Public key signed by Samsung root CA (X.509 chain).\n");
    printf("    Proves device was manufactured by Samsung.\n\n");

    free(buf);
    return 0;
}
