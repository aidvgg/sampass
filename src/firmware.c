#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sampass.h"

/* tar header (POSIX ustar) */
typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];       /* octal */
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];       /* "ustar" */
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
} __attribute__((packed)) tar_header_t;

static long octal_to_long(const char *str, int len)
{
    long val = 0;
    for (int i = 0; i < len && str[i] >= '0' && str[i] <= '7'; i++)
        val = val * 8 + (str[i] - '0');
    return val;
}

static void analyze_boot_img(const uint8_t *data, size_t len, const char *source)
{
    if (len < sizeof(boot_img_hdr_v0_t)) {
        printf("  " CLR_YELLOW "File too small for boot image header" CLR_RESET "\n");
        return;
    }

    const boot_img_hdr_v0_t *hdr = (const boot_img_hdr_v0_t *)data;

    if (memcmp(hdr->magic, "ANDROID!", 8) != 0) {
        printf("  " CLR_DIM "Not an Android boot image (magic mismatch)" CLR_RESET "\n");
        return;
    }

    printf("\n");
    color_print(CLR_BOLD, "  ANDROID BOOT IMAGE ANALYSIS");
    if (source) printf(" (%s)", source);
    printf("\n");
    print_separator();

    printf("  " CLR_BOLD "Magic:" CLR_RESET "           ANDROID!\n");
    printf("  " CLR_BOLD "Header Version:" CLR_RESET "  %u\n", hdr->header_version);
    printf("  " CLR_BOLD "Page Size:" CLR_RESET "       %u bytes\n", hdr->page_size);

    /* decode os_version field */
    if (hdr->os_version != 0) {
        uint32_t os = hdr->os_version;
        uint32_t os_major = (os >> 25) & 0x7F;
        uint32_t os_minor = (os >> 18) & 0x7F;
        uint32_t os_patch = (os >> 11) & 0x7F;
        uint32_t year     = ((os >> 4) & 0x7F) + 2000;
        uint32_t month    = os & 0x0F;

        printf("  " CLR_BOLD "OS Version:" CLR_RESET "     Android %u.%u.%u\n",
               os_major, os_minor, os_patch);
        printf("  " CLR_BOLD "Patch Level:" CLR_RESET "    %u-%02u\n", year, month);

        /* security assessment based on patch level */
        if (year < 2022 || (year == 2022 && month < 3)) {
            color_print(CLR_RED, "  SECURITY:        Pre-March 2022 — major forensic tool exploits unpatched\n");
        } else if (year < 2023 || (year == 2023 && month < 3)) {
            color_print(CLR_ORANGE, "  SECURITY:        Pre-March 2023 — baseband vulnerabilities likely unpatched\n");
        } else {
            color_print(CLR_GREEN, "  SECURITY:        Relatively recent patch level\n");
        }
    }

    printf("\n  " CLR_BOLD "Kernel:" CLR_RESET "\n");
    printf("    Address:     0x%08x\n", hdr->kernel_addr);
    printf("    Size:        %u bytes (%.1f MB)\n",
           hdr->kernel_size, hdr->kernel_size / (1024.0 * 1024.0));

    /* check for LZ4 compression */
    if (hdr->page_size > 0 && len > hdr->page_size + 4) {
        const uint8_t *kernel_data = data + hdr->page_size;
        if (kernel_data[0] == 0x02 && kernel_data[1] == 0x21 &&
            kernel_data[2] == 0x4c && kernel_data[3] == 0x18) {
            printf("    Compression: " CLR_CYAN "LZ4" CLR_RESET " (magic: 02 21 4c 18)\n");
        } else if (kernel_data[0] == 0x1f && kernel_data[1] == 0x8b) {
            printf("    Compression: " CLR_CYAN "GZIP" CLR_RESET " (magic: 1f 8b)\n");
        }
    }

    printf("\n  " CLR_BOLD "Ramdisk:" CLR_RESET "\n");
    printf("    Address:     0x%08x\n", hdr->ramdisk_addr);
    printf("    Size:        %u bytes (%.1f KB)\n",
           hdr->ramdisk_size, hdr->ramdisk_size / 1024.0);
    if (hdr->ramdisk_size == 0)
        color_print(CLR_YELLOW, "    WARNING: No ramdisk — unusual for boot image\n");

    if (hdr->second_size > 0) {
        printf("\n  " CLR_BOLD "Second Stage:" CLR_RESET "\n");
        printf("    Address:     0x%08x\n", hdr->second_addr);
        printf("    Size:        %u bytes\n", hdr->second_size);
    }

    printf("\n  " CLR_BOLD "Board Name:" CLR_RESET "     ");
    if (hdr->name[0])
        printf("%s\n", hdr->name);
    else
        printf(CLR_DIM "(empty)" CLR_RESET "\n");

    printf("  " CLR_BOLD "Cmdline:" CLR_RESET "         ");
    if (hdr->cmdline[0]) {
        /* print first 70 chars */
        printf("%.70s", hdr->cmdline);
        if (strlen(hdr->cmdline) > 70) printf("...");
        printf("\n");
    } else {
        printf(CLR_DIM "(empty)" CLR_RESET "\n");
    }

    /* header version-specific extensions */
    if (hdr->header_version >= 1 && len >= sizeof(boot_img_hdr_v0_t) + sizeof(boot_img_hdr_v1_ext_t)) {
        const boot_img_hdr_v1_ext_t *v1 =
            (const boot_img_hdr_v1_ext_t *)(data + sizeof(boot_img_hdr_v0_t));
        printf("\n  " CLR_BOLD "Header v1 Extension:" CLR_RESET "\n");
        printf("    Recovery DTBO:  %u bytes at offset 0x%llx\n",
               v1->recovery_dtbo_size, (unsigned long long)v1->recovery_dtbo_offset);
        printf("    Header Size:    %u bytes\n", v1->header_size);
    }

    if (hdr->header_version >= 2 && len >= sizeof(boot_img_hdr_v0_t) +
        sizeof(boot_img_hdr_v1_ext_t) + sizeof(boot_img_hdr_v2_ext_t)) {
        const boot_img_hdr_v2_ext_t *v2 =
            (const boot_img_hdr_v2_ext_t *)(data + sizeof(boot_img_hdr_v0_t) +
                                             sizeof(boot_img_hdr_v1_ext_t));
        printf("\n  " CLR_BOLD "Header v2 Extension:" CLR_RESET "\n");
        printf("    DTB Size:       %u bytes\n", v2->dtb_size);
        printf("    DTB Address:    0x%llx\n", (unsigned long long)v2->dtb_addr);
    }

    /* image ID (SHA hash) */
    printf("\n  " CLR_BOLD "Image ID (SHA):" CLR_RESET "\n  ");
    for (int i = 0; i < 8; i++)
        printf("%08x", hdr->id[i]);
    printf("\n");

    /* hex dump of header */
    printf("\n  " CLR_BOLD "Raw Header (first 64 bytes):" CLR_RESET "\n");
    hex_dump(data, 64);
}

int firmware_analyze(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        color_print(CLR_RED, "  error: cannot open '%s'\n\n", path);
        return 1;
    }

    /* get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    print_section_header("FIRMWARE IMAGE ANALYSIS");
    printf("  " CLR_BOLD "File:" CLR_RESET "  %s\n", path);
    printf("  " CLR_BOLD "Size:" CLR_RESET "  %ld bytes (%.1f MB)\n\n",
           file_size, file_size / (1024.0 * 1024.0));

    /* read first 8 bytes to identify format */
    uint8_t magic[8];
    if (fread(magic, 1, 8, fp) != 8) {
        color_print(CLR_RED, "  error: file too small\n\n");
        fclose(fp);
        return 1;
    }
    fseek(fp, 0, SEEK_SET);

    /* check for Android boot image */
    if (memcmp(magic, "ANDROID!", 8) == 0) {
        printf("  " CLR_GREEN "Detected: Android Boot Image" CLR_RESET "\n");

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

        analyze_boot_img(buf, read_size, path);
        free(buf);
        fclose(fp);
        return 0;
    }

    /* check for tar format (Samsung .tar.md5) */
    /* tar magic is at offset 257: "ustar" */
    if (file_size > 512) {
        uint8_t tar_check[512];
        if (fread(tar_check, 1, 512, fp) == 512) {
            if (memcmp(tar_check + 257, "ustar", 5) == 0) {
                printf("  " CLR_GREEN "Detected: TAR archive (Samsung .tar.md5 firmware)" CLR_RESET "\n\n");

                /* parse tar entries */
                fseek(fp, 0, SEEK_SET);
                printf("  " CLR_BOLD "Partition Images:" CLR_RESET "\n");
                print_separator();

                int entry_count = 0;
                while (1) {
                    tar_header_t thdr;
                    if (fread(&thdr, 1, 512, fp) != 512) break;
                    if (thdr.name[0] == '\0') break;

                    long entry_size = octal_to_long(thdr.size, 12);
                    entry_count++;

                    /* identify partition type from filename */
                    const char *part_type = "unknown";
                    if (strstr(thdr.name, "boot.img"))       part_type = "Boot Image";
                    else if (strstr(thdr.name, "recovery"))  part_type = "Recovery";
                    else if (strstr(thdr.name, "system"))    part_type = "System";
                    else if (strstr(thdr.name, "vendor"))    part_type = "Vendor";
                    else if (strstr(thdr.name, "super"))     part_type = "Super (system+vendor+product)";
                    else if (strstr(thdr.name, "vbmeta"))    part_type = "Verified Boot Metadata";
                    else if (strstr(thdr.name, "dtbo"))      part_type = "Device Tree Blob Overlay";
                    else if (strstr(thdr.name, "modem"))     part_type = "Baseband/Modem Firmware";
                    else if (strstr(thdr.name, "sboot"))     part_type = "Samsung Bootloader (S-Boot)";
                    else if (strstr(thdr.name, "param"))     part_type = "Parameters";
                    else if (strstr(thdr.name, "up_param"))  part_type = "Bootloader Logo/Params";
                    else if (strstr(thdr.name, "userdata"))  part_type = "User Data (encrypted)";
                    else if (strstr(thdr.name, "cache"))     part_type = "Cache";
                    else if (strstr(thdr.name, "optics"))    part_type = "CSC/Optics";
                    else if (strstr(thdr.name, "prism"))     part_type = "CSC/Prism";
                    else if (strstr(thdr.name, ".pit"))      part_type = "Partition Info Table";
                    else if (strstr(thdr.name, ".md5"))      part_type = "MD5 Checksum";

                    printf("  " CLR_CYAN "%-40s" CLR_RESET " %8ld bytes  (%s)\n",
                           thdr.name, entry_size, part_type);

                    /* check for boot.img inside — read its header */
                    if (strstr(thdr.name, "boot.img") && entry_size > (long)sizeof(boot_img_hdr_v0_t)) {
                        long saved_pos = ftell(fp);
                        size_t boot_read = entry_size < 65536 ? (size_t)entry_size : 65536;
                        uint8_t *boot_buf = malloc(boot_read);
                        if (boot_buf) {
                            if (fread(boot_buf, 1, boot_read, fp) == boot_read) {
                                if (memcmp(boot_buf, "ANDROID!", 8) == 0)
                                    analyze_boot_img(boot_buf, boot_read, thdr.name);
                            }
                            free(boot_buf);
                        }
                        fseek(fp, saved_pos, SEEK_SET);
                    }

                    /* skip to next tar entry (512-byte aligned) */
                    long skip = ((entry_size + 511) / 512) * 512;
                    fseek(fp, skip, SEEK_CUR);
                }

                printf("\n  " CLR_BOLD "Total entries:" CLR_RESET " %d\n\n", entry_count);

                /* check for MD5 at end of file */
                if (strstr(path, ".md5")) {
                    printf("  " CLR_DIM "Samsung .tar.md5 format: standard tar with MD5 checksum appended.\n" CLR_RESET);
                    printf("  " CLR_DIM "The MD5 covers all partition images for integrity verification.\n" CLR_RESET);
                    printf("  " CLR_DIM "Flashed via Odin (Windows) or Heimdall (Linux/macOS).\n" CLR_RESET "\n");
                }

                fclose(fp);
                return 0;
            }
        }
    }

    /* unknown format — hexdump first 256 bytes */
    printf("  " CLR_YELLOW "Unknown format — dumping first 256 bytes:" CLR_RESET "\n\n");
    fseek(fp, 0, SEEK_SET);
    uint8_t buf[256];
    size_t nread = fread(buf, 1, sizeof(buf), fp);
    hex_dump(buf, nread);
    printf("\n");

    fclose(fp);
    return 0;
}
