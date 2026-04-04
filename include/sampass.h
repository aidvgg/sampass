#ifndef SAMPASS_H
#define SAMPASS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SAMPASS_VERSION "1.0.0"
#define SAMPASS_NAME    "sampass"

/* severity levels */
typedef enum {
    SEV_CRITICAL = 0,
    SEV_HIGH,
    SEV_MEDIUM,
    SEV_LOW,
    SEV_INFO
} severity_t;

/* chipset type */
typedef enum {
    CHIP_EXYNOS = 0,
    CHIP_SNAPDRAGON,
    CHIP_BOTH,
    CHIP_UNKNOWN
} chipset_t;

/* CVE database entry */
typedef struct {
    const char   *cve_id;
    const char   *title;
    float         cvss;
    severity_t    severity;
    chipset_t     affected_chipset;
    const char   *affected_layer;
    const char   *patch_date;       /* "YYYY-MM-DD" or NULL if unpatched */
    const char   *description;
    const char   *impact;
    const char   *exploitation;
} cve_entry_t;

/* Android boot image header (v0) */
typedef struct {
    uint8_t  magic[8];          /* ANDROID! */
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;
    uint32_t header_version;
    uint32_t os_version;
    char     name[16];
    char     cmdline[512];
    uint32_t id[8];
    char     extra_cmdline[1024];
} __attribute__((packed)) boot_img_hdr_v0_t;

/* boot image header v1 extension */
typedef struct {
    uint32_t recovery_dtbo_size;
    uint64_t recovery_dtbo_offset;
    uint32_t header_size;
} __attribute__((packed)) boot_img_hdr_v1_ext_t;

/* boot image header v2 extension */
typedef struct {
    uint32_t dtb_size;
    uint64_t dtb_addr;
} __attribute__((packed)) boot_img_hdr_v2_ext_t;

/* attack path entry */
typedef struct {
    const char  *name;
    const char  *target_layer;
    int          feasibility;      /* 1-10, higher = more feasible */
    bool         requires_physical;
    bool         destructive;
    const char  *prerequisites;
    const char  *cve_chain;
    const char  *steps;
    const char  *tools_needed;
    const char  *data_accessible;
} attack_path_t;

/* --- module interfaces --- */

/* util.c */
void print_banner(void);
void print_usage(void);
void color_print(const char *color, const char *fmt, ...);
void hex_dump(const uint8_t *data, size_t len);
void print_separator(void);
void print_section_header(const char *title);
const char *severity_str(severity_t s);
const char *severity_color(severity_t s);
const char *chipset_str(chipset_t c);

/* cve_db.c */
int          cve_db_count(void);
cve_entry_t *cve_db_get_all(void);
chipset_t    model_to_chipset(const char *model);
int          cve_scan(const char *model, const char *patch_date);

/* keymaster_poc.c */
int keymaster_demo(void);

/* knox.c */
int knox_info(void);

/* assess.c */
int assess_device(const char *model, const char *patch_date);

/* firmware.c */
int firmware_analyze(const char *path);

/* bootchain.c */
int bootchain_analyze(const char *path);

/* detect.c */
int detect_device(void);

/* exploit.c */
int exploit_odin(void);
int exploit_edl(void);
int exploit_gen(const char *output_path);
int exploit_edl_push(const char *filepath);
int exploit_probe(void);
int exploit_fullchain(const char *model);
int exploit_extract(void);

/* gadget.c */
int gadget_setup(const char *output_dir);

/* adb_extract.c */
int adb_pull_photos(const char *output_dir);

/* ANSI color codes */
#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_WHITE   "\033[1;37m"
#define CLR_DIM     "\033[2m"
#define CLR_BOLD    "\033[1m"
#define CLR_ORANGE  "\033[38;5;208m"

#endif /* SAMPASS_H */
