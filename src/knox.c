#include <stdio.h>
#include "sampass.h"

int knox_info(void)
{
    print_section_header("Samsung Galaxy S20 FE — Security Architecture Overview");

    /* 7-layer model */
    printf(CLR_BOLD "  7-LAYER DEFENSE-IN-DEPTH MODEL\n" CLR_RESET "\n");

    printf("  " CLR_DIM "Layer" CLR_RESET "  " CLR_DIM "Depth" CLR_RESET
           "       " CLR_DIM "Component" CLR_RESET
           "                    " CLR_DIM "Trust Level" CLR_RESET "\n");
    print_separator();

    printf("  " CLR_GREEN "[7]" CLR_RESET "    Hardware    "
           CLR_GREEN "Boot ROM (PBL)" CLR_RESET "               Immutable root of trust\n");
    printf("                        Asymmetric verification via SSBK in OTP fuses\n");
    printf("                        Cannot be patched or modified post-manufacture\n\n");

    printf("  " CLR_GREEN "[6]" CLR_RESET "    Hardware    "
           CLR_GREEN "Secure Element (S3K250AF)" CLR_RESET "    CC EAL5+ certified\n");
    printf("                        Discrete chip outside SoC, credential storage\n");
    printf("                        + Thales eSE/eSIM (CC EAL6+)\n\n");

    printf("  " CLR_CYAN "[5]" CLR_RESET "    Firmware    "
           CLR_CYAN "TrustZone TEE" CLR_RESET "                S-EL1: TEEGRIS (Exynos) / QSEE (SD)\n");
    printf("                        Runs Keymaster, Gatekeeper, TIMA, DRM TAs\n");
    printf("                        Isolated Secure World at ARM S-EL0/S-EL1\n\n");

    printf("  " CLR_CYAN "[4]" CLR_RESET "    Firmware    "
           CLR_CYAN "RKP Hypervisor (uh.bin)" CLR_RESET "     ARM EL2 — above the kernel\n");
    printf("                        Controls page table modifications\n");
    printf("                        Enforces Kernel Data Protection (KDP)\n\n");

    printf("  " CLR_YELLOW "[3]" CLR_RESET "    Software   "
           CLR_YELLOW "Linux Kernel + dm-verity" CLR_RESET "    ARM EL1\n");
    printf("                        SELinux enforcing, RKP-protected structures\n");
    printf("                        dm-verity Merkle tree on system partitions\n\n");

    printf("  " CLR_YELLOW "[2]" CLR_RESET "    Software   "
           CLR_YELLOW "Android Framework" CLR_RESET "            ARM EL0\n");
    printf("                        Knox Platform APIs, app sandboxing\n");
    printf("                        File-Based Encryption (CE + DE domains)\n\n");

    printf("  " CLR_ORANGE "[1]" CLR_RESET "    Software   "
           CLR_ORANGE "User Applications" CLR_RESET "            ARM EL0\n");
    printf("                        Samsung Pay, Secure Folder, Knox Workspace\n");
    printf("                        Depend on all lower layers for trust\n\n");

    /* ARM exception levels */
    print_section_header("ARM Exception Level Layout");

    printf("  " CLR_DIM "Exception Level" CLR_RESET "   "
           CLR_DIM "Normal World" CLR_RESET "          "
           CLR_DIM "Secure World" CLR_RESET "\n");
    print_separator();
    printf("  EL3               " CLR_DIM "---" CLR_RESET
           "                   " CLR_GREEN "Secure Monitor (sboot.bin)" CLR_RESET "\n");
    printf("  EL2               " CLR_CYAN "RKP Hypervisor" CLR_RESET
           "        " CLR_DIM "---" CLR_RESET "\n");
    printf("  S-EL1 / EL1       " CLR_YELLOW "Linux Kernel" CLR_RESET
           "          " CLR_CYAN "TEEGRIS/QSEE Kernel" CLR_RESET "\n");
    printf("  S-EL0 / EL0       " CLR_ORANGE "Android Apps" CLR_RESET
           "          " CLR_CYAN "Keymaster|Gatekeeper|TIMA" CLR_RESET "\n\n");

    /* chipset comparison */
    print_section_header("Chipset Comparison: Exynos 990 vs Snapdragon 865");

    printf("  " CLR_DIM "Feature" CLR_RESET "                "
           CLR_DIM "Exynos 990" CLR_RESET "              "
           CLR_DIM "Snapdragon 865" CLR_RESET "\n");
    print_separator();
    printf("  TEE                  TEEGRIS v4.1.0.0        QSEE / QTEE\n");
    printf("  Secure Element       Integrated iSE + PUF    SPU v4.0 (on-die)\n");
    printf("  SE Certification     GlobalPlatform AVA2     CC EAL4+ / FIPS 140-2 L2\n");
    printf("  DRAM Encryption      Hardware engine          Not present\n");
    printf("  DMA Isolation        S2MPU                   SMMU\n");
    printf("  Modem                Exynos 5123 (discrete)  X55 (integrated)\n");
    printf("  Modem Security       " CLR_RED "WEAK" CLR_RESET
           " (no ASLR, static   Better SMMU isolation\n");
    printf("                       stack cookies)\n");
    printf("  Key Derivation       PUF-based (unique)      SPU hardware keys\n");
    printf("  Market               EU, Asia, Middle East   US, Canada, Korea\n\n");

    /* Knox warranty fuse */
    print_section_header("Knox Warranty eFuse — The Point of No Return");

    printf("  The Knox bit is a " CLR_RED "one-time programmable eFuse" CLR_RESET ".\n");
    printf("  Once tripped (0x0 -> 0x1), it is " CLR_RED "PERMANENT" CLR_RESET ".\n");
    printf("  Not reversible by factory reset, firmware reflash, or any software.\n\n");

    printf("  " CLR_BOLD "TRIGGERS:" CLR_RESET "\n");
    printf("    - Booting a non-Samsung-signed kernel\n");
    printf("    - Flashing TWRP, Magisk, or custom ROM\n");
    printf("    - Rooting the device\n");
    printf("    - Disabling SELinux\n\n");

    printf("  " CLR_BOLD "CONSEQUENCES:" CLR_RESET "\n");
    printf("    " CLR_RED "- Knox Keystore keys permanently inaccessible" CLR_RESET "\n");
    printf("    " CLR_RED "- Secure Folder data permanently lost" CLR_RESET "\n");
    printf("    " CLR_RED "- Knox Workspace containers destroyed" CLR_RESET "\n");
    printf("    " CLR_RED "- Samsung Pay permanently disabled" CLR_RESET "\n");
    printf("    " CLR_RED "- Device health attestation fails permanently" CLR_RESET "\n\n");

    printf("  " CLR_YELLOW "NOTE:" CLR_RESET " Simply unlocking the bootloader does NOT trip the fuse.\n");
    printf("  The fuse trips when custom binaries are " CLR_BOLD "actually flashed" CLR_RESET ".\n\n");

    /* AFU vs BFU */
    print_section_header("AFU vs BFU — The Forensic Boundary");

    printf("  " CLR_BOLD "After First Unlock (AFU)" CLR_RESET "\n");
    printf("  The device has been unlocked at least once since boot.\n");
    printf("  CE (Credential Encrypted) keys remain in memory.\n");
    printf("  " CLR_RED "~95%% of user data is accessible" CLR_RESET " to forensic tools.\n");
    printf("  Photos, messages, app data, call logs — all available.\n\n");

    printf("  " CLR_BOLD "Before First Unlock (BFU)" CLR_RESET "\n");
    printf("  The device has not been unlocked since boot/reboot.\n");
    printf("  CE keys are NOT in memory — only DE storage is accessible.\n");
    printf("  " CLR_GREEN "Only system data, some notifications accessible." CLR_RESET "\n");
    printf("  User photos, messages, app data remain encrypted.\n\n");

    printf("  " CLR_BOLD "Key Insight:" CLR_RESET " Samsung's One UI 7+ auto-restarts locked devices\n");
    printf("  back to BFU state after prolonged inactivity — specifically designed\n");
    printf("  to counter forensic AFU exploitation.\n\n");

    printf("  " CLR_YELLOW "For photo extraction:" CLR_RESET " The device MUST be in AFU state.\n");
    printf("  Keeping a seized device powered on is the #1 forensic priority.\n");
    printf("\n");

    /* encryption */
    print_section_header("File-Based Encryption (FBE) — Key Hierarchy");

    printf("  " CLR_DIM "┌─────────────────────────────────────────┐\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET CLR_GREEN "  DUHK (Device-Unique Hardware Key)       " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET "  Symmetric, hardware-only, never exposed  " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "└──────────────────┬──────────────────────┘\n" CLR_RESET);
    printf("  " CLR_DIM "                   │\n" CLR_RESET);
    printf("  " CLR_DIM "                   ▼\n" CLR_RESET);
    printf("  " CLR_DIM "┌─────────────────────────────────────────┐\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET CLR_CYAN "  REK (Root Encryption Key)               " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET "  Device-unique, via TEE crypto driver      " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "└──────────────────┬──────────────────────┘\n" CLR_RESET);
    printf("  " CLR_DIM "                   │\n" CLR_RESET);
    printf("  " CLR_DIM "                   ▼\n" CLR_RESET);
    printf("  " CLR_DIM "┌─────────────────────────────────────────┐\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET CLR_YELLOW "  HDK (Hardware-Derived Key)              " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET "  Wraps all Keymaster key blobs (AES-GCM)  " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "└────────┬───────────────────┬────────────┘\n" CLR_RESET);
    printf("  " CLR_DIM "         │                   │\n" CLR_RESET);
    printf("  " CLR_DIM "         ▼                   ▼\n" CLR_RESET);
    printf("  " CLR_DIM "┌──────────────────┐ ┌──────────────────┐\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET CLR_GREEN " CE Keys          " CLR_DIM "│ │" CLR_RESET CLR_ORANGE " DE Keys          " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET " PIN + hardware   " CLR_DIM "│ │" CLR_RESET " Hardware only    " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET " Available AFU    " CLR_DIM "│ │" CLR_RESET " Available at boot" CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "│" CLR_RESET " " CLR_RED "Photos, messages" CLR_RESET " " CLR_DIM "│ │" CLR_RESET " Alarms, system   " CLR_DIM "│\n" CLR_RESET);
    printf("  " CLR_DIM "└──────────────────┘ └──────────────────┘\n" CLR_RESET);
    printf("\n");

    printf("  Per-file encryption: " CLR_BOLD "AES-256-XTS" CLR_RESET " with unique per-file keys.\n");
    printf("  Key blobs stored encrypted in Normal World filesystem.\n");
    printf("  Decryption requires TEE + hardware crypto engine.\n");
    printf("\n");

    return 0;
}
