#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "sampass.h"

/*
 * CVE-2021-25444 Proof of Concept — AES-GCM Nonce Reuse
 *
 * Samsung's Keymaster TA used AES-256-GCM to wrap key blobs but derived
 * the IV deterministically, causing the same nonce to be reused across
 * different encryptions. This is a catastrophic failure mode for GCM:
 *
 *   C1 = P1 XOR E(K, IV, ctr)
 *   C2 = P2 XOR E(K, IV, ctr)     <-- same K, same IV, same ctr stream
 *
 *   Therefore: C1 XOR C2 = P1 XOR P2
 *
 * An attacker who knows or can guess P1 (e.g., a key blob with known
 * structure) can recover P2 directly. Additionally, the relationship
 * between authentication tags leaks the GHASH key H, enabling forgery.
 *
 * This demo uses synthetic data — no real device is involved.
 */

static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *pt, int pt_len,
                           uint8_t *ct, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, ct_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto fail;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1)
        goto fail;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1)
        goto fail;
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto fail;

    EVP_CIPHER_CTX_free(ctx);
    return ct_len;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int keymaster_demo(void)
{
    print_section_header("CVE-2021-25444 — Keymaster AES-GCM IV Reuse PoC");

    printf("  This demonstrates the cryptographic flaw in Samsung's Keymaster TA\n");
    printf("  that affected ~100 million devices (Galaxy S9 through S21).\n\n");
    printf("  The Keymaster wrapped key blobs using AES-256-GCM with a " CLR_RED "reused IV" CLR_RESET ".\n");
    printf("  GCM is a stream cipher mode — reusing the nonce is catastrophic.\n\n");

    /* step 1: generate synthetic key and IV */
    printf(CLR_BOLD "  [STEP 1] Generate AES-256 key and 96-bit IV (simulating Keymaster)\n" CLR_RESET);
    print_separator();

    uint8_t key[32];
    uint8_t iv[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    printf("  AES-256 Key (Hardware-Derived Key):\n");
    hex_dump(key, sizeof(key));
    printf("\n  IV / Nonce (deterministically derived — " CLR_RED "THIS IS THE BUG" CLR_RESET "):\n");
    hex_dump(iv, sizeof(iv));

    /* step 2: two different key blobs, same nonce */
    printf("\n" CLR_BOLD "  [STEP 2] Encrypt two different key blobs with the SAME nonce\n" CLR_RESET);
    print_separator();

    /* simulate two different key blobs with known structure */
    uint8_t plaintext1[48] = {
        /* key blob header (known structure) */
        0x00, 0x01, 0x00, 0x0F,  /* version, type */
        0x00, 0x00, 0x01, 0x00,  /* key size: 256 */
        /* actual key material (AES-256 key being protected) */
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        /* padding */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t plaintext2[48] = {
        /* same header structure */
        0x00, 0x01, 0x00, 0x0F,
        0x00, 0x00, 0x01, 0x00,
        /* different key material (RSA private key fragment) */
        0xD4, 0x3A, 0x98, 0x76, 0x1F, 0x5C, 0x01, 0xB3,
        0x8E, 0x22, 0xAA, 0x67, 0xF0, 0x11, 0xBD, 0x95,
        0x4C, 0xE7, 0x90, 0x18, 0x3A, 0x55, 0x62, 0xC8,
        0x71, 0x09, 0xAB, 0xF3, 0xE5, 0x7D, 0x40, 0x6E,
        /* padding */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    printf("  Plaintext 1 (Key Blob #1 — e.g., AES key for file encryption):\n");
    hex_dump(plaintext1, sizeof(plaintext1));
    printf("\n  Plaintext 2 (Key Blob #2 — e.g., RSA private key fragment):\n");
    hex_dump(plaintext2, sizeof(plaintext2));

    uint8_t ct1[48], ct2[48];
    uint8_t tag1[16], tag2[16];

    int ct1_len = aes_gcm_encrypt(key, iv, plaintext1, 48, ct1, tag1);
    int ct2_len = aes_gcm_encrypt(key, iv, plaintext2, 48, ct2, tag2);

    if (ct1_len < 0 || ct2_len < 0) {
        color_print(CLR_RED, "\n  error: AES-GCM encryption failed\n");
        return 1;
    }

    printf("\n  Ciphertext 1 (encrypted with key, " CLR_RED "IV" CLR_RESET "):\n");
    hex_dump(ct1, 48);
    printf("  Tag 1: ");
    for (int i = 0; i < 16; i++) printf("%02x", tag1[i]);
    printf("\n");

    printf("\n  Ciphertext 2 (encrypted with key, " CLR_RED "SAME IV" CLR_RESET "):\n");
    hex_dump(ct2, 48);
    printf("  Tag 2: ");
    for (int i = 0; i < 16; i++) printf("%02x", tag2[i]);
    printf("\n");

    /* step 3: the attack — XOR ciphertexts */
    printf("\n" CLR_BOLD "  [STEP 3] The Attack — XOR the two ciphertexts\n" CLR_RESET);
    print_separator();

    printf("  Since both used the same keystream (same key + same IV):\n");
    printf("    C1 = P1 " CLR_CYAN "XOR" CLR_RESET " keystream\n");
    printf("    C2 = P2 " CLR_CYAN "XOR" CLR_RESET " keystream\n");
    printf("    C1 " CLR_CYAN "XOR" CLR_RESET " C2 = P1 " CLR_CYAN "XOR" CLR_RESET " P2  "
           CLR_DIM "(keystream cancels out)" CLR_RESET "\n\n");

    uint8_t ct_xor[48];
    for (int i = 0; i < 48; i++)
        ct_xor[i] = ct1[i] ^ ct2[i];

    printf("  C1 XOR C2 (computed by attacker):\n");
    hex_dump(ct_xor, 48);

    /* verify: compute P1 XOR P2 directly */
    uint8_t pt_xor[48];
    for (int i = 0; i < 48; i++)
        pt_xor[i] = plaintext1[i] ^ plaintext2[i];

    printf("\n  P1 XOR P2 (ground truth — attacker doesn't have this directly):\n");
    hex_dump(pt_xor, 48);

    /* verify they match */
    bool match = (memcmp(ct_xor, pt_xor, 48) == 0);
    printf("\n  " CLR_BOLD "MATCH: " CLR_RESET);
    if (match) {
        color_print(CLR_RED, "YES — C1^C2 == P1^P2  (nonce reuse confirmed)\n");
    } else {
        color_print(CLR_GREEN, "NO (this should not happen)\n");
    }

    /* step 4: key recovery scenario */
    printf("\n" CLR_BOLD "  [STEP 4] Key Recovery — Why This Breaks Everything\n" CLR_RESET);
    print_separator();

    printf("  The key blob header bytes are " CLR_YELLOW "known/predictable" CLR_RESET " (fixed structure).\n");
    printf("  The first 8 bytes of both blobs share the same header:\n\n");
    printf("    Header: 00 01 00 0f 00 00 01 00\n\n");

    printf("  Since the attacker knows P1_header and has (P1 XOR P2):\n");
    printf("    P2_header = P1_header XOR (P1 XOR P2)  ...for the known bytes\n\n");

    printf("  Recovering P2's key material from position 8 onward:\n");
    printf("  If attacker knows ALL of P1 (e.g., they generated it themselves),\n");
    printf("  they can recover ALL of P2:\n\n");

    printf("    P2 = P1 XOR (C1 XOR C2)\n\n");

    uint8_t recovered[48];
    for (int i = 0; i < 48; i++)
        recovered[i] = plaintext1[i] ^ ct_xor[i];

    printf("  Recovered P2 (using P1 and ciphertext XOR):\n");
    hex_dump(recovered, 48);

    bool recovered_ok = (memcmp(recovered, plaintext2, 48) == 0);
    printf("\n  " CLR_BOLD "FULL RECOVERY: " CLR_RESET);
    if (recovered_ok) {
        color_print(CLR_RED, "SUCCESS — P2 fully recovered without TEE access\n");
    } else {
        color_print(CLR_GREEN, "FAILED (unexpected)\n");
    }

    /* step 5: GHASH key leak via tags */
    printf("\n" CLR_BOLD "  [STEP 5] Authentication Tag Analysis — GHASH Key Leak\n" CLR_RESET);
    print_separator();

    printf("  GCM authentication tags are computed using a secret hash key H:\n");
    printf("    H = AES_K(0^128)   (encrypt the zero block with the key)\n\n");
    printf("  With nonce reuse, the tag relationship leaks H:\n");
    printf("    Tag1 XOR Tag2 = GHASH_H(C1) XOR GHASH_H(C2)\n");
    printf("    This is a polynomial equation in GF(2^128) solvable for H.\n\n");

    uint8_t tag_xor[16];
    for (int i = 0; i < 16; i++)
        tag_xor[i] = tag1[i] ^ tag2[i];

    printf("  Tag1 XOR Tag2:\n");
    hex_dump(tag_xor, 16);

    printf("\n  With H recovered, the attacker can:\n");
    printf("  " CLR_RED "  1. Forge valid authentication tags for arbitrary ciphertexts\n" CLR_RESET);
    printf("  " CLR_RED "  2. Modify encrypted key blobs without detection\n" CLR_RESET);
    printf("  " CLR_RED "  3. Inject chosen key material into the Keymaster's trust chain\n" CLR_RESET);

    /* summary */
    printf("\n");
    print_section_header("PoC Summary");

    printf("  " CLR_RED "VULNERABILITY:" CLR_RESET "  AES-256-GCM with deterministic (reused) IV\n");
    printf("  " CLR_RED "ROOT CAUSE:" CLR_RESET "     Keymaster derived IV from blob metadata, not random\n");
    printf("  " CLR_RED "IMPACT:" CLR_RESET "         Full decryption of hardware-protected key blobs\n");
    printf("  " CLR_RED "SCALE:" CLR_RESET "          ~100 million Samsung devices (S9 through S21)\n");
    printf("  " CLR_RED "DISCLOSURE:" CLR_RESET "     USENIX Security 2022 — Tel Aviv University\n");
    printf("  " CLR_RED "SAMSUNG FIX:" CLR_RESET "    Removed entire legacy v15 blob implementation\n\n");

    printf("  " CLR_YELLOW "This PoC used synthetic keys — no real device was targeted.\n" CLR_RESET);
    printf("  " CLR_YELLOW "The mathematical proof is identical to the real vulnerability.\n" CLR_RESET);
    printf("\n");

    return 0;
}
