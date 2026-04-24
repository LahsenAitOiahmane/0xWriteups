#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emmintrin.h>
#include <wmmintrin.h>

static void aes_block_transform(const uint8_t *in, uint8_t *out, uint8_t key_byte) {
    __m128i key = _mm_set1_epi8((char)key_byte);
    __m128i k0 = _mm_aeskeygenassist_si128(key, 0x00);
    __m128i k1 = _mm_aeskeygenassist_si128(key, 0x10);
    __m128i data = _mm_loadu_si128((const __m128i *)in);

    // Match the binary: data ^= k1; data = aesdeclast(data, k0).
    data = _mm_xor_si128(data, k1);
    data = _mm_aesdeclast_si128(data, k0);
    _mm_storeu_si128((__m128i *)out, data);
}

static int decrypt_blob(const uint8_t *file, size_t file_size, uint64_t va,
                        size_t size, const char *out_path) {
    const uint64_t data_va_base = 0x140004000ULL;
    const uint64_t data_file_off = 0x2600ULL;
    size_t blocks = (size + 15U) / 16U;
    size_t out_size = blocks * 16U;
    uint64_t offset = (va - data_va_base) + data_file_off;

    if (va < data_va_base || offset + out_size > file_size) {
        fprintf(stderr, "Invalid blob range: va=0x%llx size=0x%zx\n",
                (unsigned long long)va, size);
        return -1;
    }

    const uint8_t *enc = file + offset;
    uint8_t *out = (uint8_t *)calloc(1, out_size);
    if (!out) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    for (size_t i = 0; i < blocks; i++) {
        aes_block_transform(enc + (i * 16U), out + (i * 16U), (uint8_t)i);
    }

    FILE *f = fopen(out_path, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s: %s\n", out_path, strerror(errno));
        free(out);
        return -1;
    }
    fwrite(out, 1, out_size, f);
    fclose(f);
    free(out);

    printf("Wrote %s (size=0x%zx, blocks=0x%zx)\n", out_path, size, blocks);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <partialencryption.exe>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) {
        fprintf(stderr, "Invalid file size\n");
        fclose(f);
        return 1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        fprintf(stderr, "Failed to read file\n");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    int rc = 0;
    rc |= decrypt_blob(buf, (size_t)fsize, 0x140004000ULL, 0x70,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_4000.bin");
    rc |= decrypt_blob(buf, (size_t)fsize, 0x140004070ULL, 0x40,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_4070.bin");
    rc |= decrypt_blob(buf, (size_t)fsize, 0x140004110ULL, 0x30,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_4110.bin");
    rc |= decrypt_blob(buf, (size_t)fsize, 0x140004140ULL, 0x1a0,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_4140.bin");
    rc |= decrypt_blob(buf, (size_t)fsize, 0x1400042e0ULL, 0x1e0,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_42e0.bin");
    rc |= decrypt_blob(buf, (size_t)fsize, 0x1400044c0ULL, 0x270,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_44c0.bin");
    rc |= decrypt_blob(buf, (size_t)fsize, 0x140004730ULL, 0x100,
                       "/mnt/c/Users/sadik/Documents/Shaned/rev/decrypted/blob_4730.bin");

    free(buf);
    return rc ? 1 : 0;
}
