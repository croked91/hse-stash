#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int DEFAULT_MAGIC_BYTES_LENGTH = 256;  // шифрую до 256 байт, что бы работало в т.ч. с файлами типа docx, pdf
const int MIN_MAGIC_BYTES_LEN = 4;
const unsigned char XOR_KEY = 0xFF;
const char *ENCRYPTION_MARKER = "ENCR";  // простейшая проверка, чтобы предотвратить повторный restore или restore не stashed файла

void stashMagicBytes(const char *filename);
void restoreMagicBytes(const char *filename);
int isEncrypted(const unsigned char *fileData, size_t fileLen);
void encrypt(unsigned char *data, size_t len);
void decrypt(unsigned char *data, size_t len);
size_t magicBytesLen(size_t fileLen);
void fatalOnError(int condition, const char *message);
void readFile(const char *filename, unsigned char **fileData, size_t *fileLen);
void writeFile(const char *filename, unsigned char *fileData, size_t fileLen);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: <stash|restore> <filename>\n");
        return 1;
    }

    const char *mode = argv[1];
    const char *filename = argv[2];

    if (strcmp(mode, "stash") == 0) {
        stashMagicBytes(filename);
    } else if (strcmp(mode, "restore") == 0) {
        restoreMagicBytes(filename);
    } else {
        printf("Unknown mode: %s\n", mode);
        return 1;
    }

    return 0;
}

void stashMagicBytes(const char *filename) {
    unsigned char *fileData = NULL;
    size_t fileLen = 0;

    readFile(filename, &fileData, &fileLen);

    if (isEncrypted(fileData, fileLen)) {
        printf("File: %s is already stashed\n", filename);
        free(fileData);
        return;
    }

    size_t magicBytesEnd = magicBytesLen(fileLen);

    // Шифрую сами магические байты
    encrypt(fileData, magicBytesEnd);

    // Добавляю маркер шифрования.
    // а-ля гошный аппенд
    fileData = realloc(fileData, fileLen + strlen(ENCRYPTION_MARKER));
    fatalOnError(fileData == NULL, "Memory allocation error");
    memcpy(fileData + fileLen, ENCRYPTION_MARKER, strlen(ENCRYPTION_MARKER));

    writeFile(filename, fileData, fileLen + strlen(ENCRYPTION_MARKER));

    printf("File is stashed: %s\n", filename);

    free(fileData);
}

void restoreMagicBytes(const char *filename) {
    unsigned char *fileData = NULL;
    size_t fileLen = 0;

    readFile(filename, &fileData, &fileLen);

    if (!isEncrypted(fileData, fileLen)) {
        printf("File: %s is not stashed\n", filename);
        free(fileData);
        return;
    }

    fileLen -= strlen(ENCRYPTION_MARKER);

    size_t magicBytesEnd = magicBytesLen(fileLen);

    // XORю зашифрованные байты
    decrypt(fileData, magicBytesEnd);

    writeFile(filename, fileData, fileLen);

    printf("File is restored: %s\n", filename);

    free(fileData);
}

int isEncrypted(const unsigned char *fileData, size_t fileLen) {
    size_t markerLen = strlen(ENCRYPTION_MARKER);
    if (fileLen < markerLen) return 0;
    return memcmp(fileData + fileLen - markerLen, ENCRYPTION_MARKER, markerLen) == 0;
}

void encrypt(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

void decrypt(unsigned char *data, size_t len) {
    encrypt(data, len);
}

size_t magicBytesLen(size_t fileLen) {
    return (fileLen < DEFAULT_MAGIC_BYTES_LENGTH) ? MIN_MAGIC_BYTES_LEN : DEFAULT_MAGIC_BYTES_LENGTH;
}

void fatalOnError(int condition, const char *message) {
    if (condition) {
        fprintf(stderr, "Error: %s\n", message);
        exit(1);
    }
}

// кажется, что указатель на указатель это сомнительно, но с другой стороны такие примеры встречал
void readFile(const char *filename, unsigned char **fileData, size_t *fileLen) {
    FILE *file = fopen(filename, "rb");
    fatalOnError(file == NULL, "Cannot open file");

    fseek(file, 0, SEEK_END);
    *fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);

    *fileData = malloc(*fileLen);
    fatalOnError(*fileData == NULL, "Memory allocation error");

    fread(*fileData, 1, *fileLen, file);
    fclose(file);
}

void writeFile(const char *filename, unsigned char *fileData, size_t fileLen) {
    FILE *file = fopen(filename, "wb");
    fatalOnError(file == NULL, "Cannot open file for writing");

    fwrite(fileData, 1, fileLen, file);
    fclose(file);
}