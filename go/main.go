package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

const (
	defaultMagicBytesLength = 256 // шифрую до 256 байт, что бы работало в т.ч. с файлами типа docx, pdf
	minMagicBytesLen        = 4
	xorKey                  = 0xFF
	encryptionMarker        = "ENCR" // простейшая проверка, чтобы предотвратить повторный restore или restore не stashed файла
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: <stash|restore> <filename>")
		return
	}

	mode := os.Args[1]
	filename := os.Args[2]

	switch mode {
	case "stash":
		stashMagicBytes(filename)
	case "restore":
		restoreMagicBytes(filename)
	default:
		fmt.Println("Unknown mode:", mode)
	}
}

func stashMagicBytes(filename string) {
	fileData, err := os.ReadFile(filename)
	fatalOnError(err)

	if isEncrypted(fileData) {
		fmt.Println("File: ", filename, " is already stashed")
		return
	}

	magicBytesEnd := magicBytesLen(len(fileData))

	magicBytes := fileData[:magicBytesEnd]

	encryptedMagicBytes := encrypt(magicBytes)

	// Шифрую сами магические байты
	copy(fileData[:magicBytesEnd], encryptedMagicBytes)

	// Добавляю маркер шифрования.
	fileData = append(fileData, []byte(encryptionMarker)...)

	fatalOnError(
		os.WriteFile(filename, fileData, 0644),
	)

	fmt.Println("File is stashed:", filename)
}

func restoreMagicBytes(filename string) {
	fileData, err := os.ReadFile(filename)
	fatalOnError(err)

	if !isEncrypted(fileData) {
		fmt.Println("File: ", filename, " is not stashed")
		return
	}

	fileData = fileData[:len(fileData)-len(encryptionMarker)]

	magicBytesEnd := magicBytesLen(len(fileData))

	encryptedMagicBytes := fileData[:magicBytesEnd]

	decryptedMagicBytes := encrypt(encryptedMagicBytes)

	// XORю зашифрованные байты
	copy(fileData[:magicBytesEnd], decryptedMagicBytes)

	fatalOnError(
		os.WriteFile(filename, fileData, 0644),
	)

	fmt.Println("File is restored:", filename)
}

func isEncrypted(fileData []byte) bool {
	marker := []byte(encryptionMarker)
	return bytes.HasSuffix(fileData, marker)
}

func encrypt(data []byte) []byte {
	for i := range data {
		data[i] ^= xorKey // имитация шифрования (задача же не про это)
	}
	return data
}

// полная копия encrypt, но вдруг будет что-то сложнее XOR
func decrypt(data []byte) []byte {
	return encrypt(data)
}

func magicBytesLen(fileLen int) int {
	if fileLen < defaultMagicBytesLength {
		return minMagicBytesLen
	}

	return defaultMagicBytesLength
}

func fatalOnError(err error) {
	if err != nil {
		log.Fatal("Ошибка:", err)
	}
}
