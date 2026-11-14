package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	versionFlag := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Bitseal v%s (build: %s)\n", Version, Build)
		os.Exit(0)
	}

	encCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encFile := encCmd.String("file", "", "File to encrypt")
	encOut := encCmd.String("out", "", "Output file (optional, appends .enc)")

	decCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decFile := decCmd.String("file", "", "File to decrypt")
	decOut := decCmd.String("out", "", "Output file (optional, removes .enc)")

	if len(os.Args) < 2 {
		fmt.Println("Bitseal - File Encryption CLI Tool")
		fmt.Printf("Version: v%s\n\n", Version)
		fmt.Println("Usage: bitseal <encrypt|decrypt> -file <path> [-out <path>]")
		fmt.Println("       bitseal -version")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		encCmd.Parse(os.Args[2:])
		if *encFile == "" {
			fmt.Println("Error: -file flag required")
			os.Exit(1)
		}
		if err := encryptCommand(*encFile, *encOut); err != nil {
			fmt.Printf("Encryption error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ File encrypted successfully")

	case "decrypt":
		decCmd.Parse(os.Args[2:])
		if *decFile == "" {
			fmt.Println("Error: -file flag required")
			os.Exit(1)
		}
		if err := decryptCommand(*decFile, *decOut); err != nil {
			fmt.Printf("Decryption error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ File decrypted successfully")

	case "-version":
		fmt.Printf("Bitseal v%s (build: %s)\n", Version, Build)
		os.Exit(0)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func encryptCommand(inputPath, outputPath string) error {
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	manager := NewCipherManager()
	return manager.EncryptFile(inputPath, outputPath, password)
}

func decryptCommand(inputPath, outputPath string) error {
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	manager := NewCipherManager()
	return manager.DecryptFile(inputPath, outputPath, password)
}
