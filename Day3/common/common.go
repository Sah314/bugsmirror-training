package common

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)


type enum ={
	
}

var jsonData struct {
	PackageName string `json:"packageName"`

	Result enum `json:"result"`

}

func DownloadFile(url, outputPath string) error {
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP response error: %s", response.Status)
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, response.Body)
	if err != nil {
		return err
	}

	return nil
}

func GenerateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {

		}
	}(file)

	hash := md5.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", fmt.Errorf("failed to generate checksum: %v", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func GenerateChecksumForLayoutFiles(layoutDir string) (string, error) {
	var checksums []string

	err := filepath.Walk(layoutDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Generate checksum for each file
		checksum, err := GenerateChecksum(path)
		if err != nil {
			return fmt.Errorf("failed to generate checksum for %s: %v", path, err)
		}

		checksums = append(checksums, checksum)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to walk layout directory: %v", err)
	}

	// Combine checksums of individual files to get a checksum for the entire directory
	dirChecksum := md5.New()
	for _, checksum := range checksums {
		io.WriteString(dirChecksum, checksum)
	}

	return hex.EncodeToString(dirChecksum.Sum(nil)), nil
}

func DecompileAPK(apkPath, outputDir string) error {
	cmd := exec.Command("java", "-jar", "apktool.jar", "d", apkPath, "-o", outputDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run the command
	err := cmd.Run()
	if err != nil {
		//Todo: Can use log instead of fmt
		return fmt.Errorf("failed to decompile APK: %v", err)
	}

	return nil
}

func ExtractPackageName(outputDir string) (string, error) {
	//Todo: Use filepath package here
	manifestPath := outputDir + "/AndroidManifest.xml"

	// Read the AndroidManifest.xml file
	file, err := os.Open(manifestPath)
	if err != nil {
		return "", fmt.Errorf("failed to open AndroidManifest.xml: %v", err)
	}
	defer file.Close()

	// Define a regular expression pattern to extract the package name
	pattern := regexp.MustCompile(`package="([^"]+)"`)

	// Read file content and apply the regular expression
	buffer := make([]byte, 1024)
	_, err = file.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to read AndroidManifest.xml: %v", err)
	}

	match := pattern.FindStringSubmatch(string(buffer))
	if match == nil {
		return "", fmt.Errorf("failed to extract package name from AndroidManifest.xml")
	}

	return match[1], nil
}
//func IsApktoolInstalled() bool {
//	// Check if 'apktool' command is available in PATH
//	_, err := exec.LookPath(apktoolCmd)
//	return err == nil
//}
