package common

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type ResultStatus string

const (
	Pass ResultStatus = "Pass"
	Fail ResultStatus = "Fail"
)

// Result struct for storing results
type Result struct {
	PackageName      string            `json:"package_name"`
	ManifestChecksum string            `json:"manifest_checksum"`
	LayoutChecksums  map[string]string `json:"layout_checksums"`
	Status           ResultStatus      `json:"status"`
	ErrorMessage     string            `json:"error_message,omitempty"`
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

//func GenerateChecksumForLayoutFiles(layoutDir string) (string, error) {
//	var checksums []string
//
//	err := filepath.Walk(layoutDir, func(path string, info os.FileInfo, err error) error {
//		if err != nil {
//			return err
//		}
//
//		// Skip directories
//		if info.IsDir() {
//			return nil
//		}
//
//		// Generate checksum for each file
//		checksum, err := GenerateChecksum(path)
//		if err != nil {
//			return fmt.Errorf("failed to generate checksum for %s: %v", path, err)
//		}
//
//		checksums = append(checksums, checksum)
//		return nil
//	})
//	if err != nil {
//		return "", fmt.Errorf("failed to walk layout directory: %v", err)
//	}
//
//	// Combine checksums of individual files to get a checksum for the entire directory
//	dirChecksum := md5.New()
//	for _, checksum := range checksums {
//		io.WriteString(dirChecksum, checksum)
//	}
//
//	return hex.EncodeToString(dirChecksum.Sum(nil)), nil
//}

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

//func StoreResults(apkPath, outputJSONPath string) error {
//	result := Result{}
//
//	// Extract package name
//	packageName, err := ExtractPackageName(apkPath)
//	if err != nil {
//		result.Status = Fail
//		result.ErrorMessage = err.Error()
//	} else {
//		result.PackageName = packageName
//
//		// Generate checksum for AndroidManifest.xml
//		manifestPath := filepath.Join(apkPath, "AndroidManifest.xml")
//		manifestChecksum, err := GenerateChecksum(manifestPath)
//		if err != nil {
//			result.Status = Fail
//			result.ErrorMessage = err.Error()
//		} else {
//			result.ManifestChecksum = manifestChecksum
//
//			// Generate checksum for res/layout files
//			layoutDir := filepath.Join(apkPath, "res", "layout")
//			layoutChecksums := make(map[string]string)
//			err := filepath.Walk(layoutDir, func(path string, info os.FileInfo, err error) error {
//				if err != nil {
//					return err
//				}
//				if !info.IsDir() {
//					relativePath, err := filepath.Rel(layoutDir, path)
//					if err != nil {
//						return err
//					}
//					checksum, err := GenerateChecksum(path)
//					if err != nil {
//						return err
//					}
//					layoutChecksums[relativePath] = checksum
//				}
//				return nil
//			})
//			if err != nil {
//				result.Status = Fail
//				result.ErrorMessage = err.Error()
//			} else {
//				result.LayoutChecksums = layoutChecksums
//				result.Status = Pass
//			}
//		}
//	}
//
//	// Read existing data from the file
//	existingData, err := ioutil.ReadFile(outputJSONPath)
//	if err != nil && !os.IsNotExist(err) {
//		return err
//	}
//
//	// Unmarshal existing data into a slice of Result
//	var existingSlice []Result
//	if len(existingData) > 0 {
//		if err := json.Unmarshal(existingData, &existingSlice); err != nil {
//			return err
//		}
//	}
//
//	// Append the new result to the existing slice
//	existingSlice = append(existingSlice, result)
//
//	// Marshal the combined data back to JSON
//	combinedData, err := json.MarshalIndent(existingSlice, "", "    ")
//	if err != nil {
//		return err
//	}
//
//	// Write the combined data back to the file
//	err = ioutil.WriteFile(outputJSONPath, combinedData, 0644)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

func ProcessAPK(apkFilename string, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()

	outputDir := filepath.Join("output", strings.TrimSuffix(apkFilename, filepath.Ext(apkFilename)))
	apkDir := filepath.Join("apks", apkFilename)

	if _, err := os.Stat(apkDir); os.IsNotExist(err) {
		fmt.Println("APK file not found:", apkDir)
		return
	}

	err := DecompileAPK(apkDir, outputDir)
	if err != nil {
		fmt.Println("Error during APK decompilation:", err)
		return
	}
	fmt.Println("APK decompiled successfully.")

	result, err := ExtractAndStoreResults(outputDir)
	if err != nil {
		fmt.Println("Error extracting and storing results:", err)
		return
	}

	// Send the result to the channel
	results <- result
}

func ExtractAndStoreResults(apkPath string) (Result, error) {
	result := Result{}

	// Extract package name
	packageName, err := ExtractPackageName(apkPath)
	if err != nil {
		result.Status = Fail
		result.ErrorMessage = err.Error()
		return result, err
	}

	result.PackageName = packageName

	// Generate checksum for AndroidManifest.xml
	manifestPath := filepath.Join(apkPath, "AndroidManifest.xml")
	manifestChecksum, err := GenerateChecksum(manifestPath)
	if err != nil {
		result.Status = Fail
		result.ErrorMessage = err.Error()
		return result, err
	}

	result.ManifestChecksum = manifestChecksum

	// Generate checksum for res/layout files
	layoutDir := filepath.Join(apkPath, "res", "layout")
	layoutChecksums, err := GenerateChecksumsForLayoutFiles(layoutDir)
	if err != nil {
		result.Status = Fail
		result.ErrorMessage = err.Error()
		return result, err
	}

	result.LayoutChecksums = layoutChecksums
	result.Status = Pass

	return result, nil
}

func GenerateChecksumsForLayoutFiles(layoutDir string) (map[string]string, error) {
	checksums := make(map[string]string)

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

		relativePath, err := filepath.Rel(layoutDir, path)
		if err != nil {
			return err
		}

		checksums[relativePath] = checksum
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk layout directory: %v", err)
	}

	return checksums, nil
}

func StoreResults(results []Result, outputJSONPath string) error {
	// Read existing data from the file
	existingData, err := ioutil.ReadFile(outputJSONPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Unmarshal existing data into a slice of Result
	var existingSlice []Result
	if len(existingData) > 0 {
		if err := json.Unmarshal(existingData, &existingSlice); err != nil {
			return err
		}
	}

	// Append the new results to the existing slice
	existingSlice = append(existingSlice, results...)

	// Marshal the combined data back to JSON
	combinedData, err := json.MarshalIndent(existingSlice, "", "    ")
	if err != nil {
		return err
	}

	// Write the combined data back to the file
	err = ioutil.WriteFile(outputJSONPath, combinedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

//func IsApktoolInstalled() bool {
//	// Check if 'apktool' command is available in PATH
//	_, err := exec.LookPath(apktoolCmd)
//	return err == nil
//}
