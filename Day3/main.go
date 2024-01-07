package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"training/Day3/common"
)

const (
	apktoolVersion = "2.6.0"
)

var apkFilenames = []string{"com.anumati.apk"}

func main() {
	//Todo:Implement for all the the apks

	err := common.DownloadFile(fmt.Sprintf("https://github.com/iBotPeaches/Apktool/releases/download/v%s/apktool_%s.jar", apktoolVersion, apktoolVersion), "apktool.jar")
	if err != nil {
		fmt.Println("Error downloading Apktool JAR:", err)
		os.Exit(1)
	}
	var wg sync.WaitGroup

	for _, apkFilename := range apkFilenames {
		wg.Add(1)
		go func(apkFilename string) {
			defer wg.Done()

			outputDir := filepath.Join("output", strings.TrimSuffix(apkFilename, filepath.Ext(apkFilename)))
			apkDir := filepath.Join("apks", apkFilename)

			if _, err = os.Stat(apkDir); os.IsNotExist(err) {
				fmt.Println("APK file not found:", apkDir)
				os.Exit(1)
			}

			err = common.DecompileAPK(apkDir, outputDir)
			if err != nil {
				fmt.Println("Error during APK decompilation:", err)
				os.Exit(1)
			}
			fmt.Println("APK decompiled successfully.")

			//packageName, err := common.ExtractPackageName(outputDir)
			//if err != nil {
			//	fmt.Println("Error extracting package name:", err)
			//	os.Exit(1)
			//}
			//
			//manifestChecksum, err := common.GenerateChecksum(filepath.Join(outputDir, "AndroidManifest.xml"))
			//if err != nil {
			//	fmt.Println("Error generating checksum for AndroidManifest.xml:", err)
			//	os.Exit(1)
			//}

			//layoutChecksum, err := common.GenerateChecksumForLayoutFiles(filepath.Join(outputDir, "res", "layout"))
			//if err != nil {
			//	fmt.Println("Error generating checksum for res/layout files:", err)
			//	os.Exit(1)
			//}

			// Create a unique JSON file for each APK
			outputJSONPath := "results.json"
			// Store results in JSON file
			err = common.StoreResults(outputDir, outputJSONPath)
			if err != nil {
				fmt.Println("Error storing results:", err)
				os.Exit(1)
			}
		}(apkFilename)
	}

	wg.Wait()
	fmt.Println("All downloads and processing completed.")

}
