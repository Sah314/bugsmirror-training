package main

import (
	"fmt"
	"os"
	"path/filepath"
	"training/Day3/common"
)

const (
	apktoolCmd = "apktool"
	//bitbucketRepo = "https://bitbucket.org/iBotPeaches/apktool.git"
	apktoolVersion = "2.6.0"
)

func main() {
	//Todo:Implement for all the the apks

	// Replace "com.anumati.apk" with the path to your APK file
	apkPath := "com.anumati.apk"

	// Specify the output directory for decompiled files
	outputDir := "Day3"

	err := common.DownloadFile(fmt.Sprintf("https://github.com/iBotPeaches/Apktool/releases/download/v%s/apktool_%s.jar", apktoolVersion, apktoolVersion), "apktool.jar")
	if err != nil {
		fmt.Println("Error downloading Apktool JAR:", err)
		os.Exit(1)
	}

	// Perform the APK decompilation
	err = common.DecompileAPK(apkPath, outputDir)
	if err != nil {
		fmt.Println("Error during APK decompilation:", err)
		os.Exit(1)
	}

	// Run the APKTool command to decompile the APK

	fmt.Println("APK decompiled successfully.")

	packageName, err := common.ExtractPackageName(outputDir)
	if err != nil {
		fmt.Println("Error extracting package name:", err)
		os.Exit(1)
	}

	fmt.Println("Package name:", packageName)

	manifestChecksum, err := common.GenerateChecksum(filepath.Join(outputDir, "AndroidManifest.xml"))
	if err != nil {
		fmt.Println("Error generating checksum for AndroidManifest.xml:", err)
		os.Exit(1)
	}
	fmt.Println("Checksum for AndroidManifest.xml:", manifestChecksum)

	layoutChecksum, err := common.GenerateChecksumForLayoutFiles(filepath.Join(outputDir, "res", "layout"))
	if err != nil {
		fmt.Println("Error generating checksum for res/layout files:", err)
		os.Exit(1)
	}
	fmt.Println("Checksum for res/layout files:", layoutChecksum)

}
