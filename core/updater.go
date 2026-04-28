package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"penhunter/utils"
)

const (
	CurrentVersion = "0.1.0"
	GitHubRepo     = "cc1a2b/penhunter" // Update this with your actual GitHub repo
	GitHubAPIURL   = "https://api.github.com/repos/" + GitHubRepo + "/releases/latest"
)

type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
	Body string `json:"body"`
}

// CheckForUpdates checks if a newer version is available
func CheckForUpdates() (bool, string, error) {
	resp, err := http.Get(GitHubAPIURL)
	if err != nil {
		return false, "", fmt.Errorf("failed to check for updates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("failed to check for updates: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("failed to read update response: %v", err)
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return false, "", fmt.Errorf("failed to parse update response: %v", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(CurrentVersion, "v")

	if compareVersions(latestVersion, currentVersion) > 0 {
		return true, release.TagName, nil
	}

	return false, "", nil
}

// UpdateTool downloads and installs the latest version
func UpdateTool() error {
	fmt.Printf("%sChecking for updates...%s\n", utils.Yellow, utils.NC)

	resp, err := http.Get(GitHubAPIURL)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to check for updates: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read update response: %v", err)
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return fmt.Errorf("failed to parse update response: %v", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(CurrentVersion, "v")

	if compareVersions(latestVersion, currentVersion) <= 0 {
		fmt.Printf("%sYou are already running the latest version (%s)%s\n", utils.Green, CurrentVersion, utils.NC)
		return nil
	}

	fmt.Printf("%sNew version available: %s (current: %s)%s\n", utils.Green, release.TagName, CurrentVersion, utils.NC)
	fmt.Printf("%sRelease notes:%s\n%s\n", utils.Yellow, utils.NC, release.Body)

	// Find the appropriate binary for this platform
	var downloadURL string
	osArch := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, osArch) || strings.Contains(asset.Name, "penhunter") {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		// Fallback: try to find any penhunter binary
		for _, asset := range release.Assets {
			if strings.Contains(strings.ToLower(asset.Name), "penhunter") {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no suitable binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	fmt.Printf("%sDownloading update from: %s%s\n", utils.Yellow, downloadURL, utils.NC)

	// Download the new binary
	resp, err = http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %v", err)
	}
	defer resp.Body.Close()

	// Get the current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Create temporary file for new binary
	tmpPath := execPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write update file: %v", err)
	}
	out.Close()

	// Make it executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to make binary executable: %v", err)
	}

	// Replace the old binary
	if err := os.Rename(tmpPath, execPath); err != nil {
		// On Windows, we might need to remove the old file first
		if runtime.GOOS == "windows" {
			os.Remove(execPath)
			if err := os.Rename(tmpPath, execPath); err != nil {
				return fmt.Errorf("failed to replace binary: %v", err)
			}
		} else {
			return fmt.Errorf("failed to replace binary: %v", err)
		}
	}

	fmt.Printf("%sUpdate successful! New version: %s%s\n", utils.Green, release.TagName, utils.NC)
	fmt.Printf("%sPlease restart penhunter to use the new version.%s\n", utils.Yellow, utils.NC)

	return nil
}

// compareVersions compares two version strings
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &num1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &num2)
		}

		if num1 > num2 {
			return 1
		} else if num1 < num2 {
			return -1
		}
	}

	return 0
}

// GetInstallPath returns the installation path
// Uses $HOME/penhunter on Linux/macOS, %USERPROFILE%\penhunter on Windows
func GetInstallPath() string {
	return GetPenhunterHome()
}

// IsInstalled checks if penhunter is installed in the user's home directory
func IsInstalled() bool {
	penhunterHome := GetPenhunterHome()
	binPath := filepath.Join(penhunterHome, "bin", "penhunter")
	return FileExists(binPath)
}

// InstallUpdate installs the update
func InstallUpdate() error {
	if IsInstalled() {
		fmt.Printf("%sPenhunter is installed. Updating...%s\n", utils.Yellow, utils.NC)
		penhunterHome := GetPenhunterHome()
		binPath := filepath.Join(penhunterHome, "bin", "penhunter")
		fmt.Printf("%sTo update manually, download the latest release to: %s%s\n", utils.Yellow, binPath, utils.NC)
		fmt.Printf("  wget -O %s https://github.com/%s/releases/latest/download/penhunter_%s_%s\n", binPath, GitHubRepo, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  chmod +x %s\n", binPath)
	}

	return UpdateTool()
}

