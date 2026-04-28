package core

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// UserConfig holds user-configurable callback URLs
type UserConfig struct {
	XSSCallback    string
	RedirectDomain string
	SSRFCallback   string
	OOBServer      string
}

// Global user config
var userConfig *UserConfig

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetPenhunterHome returns the penhunter home directory
// Linux/macOS: $HOME/penhunter
// Windows: %USERPROFILE%\penhunter
func GetPenhunterHome() string {
	usr, err := user.Current()
	if err != nil {
		// Fallback
		if runtime.GOOS == "windows" {
			return filepath.Join(os.Getenv("USERPROFILE"), "penhunter")
		}
		return filepath.Join(os.Getenv("HOME"), "penhunter")
	}
	return filepath.Join(usr.HomeDir, "penhunter")
}

// GetConfigPath returns the config directory path
func GetConfigPath() string {
	// First check penhunter home directory
	homePath := filepath.Join(GetPenhunterHome(), "config")
	if FileExists(homePath) {
		return homePath
	}

	// Check if running from installed location (legacy support)
	if runtime.GOOS != "windows" {
		legacyPath := filepath.Join(GetPenhunterHome(), "config")
		if FileExists(legacyPath) {
			return legacyPath
		}
	}

	// Fallback to local config (development)
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	return filepath.Join(execDir, "config")
}

// parseYAMLValue extracts value from a simple "key: value" or 'key: "value"' line
func parseYAMLValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	value := strings.TrimSpace(parts[1])
	// Remove quotes if present
	value = strings.Trim(value, `"'`)
	return value
}

// LoadUserConfig loads the user configuration from user_config.yaml
func LoadUserConfig() (*UserConfig, error) {
	if userConfig != nil {
		return userConfig, nil
	}

	configPath := filepath.Join(GetConfigPath(), "user_config.yaml")

	// Default values
	userConfig = &UserConfig{
		XSSCallback:    "https://YOUR_XSS_CALLBACK_URL",
		RedirectDomain: "evil.com",
		SSRFCallback:   "https://YOUR_SSRF_CALLBACK_URL",
		OOBServer:      "https://YOUR_OOB_SERVER",
	}

	// Load from file if exists
	if FileExists(configPath) {
		file, err := os.Open(configPath)
		if err != nil {
			return userConfig, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Skip comments and empty lines
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if strings.HasPrefix(line, "xss_callback:") {
				userConfig.XSSCallback = parseYAMLValue(line)
			} else if strings.HasPrefix(line, "redirect_domain:") {
				userConfig.RedirectDomain = parseYAMLValue(line)
			} else if strings.HasPrefix(line, "ssrf_callback:") {
				userConfig.SSRFCallback = parseYAMLValue(line)
			} else if strings.HasPrefix(line, "oob_server:") {
				userConfig.OOBServer = parseYAMLValue(line)
			}
		}
	}

	return userConfig, nil
}

// GetXSSCallback returns the configured XSS callback URL
func GetXSSCallback() string {
	cfg, _ := LoadUserConfig()
	return cfg.XSSCallback
}

// GetRedirectDomain returns the configured redirect test domain
func GetRedirectDomain() string {
	cfg, _ := LoadUserConfig()
	return cfg.RedirectDomain
}

// GetSSRFCallback returns the configured SSRF callback URL
func GetSSRFCallback() string {
	cfg, _ := LoadUserConfig()
	return cfg.SSRFCallback
}

// GetOOBServer returns the configured OOB server
func GetOOBServer() string {
	cfg, _ := LoadUserConfig()
	return cfg.OOBServer
}

// IsCallbackConfigured checks if the user has configured their callback URLs
func IsCallbackConfigured() bool {
	cfg, _ := LoadUserConfig()
	return cfg.XSSCallback != "https://YOUR_XSS_CALLBACK_URL" &&
		cfg.XSSCallback != ""
}
