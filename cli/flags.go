package cli

import (
	"flag"
)

type Flags struct {
	Help        bool
	Version     bool
	Update      bool
	CheckUpdate bool
	CheckTools  bool
	URL         string
	List        string
	Vulns       string
	Encoders    string
	Threads     int
	Silent      bool
	JSON        string
	HTML        string
	TXT         string
}

func ParseFlags() *Flags {
	flags := &Flags{}

	flag.BoolVar(&flags.Help, "help", false, "Show help message")
	flag.BoolVar(&flags.Help, "h", false, "Show help message (short)")
	flag.BoolVar(&flags.Version, "version", false, "Show version information")
	flag.BoolVar(&flags.Update, "update", false, "Update penhunter to the latest version")
	flag.BoolVar(&flags.CheckUpdate, "check-update", false, "Check if a new version is available")
	flag.BoolVar(&flags.CheckTools, "check-tools", false, "Check if all required tools are installed")
	flag.StringVar(&flags.URL, "url", "", "Single URL to test")
	flag.StringVar(&flags.URL, "u", "", "Single URL to test (short)")
	flag.StringVar(&flags.List, "list", "", "File containing list of URLs")
	flag.StringVar(&flags.List, "l", "", "File containing list of URLs (short)")
	flag.StringVar(&flags.Vulns, "vulns", "", "Comma-separated list of vulnerabilities to test")
	flag.StringVar(&flags.Vulns, "v", "", "Comma-separated list of vulnerabilities (short)")
	flag.StringVar(&flags.Encoders, "encoders", "", "Comma-separated list of encoders to use")
	flag.StringVar(&flags.Encoders, "e", "", "Comma-separated list of encoders (short)")
	flag.IntVar(&flags.Threads, "threads", 25, "Number of concurrent threads")
	flag.IntVar(&flags.Threads, "t", 25, "Number of concurrent threads (short)")
	flag.BoolVar(&flags.Silent, "silent", false, "Silent mode (minimal output)")
	flag.StringVar(&flags.JSON, "json", "", "Output results to JSON file")
	flag.StringVar(&flags.HTML, "html", "", "Output results to HTML file")
	flag.StringVar(&flags.TXT, "txt", "", "Output results to text file")

	flag.Parse()

	return flags
}
