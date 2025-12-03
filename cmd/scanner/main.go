package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"shai-hulud-scanner/pkg/scanner"
)

const version = "1.0.0"

const bannerNarrow = `
   ___  _  _   _   ___      _  _ _   _ _    _   _ ___
  / __|| || | /_\ |_ _| ___| || | | | | |  | | | |   \
  \__ \| __ |/ _ \ | | |___| __ | |_| | |__| |_| | |) |
  |___/|_||_/_/ \_\___|    |_||_|\___/|____|\___/|___/

         Supply Chain Malware Detection Scanner
`

func printBanner(banner *os.File) {
	fmt.Fprintln(banner)
	fmt.Fprint(banner, bannerNarrow)
	fmt.Fprintln(banner)
}

func printUsage() {
	fmt.Println("Shai-Hulud Detection Scanner - Cross-platform npm supply chain malware detector")
	fmt.Println()
	fmt.Println("Usage: shai-hulud-scanner [options] [paths...]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  shai-hulud-scanner                          # Quick scan of home directory")
	fmt.Println("  shai-hulud-scanner -mode full               # Full scan of home directory")
	fmt.Println("  shai-hulud-scanner /path/to/project         # Quick scan of specific path")
	fmt.Println("  shai-hulud-scanner -mode full -report scan.txt /projects")
	fmt.Println()
}

func main() {
	// Define flags
	var (
		mode       = flag.String("mode", "quick", "Scan mode: quick or full")
		reportPath = flag.String("report", "./ShaiHulud-Scan-Report.txt", "Report output path")
		noBanner   = flag.Bool("no-banner", false, "Do not print the banner")
		filesOnly  = flag.Bool("files-only", false, "Only scan for malicious files (skip git, npm cache, etc.)")
		showHelp   = flag.Bool("help", false, "Show help message")
		showVer    = flag.Bool("version", false, "Show version")
	)

	flag.Usage = printUsage

	flag.Parse()

	// Handle version
	if *showVer {
		fmt.Printf("shai-hulud-scanner version %s\n", version)
		os.Exit(0)
	}

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	// Validate mode
	scanMode := strings.ToLower(*mode)
	if scanMode != "quick" && scanMode != "full" {
		fmt.Fprintf(os.Stderr, "Error: Invalid mode '%s'. Use 'quick' or 'full'.\n", *mode)
		os.Exit(1)
	}

	// Get root paths from remaining arguments or use default
	rootPaths := flag.Args()
	if len(rootPaths) == 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Could not determine home directory: %v\n", err)
			os.Exit(1)
		}
		rootPaths = []string{homeDir}
	}

	// Print banner
	if !*noBanner {
		printBanner(os.Stdout)
		fmt.Println("============================================")
		fmt.Println(" Shai-Hulud Dynamic Detection (Go)")
		fmt.Println("============================================")
		fmt.Println()

		if scanMode == "quick" {
			fmt.Println("[*] Scan Mode: QUICK (fast scan, common IOCs)")
			fmt.Println("[*] For comprehensive analysis, use: -mode full")
		} else {
			fmt.Println("[*] Scan Mode: FULL (comprehensive deep scan)")
			fmt.Println("[*] This may take several minutes...")
		}
		fmt.Println()
	}

	// Create scanner configuration
	cfg := &scanner.Config{
		RootPaths:  rootPaths,
		ScanMode:   scanner.ScanMode(scanMode),
		ReportPath: *reportPath,
		NoBanner:   *noBanner,
		FilesOnly:  *filesOnly,
		Output:     os.Stdout,
	}
	scan := scanner.New(cfg)
	rpt, err := scan.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", err)
		os.Exit(1)
	}

	rpt.PrintSummary(os.Stdout)

	fmt.Println()
	fmt.Printf("[*] Writing detailed report to: %s\n", *reportPath)
	if err := rpt.WriteToFile(*reportPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
	} else {
		fmt.Println("[*] Report written successfully.")
	}

	fmt.Println()
	fmt.Println("============================================")
	fmt.Println(" Scan complete - review the report carefully")
	fmt.Println("============================================")
	fmt.Println()

	// Exit with error code if critical findings
	if rpt.IsCritical() {
		os.Exit(2)
	}
	if rpt.HasFindings() {
		os.Exit(1)
	}
}
