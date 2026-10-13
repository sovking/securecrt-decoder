// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.1
// Description: Command-line entrypoint, flag parsing, and multi-format output rendering.
// License: MIT

package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/sovking/securecrt-decoder/pkg/parser"
	"github.com/sovking/securecrt-decoder/pkg/scanner"
)

// Build information injected via GoReleaser ldflags.
var (
	version = "1.0.1"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var (
		flagPath       string
		flagPassphrase string
		flagFormat     string
		flagShowEmpty  bool
		flagVersion    bool
	)

	flag.StringVar(&flagPath, "path", "", "Path to a specific .ini session file or a SecureCRT Sessions folder")
	flag.StringVar(&flagPassphrase, "passphrase", "", "Configuration master passphrase (for protected v2 sessions)")
	flag.StringVar(&flagPassphrase, "p", "", "Configuration master passphrase (shorthand)")
	flag.StringVar(&flagFormat, "format", "table", "Output format: table, json, or csv")
	flag.StringVar(&flagFormat, "f", "table", "Output format (shorthand): table, json, or csv")
	flag.BoolVar(&flagShowEmpty, "show-empty", false, "Include sessions with no saved passwords or SSH keys")
	flag.BoolVar(&flagVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&flagVersion, "v", false, "Print version information (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SecureCRT Password Decoder %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  securecrt-decoder [flags] [path]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  securecrt-decoder /path/to/Sessions\n")
		fmt.Fprintf(os.Stderr, "  securecrt-decoder -f json -p MyPassphrase /path/to/Sessions\n")
		fmt.Fprintf(os.Stderr, "  securecrt-decoder /path/to/SingleSession.ini\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flagVersion {
		fmt.Printf("securecrt-decoder version %s (commit: %s, built at: %s)\n", version, commit, date)
		return
	}

	targetPath := flagPath
	if targetPath == "" && flag.NArg() > 0 {
		targetPath = flag.Arg(0)
	}

	if targetPath == "" {
		detected := detectDefaultSessionsDir()
		if detected != "" {
			fmt.Fprintf(os.Stderr, "Auto-detected SecureCRT Sessions directory: %s\n\n", detected)
			targetPath = detected
		} else {
			fmt.Fprintf(os.Stderr, "Error: no session file or directory specified.\n\n")
			flag.Usage()
			os.Exit(1)
		}
	}

	scn := scanner.New(flagPassphrase)
	sessions, err := scn.Scan(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Filter empty credentials if requested
	if !flagShowEmpty {
		filtered := make([]parser.Session, 0, len(sessions))
		for _, s := range sessions {
			if s.Password != "" || s.SSHKeyPath != "" || s.DecryptionError != "" {
				filtered = append(filtered, s)
			}
		}
		sessions = filtered
	}

	// Output results in the requested format
	switch strings.ToLower(flagFormat) {
	case "json":
		renderJSON(sessions)
	case "csv":
		renderCSV(sessions)
	case "table":
		renderTable(sessions, scn.Warnings)
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported output format %q. Supported formats: table, json, csv\n", flagFormat)
		os.Exit(1)
	}
}

func renderTable(sessions []parser.Session, warnings []string) {
	if len(sessions) == 0 {
		fmt.Println("No sessions found with credentials.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SESSION\tPROTOCOL\tHOST\tPORT\tUSERNAME\tPASSWORD / SSH KEY\tVERSION")
	fmt.Fprintln(w, "-------\t--------\t----\t----\t--------\t------------------\t-------")

	for _, s := range sessions {
		credential := s.Password
		if credential == "" && s.SSHKeyPath != "" {
			credential = fmt.Sprintf("[KEY] %s", s.SSHKeyPath)
		} else if s.DecryptionError != "" {
			credential = s.DecryptionError
		}

		ver := s.PasswordVersion
		if ver == "" && s.SSHKeyPath != "" {
			ver = "SSH Key"
		}

		portStr := ""
		if s.Port > 0 {
			portStr = strconv.Itoa(s.Port)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.Name,
			s.Protocol,
			s.Hostname,
			portStr,
			s.Username,
			credential,
			ver,
		)
	}
	w.Flush()

	fmt.Printf("\nTotal sessions found: %d\n", len(sessions))

	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "\nWarnings encountered (%d):\n", len(warnings))
		for _, warn := range warnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", warn)
		}
	}
}

func renderJSON(sessions []parser.Session) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sessions); err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing JSON output: %v\n", err)
	}
}

func renderCSV(sessions []parser.Session) {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	header := []string{
		"Session",
		"Protocol",
		"Hostname",
		"Port",
		"Username",
		"Password",
		"PasswordVersion",
		"SSHKeyPath",
		"Status",
		"SourceFile",
	}
	w.Write(header)

	for _, s := range sessions {
		portStr := ""
		if s.Port > 0 {
			portStr = strconv.Itoa(s.Port)
		}
		status := "OK"
		if s.DecryptionError != "" {
			status = s.DecryptionError
		}

		w.Write([]string{
			s.Name,
			s.Protocol,
			s.Hostname,
			portStr,
			s.Username,
			s.Password,
			s.PasswordVersion,
			s.SSHKeyPath,
			status,
			s.SourceFile,
		})
	}
}

// detectDefaultSessionsDir looks for default SecureCRT configuration folders on the host system.
func detectDefaultSessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	var candidates []string
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			candidates = append(candidates, filepath.Join(appData, "VanDyke", "Config", "Sessions"))
		}
	case "darwin":
		candidates = append(candidates, filepath.Join(home, "Library", "Application Support", "VanDyke", "SecureCRT", "Config", "Sessions"))
	default: // Linux / BSD
		candidates = append(candidates,
			filepath.Join(home, ".vandyke", "SecureCRT", "Config", "Sessions"),
			filepath.Join(home, ".config", "VanDyke", "SecureCRT", "Sessions"),
		)
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}
