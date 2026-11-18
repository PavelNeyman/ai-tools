package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var Version = "dev"


var toolRegistry = map[string][]string{
	"Go": {"staticcheck","gosec","errcheck","govulncheck","golangci-lint","gofumpt","revive",
		"goimports","bodyclose","unconvert","ineffassign","deadcode","nilaway","gocritic",
		"osv-scanner","trivy","betterleaks","trufflehog","bearer","ruff","nuclei","difft"},
	"Rust": {"cargo-audit","cargo-deny","trivy","osv-scanner","semgrep","difft"},
	"Swift": {"swiftlint","trivy","osv-scanner","semgrep"},
	"Shell": {"shellcheck","semgrep"},
	"Docker": {"hadolint","trivy"},
	"Python": {"ruff","semgrep","trivy","osv-scanner","bandit","difft"},
	"JavaScript": {"semgrep","trivy","osv-scanner","eslint","difft"},
	"C": {"cppcheck","semgrep"},
	"C++": {"cppcheck","semgrep"},
}

// getAssetURL fetches download URL for a tool from the latest ai-tools release.
func getAssetURL(toolName string) (string, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/PavelNeyman/ai-tools/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return "", fmt.Errorf("github releases: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(snippet))
	}
	var rel struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}
	want := toolName + "-linux-amd64"
	for _, a := range rel.Assets {
		if a.Name == want {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("asset not found: %s", want)
}

type Language struct {
	Name    string
	Markers []string
}

var languages = []Language{
	{"Go", []string{"go.mod", "*.go"}},
	{"Rust", []string{"Cargo.toml", "*.rs"}},
	{"Swift", []string{"Package.swift", "*.swift"}},
	{"Shell", []string{"*.sh", "*.bash"}},
	{"Docker", []string{"Dockerfile", "docker-compose.yml"}},
	{"Python", []string{"requirements.txt", "pyproject.toml", "setup.py", "*.py"}},
	{"JavaScript", []string{"package.json", "*.js", "*.ts", "*.jsx", "*.tsx"}},
	{"C", []string{"*.c", "*.h", "Makefile", "CMakeLists.txt"}},
	{"C++", []string{"*.cpp", "*.cc", "*.cxx", "*.hpp", "*.hxx", "CMakeLists.txt"}},
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "help", "--help", "-h":
		printUsage()
	case "version", "--version", "-v":
		fmt.Printf("aitools %s\n", Version)
	case "exec":
		execCmd()
	case "read":
		readCmd()
	case "write":
		writeCmd()
	case "find":
		findCmd()
	case "tree":
		treeCmd()
	case "http":
		httpCmd()
	case "encrypt":
		encryptCmd()
	case "decrypt":
		decryptCmd()
	case "tools":
		if len(os.Args) < 3 {
			fmt.Println("Usage: aitools tools <list|fetch|status|sync>")
			os.Exit(1)
		}
		subcmd := os.Args[2]
		switch subcmd {
		case "list":
			toolsList()
		case "fetch":
			toolsFetch()
		case "status":
			toolsStatus()
		case "sync":
			toolsSync()
		default:
			fmt.Printf("Unknown tools subcommand: %s\n", subcmd)
			os.Exit(1)
		}
	case "review":
		doAI := hasFlag("--ai")
		doSarif := hasFlag("--sarif")
		diffRef := flagValue("--diff")
		var clean []string
		clean = append(clean, os.Args[:2]...)
		for _, a := range os.Args[2:] {
			if !strings.HasPrefix(a, "--") {
				clean = append(clean, a)
			}
		}
		os.Args = clean
		reviewCmd()
		if doSarif {
			sarifCmd("aitools-report.json")
		}
		if doAI || diffRef != "" {
			repoDir := "."
		for _, a := range os.Args[2:] {
			if !strings.HasPrefix(a, "--") && a != "--ai" && a != "--sarif" {
				repoDir = a
				break
			}
		}
		aiReviewCmd("aitools-report.json", diffRef, repoDir)
		}
	case "sarif":
		p := ""
		if len(os.Args) > 2 {
			p = os.Args[2]
		}
		sarifCmd(p)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`aitools - universal code review and security analysis toolkit

Usage:
  aitools <command> [arguments]

Commands:
  tools list              List available tools by language
  tools fetch             Download tools for detected languages
  tools status            Check installed tools
  tools sync <file>       Upload file to sendit.sh with encryption
  review [path]           Run full analysis on repository (default: current dir)
                          [--ai] LLM review  [--diff=REF] review changes  [--sarif] SARIF output
  sarif [report]          Convert report to SARIF 2.1.0
  exec <cmd> [args]       Execute command (sandbox bypass)
  read <file>             Read file contents
  write <file> <content>  Write content to file
  find <pattern> <path>   Find files matching pattern
  tree <path>             Show directory tree
  http <url>              Make HTTP request
  encrypt <file>          Encrypt file with AES-256-GCM
  decrypt <file>          Decrypt file
  version                 Show version
  help                    Show this help

Languages supported:
  Go, Rust, Swift, Shell, Docker, Python, JavaScript, C, C++

Examples:
  aitools tools fetch
  aitools review /path/to/repo
  aitools encrypt secret.json
  aitools exec staticcheck ./...`)
}

func detectLanguages(path string) []string {
	detected := make(map[string]bool)
	
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		
		rel, _ := filepath.Rel(path, p)
		
		for _, lang := range languages {
			for _, marker := range lang.Markers {
				if strings.Contains(marker, "*") {
					if matched, _ := filepath.Match(marker, filepath.Base(rel)); matched {
						detected[lang.Name] = true
					}
				} else if filepath.Base(rel) == marker {
					detected[lang.Name] = true
				}
			}
		}
		return nil
	})
	
	result := make([]string, 0, len(detected))
	for lang := range detected {
		result = append(result, lang)
	}
	sort.Strings(result)
	return result
}

func toolsList() {
	langs := detectLanguages(".")
	if len(langs) == 0 {
		fmt.Println("No languages detected in current directory")
		return
	}
	
	fmt.Printf("Detected languages: %s\n\n", strings.Join(langs, ", "))
	
	for _, lang := range langs {
		tools := toolRegistry[lang]
		fmt.Printf("%s (%d tools):\n", lang, len(tools))
		for _, tool := range tools {
			fmt.Printf("  - %s\n", tool)
		}
		fmt.Println()
	}
}

func toolsFetch() {
	langs := detectLanguages(".")
	if len(langs) == 0 {
		fmt.Println("No languages detected in current directory")
		return
	}

	fmt.Printf("Detected languages: %s\n\n", strings.Join(langs, ", "))

	toolsDir := filepath.Join(os.Getenv("HOME"), ".aitools", "bin")
	os.MkdirAll(toolsDir, 0755)

	client := &http.Client{Timeout: 120 * time.Second}

	needed := map[string]bool{}
	for _, lang := range langs {
		for _, t := range toolRegistry[lang] {
			needed[t] = true
		}
	}

	for tool := range needed {
		destPath := filepath.Join(toolsDir, tool)
		if _, err := os.Stat(destPath); err == nil {
			fmt.Printf("  ✓ %-15s already installed\n", tool)
			continue
		}

		url, err := getAssetURL(tool)
		if err != nil {
			fmt.Printf("  ✗ %-15s %v\n", tool, err)
			continue
		}
		fmt.Printf("  ↓ %-15s ...\n", tool)

		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("    download error: %v\n", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			fmt.Printf("    download HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(snippet)))
			continue
		}
		tmpFile, err := os.CreateTemp("", "tool-*.tmp")
		if err != nil {
			resp.Body.Close()
			fmt.Printf("    tempfile: %v\n", err)
			continue
		}
		_, copyErr := io.Copy(tmpFile, io.LimitReader(resp.Body, 512<<20))
		tmpFile.Close()
		resp.Body.Close()
		tmpPath := tmpFile.Name()
		if copyErr != nil {
			os.Remove(tmpPath)
			fmt.Printf("    download copy: %v\n", copyErr)
			continue
		}
		defer os.Remove(tmpPath)

		if err := extractArchive(tmpPath, destPath, tool); err != nil {
			fmt.Printf("    ✗ extract: %v\n", err)
			continue
		}
		os.Chmod(destPath, 0755)
		fmt.Printf("    ✓ installed\n")
	}

	fmt.Printf("\nTools installed to: %s\n", toolsDir)
	fmt.Println("Add to PATH: export PATH=\"$HOME/.aitools/bin:$PATH\"")
}


func extractArchive(archivePath, destPath, toolName string) error {
	// Detect format by content (toolsFetch temps often have no extension).
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	var magic [6]byte
	n, _ := f.Read(magic[:])
	f.Close()
	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return extractTarGz(archivePath, destPath, toolName)
	case n >= 4 && magic[0] == 'P' && magic[1] == 'K' && magic[2] == 3 && magic[3] == 4:
		return extractZip(archivePath, destPath, toolName)
	case n >= 6 && magic[0] == 0xfd && magic[1] == '7' && magic[2] == 'z' && magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0:
		return extractTarXz(archivePath, destPath, toolName)
	}
	// Plain binary (GH release assets like staticcheck-linux-amd64).
	in, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func extractTarGz(archivePath, destPath, toolName string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	
	tr := tar.NewReader(gz)
	
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		if header.Typeflag == tar.TypeReg {
			baseName := filepath.Base(header.Name)
			if baseName == toolName || strings.HasPrefix(baseName, toolName) {
				outFile, err := os.Create(destPath)
				if err != nil {
					return err
				}
				defer outFile.Close()
				
				_, err = io.Copy(outFile, tr)
				return err
			}
		}
	}
	
	return fmt.Errorf("tool binary not found in archive")
}

func extractTarXz(archivePath, destPath, toolName string) error {
	cmd := exec.Command("tar", "-xf", archivePath, "--strip-components=1", "-C", filepath.Dir(destPath))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func extractZip(archivePath, destPath, toolName string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()
	
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		
		baseName := filepath.Base(f.Name)
		if baseName == toolName || strings.HasPrefix(baseName, toolName) {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			
			outFile, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer outFile.Close()
			
			_, err = io.Copy(outFile, rc)
			return err
		}
	}
	
	return fmt.Errorf("tool binary not found in zip")
}

func toolsStatus() {
	toolsDir := filepath.Join(os.Getenv("HOME"), ".aitools", "bin")
	
	if _, err := os.Stat(toolsDir); os.IsNotExist(err) {
		fmt.Println("No tools installed. Run: aitools tools fetch")
		return
	}
	
	files, err := os.ReadDir(toolsDir)
	if err != nil {
		fmt.Printf("Error reading tools directory: %v\n", err)
		return
	}
	
	if len(files) == 0 {
		fmt.Println("No tools installed. Run: aitools tools fetch")
		return
	}
	
	fmt.Printf("Installed tools (%d):\n", len(files))
	for _, f := range files {
		info, _ := f.Info()
		fmt.Printf("  ✓ %-20s %8.1f KB\n", f.Name(), float64(info.Size())/1024)
	}
}

func toolsSync() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools tools sync <file>")
		fmt.Println("Uploads ONLY if AITOOLS_ALLOW_UPLOAD=1 and file is aitools-encrypted (.enc).")
		os.Exit(1)
	}
	if os.Getenv("AITOOLS_ALLOW_UPLOAD") != "1" {
		fmt.Println("Refusing upload: set AITOOLS_ALLOW_UPLOAD=1 to confirm intentional remote share.")
		fmt.Println("Prefer: AITOOLS_KEY=... aitools encrypt <file> then share the .enc yourself.")
		os.Exit(1)
	}
	path := os.Args[2]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	ok := strings.HasSuffix(path, ".enc") || strings.HasSuffix(path, ".encrypted")
	if !ok {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil {
			ok = len(raw) >= len(cryptoMagic) && string(raw[:len(cryptoMagic)]) == cryptoMagic
		}
	}
	if !ok {
		fmt.Println("Refusing to upload plaintext. Encrypt first:")
		fmt.Println("  export AITOOLS_KEY=...")
		fmt.Println("  aitools encrypt report.json")
		fmt.Println("  AITOOLS_ALLOW_UPLOAD=1 aitools tools sync report.json.enc")
		os.Exit(1)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("POST", "https://sendit.sh", strings.NewReader(string(data)))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error uploading: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Upload failed HTTP %d: %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}
	fmt.Printf("Uploaded: %s\n", string(body))
}

// toolArgs returns CLI args for a named analyzer. cmd.Dir is already the
// repository root; package-oriented Go tools must receive "./...", not ".".
func toolArgs(tool, absPath string) []string {
	switch tool {
	case "gosec":
		return []string{"-fmt=json", "-quiet", "./..."}
	case "staticcheck":
		return []string{"-f=json", "./..."}
	case "errcheck":
		return []string{"-ignoretests", "./..."}
	case "govulncheck":
		return []string{"./..."}
	case "deadcode":
		return []string{"-test=false", "./..."}
	case "ineffassign":
		return []string{"./..."}
	case "nilaway":
		return []string{"./..."}
	case "bodyclose", "unconvert", "gocritic":
		return []string{"./..."}
	case "golangci-lint":
		return []string{"run", "--output.json.path=stdout"}
	case "gofumpt":
		// list mode; non-zero exit if files need formatting
		return []string{"-l", "."}
	case "goimports":
		return []string{"-l", "."}
	case "revive":
		return []string{"-formatter", "json", "./..."}
	case "trivy":
		return []string{"fs", "--format=json", "--quiet", "."}
	case "osv-scanner":
		return []string{"scan", "source", "--format=json", "-r", "."}
	case "swiftlint":
		return []string{"lint", "--reporter=json"}
	case "shellcheck":
		return shellcheckArgs(absPath)
	case "hadolint":
		return []string{"-f=json", "Dockerfile"}
	case "cargo-audit":
		return []string{"audit", "--format=json"}
	case "cargo-deny":
		return []string{"check", "--format=json"}
	case "cppcheck":
		return []string{"--enable=all", "--output-file=/dev/stdout", "."}
	case "semgrep":
		return []string{"scan", "--json", "--config=p/security-audit", "--metrics=off", "."}
	case "ruff":
		return []string{"check", "--output-format=json", "."}
	case "betterleaks":
		return []string{"git", ".", "--report-format=json", "--report-path=/dev/stdout", "--no-banner"}
	case "nuclei":
		return []string{"-jsonl", "-silent", "-u", "."}
	case "bandit":
		return []string{"-r", ".", "-f", "json", "-q"}
	case "eslint":
		return []string{".", "--format=json"}
	default:
		// Prefer package pattern for unknown Go-ish tools; "." was the
		// historical default and broke module-root analysis.
		return []string{"./..."}
	}
}

func reviewCmd() {
	path := "."
	if len(os.Args) > 2 {
		path = os.Args[2]
	}
	
	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		os.Exit(1)
	}
	
	langs := detectLanguages(absPath)
	if len(langs) == 0 {
		fmt.Println("No languages detected")
		os.Exit(1)
	}
	
	fmt.Printf("Reviewing: %s\n", absPath)
	fmt.Printf("Detected languages: %s\n\n", strings.Join(langs, ", "))
	
	report := make(map[string]interface{})
	report["path"] = absPath
	report["languages"] = langs
	report["timestamp"] = time.Now().Format(time.RFC3339)
	
	for _, lang := range langs {
		tools := toolRegistry[lang]
		langReport := make(map[string]interface{})
		
		fmt.Printf("=== %s Analysis ===\n", lang)
		
		for _, tool := range tools {
			toolPath := resolveToolPath(tool)
			if toolPath == "" {
				fmt.Printf("  ! %s not installed (run: aitools tools fetch)\n", tool)
				continue
			}
			
			fmt.Printf("  → Running %s...\n", tool)

			// Go analyzers need package patterns under cmd.Dir (= absPath).
			// Passing bare "." makes deadcode/errcheck/govulncheck report
			// "no Go files in <absPath>" even when the module is valid.
			args := toolArgs(tool, absPath)

			cmd := exec.Command(toolPath, args...)
			cmd.Dir = absPath

			output, cmdErr := cmd.CombinedOutput()
			if cmdErr != nil {
				fmt.Printf("    ⚠ command failed: %v\n", cmdErr)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(output, &result); err == nil {
				if cmdErr != nil {
					result["_cmd_error"] = cmdErr.Error()
				}
				langReport[tool] = result
				fmt.Printf("    ✓ completed\n")
			} else {
				entry := map[string]interface{}{
					"raw": string(output),
				}
				if cmdErr != nil {
					entry["cmd_error"] = cmdErr.Error()
				}
				if len(output) == 0 && cmdErr != nil {
					entry["error"] = cmdErr.Error()
				}
				langReport[tool] = entry
				fmt.Printf("    ✓ completed (raw output)\n")
			}
		}
		
		report[lang] = langReport
	}
	
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	
	reportPath := filepath.Join(absPath, "aitools-report.json")
	os.WriteFile(reportPath, reportJSON, 0644)
	
	fmt.Printf("\n✓ Report saved: %s\n", reportPath)
	
	summaryPath := filepath.Join(absPath, "aitools-report.txt")
	summary := generateSummary(report)
	os.WriteFile(summaryPath, []byte(summary), 0644)
	fmt.Printf("✓ Summary saved: %s\n", summaryPath)
}

func generateSummary(report map[string]interface{}) string {
	var sb strings.Builder
	
	sb.WriteString("AITOOLS SECURITY REVIEW SUMMARY\n")
	sb.WriteString("================================\n\n")
	
	if path, ok := report["path"].(string); ok {
		sb.WriteString(fmt.Sprintf("Path: %s\n", path))
	}
	
	if langs, ok := report["languages"].([]string); ok {
		sb.WriteString(fmt.Sprintf("Languages: %s\n", strings.Join(langs, ", ")))
	}
	
	if ts, ok := report["timestamp"].(string); ok {
		sb.WriteString(fmt.Sprintf("Timestamp: %s\n", ts))
	}
	
	sb.WriteString("\n")
	
	for _, lang := range report["languages"].([]string) {
		if langReport, ok := report[lang].(map[string]interface{}); ok {
			sb.WriteString(fmt.Sprintf("== %s ==\n", lang))
			for toolName, result := range langReport {
				sb.WriteString(fmt.Sprintf("  %s: ", toolName))
				if r, ok := result.(map[string]interface{}); ok {
					if issues, ok := r["Issues"].([]interface{}); ok {
						sb.WriteString(fmt.Sprintf("%d issues found\n", len(issues)))
					} else if vulns, ok := r["Results"].([]interface{}); ok {
						sb.WriteString(fmt.Sprintf("%d results\n", len(vulns)))
					} else {
						sb.WriteString("completed\n")
					}
				} else {
					sb.WriteString("completed\n")
				}
			}
			sb.WriteString("\n")
		}
	}
	
	return sb.String()
}

func execCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools exec <cmd> [args...]")
		os.Exit(1)
	}
	
	cmdName := os.Args[2]
	args := os.Args[3:]
	
	cmd := exec.Command(cmdName, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func readCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools read <file>")
		os.Exit(1)
	}
	
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Print(string(data))
}

func writeCmd() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: aitools write <file> <content>")
		os.Exit(1)
	}
	
	err := os.WriteFile(os.Args[2], []byte(os.Args[3]), 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func findCmd() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: aitools find <pattern> <path>")
		os.Exit(1)
	}
	
	pattern := os.Args[2]
	searchPath := os.Args[3]
	
	filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			fmt.Println(path)
		}
		return nil
	})
}

func treeCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools tree <path>")
		os.Exit(1)
	}
	
	path := os.Args[2]
	
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		rel, _ := filepath.Rel(path, p)
		depth := strings.Count(rel, string(os.PathSeparator))
		indent := strings.Repeat("  ", depth)
		
		if info.IsDir() {
			fmt.Printf("%s📁 %s/\n", indent, filepath.Base(p))
		} else {
			fmt.Printf("%s📄 %s\n", indent, filepath.Base(p))
		}
		return nil
	})
}

func httpCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools http <url>")
		os.Exit(1)
	}
	
	url := os.Args[2]
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Headers:\n")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Warning: HTTP %d\n", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	fmt.Printf("\nBody (%d bytes, capped 8MiB):\n%s\n", len(body), string(body))
}

func encryptCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools encrypt <file> [passphrase]")
		fmt.Println("Passphrase: arg or env AITOOLS_KEY (required).")
		fmt.Println("Output: <file>.enc  (AES-256-GCM, base64 envelope)")
		os.Exit(1)
	}
	filePath := os.Args[2]
	pass := cryptoPassphrase()
	if pass == "" {
		fmt.Println("Error: passphrase required (arg or AITOOLS_KEY)")
		os.Exit(1)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}
	encStr, err := encryptBytes(data, pass)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		os.Exit(1)
	}
	outPath := filePath + ".enc"
	if err := os.WriteFile(outPath, []byte(encStr+"\n"), 0o600); err != nil {
		fmt.Printf("Error writing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Encrypted (AES-256-GCM): %s\n", outPath)
}

func decryptCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aitools decrypt <file.enc> [passphrase]")
		fmt.Println("Passphrase: arg or env AITOOLS_KEY (required).")
		os.Exit(1)
	}
	filePath := os.Args[2]
	pass := cryptoPassphrase()
	if pass == "" {
		fmt.Println("Error: passphrase required (arg or AITOOLS_KEY)")
		os.Exit(1)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}
	plain, err := decryptBytes(string(data), pass)
	if err != nil {
		fmt.Printf("Error decrypting: %v\n", err)
		os.Exit(1)
	}
	outPath := strings.TrimSuffix(filePath, ".enc")
	outPath = strings.TrimSuffix(outPath, ".encrypted")
	if outPath == filePath {
		outPath = filePath + ".decrypted"
	}
	if err := os.WriteFile(outPath, plain, 0o600); err != nil {
		fmt.Printf("Error writing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Decrypted: %s\n", outPath)
}
