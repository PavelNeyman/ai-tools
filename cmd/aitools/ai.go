package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ================= context: LLM-friendly repo digest =================

func contextCmd(dir string, asJSON bool, budget int) {
	if dir == "" {
		dir = "."
	}
	if budget <= 0 {
		budget = 12000
	}
	abs, _ := filepath.Abs(dir)
	name := filepath.Base(abs)
	pats := loadGitignore(abs)

	skipDirs := map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "binaries": true, ".aitools": true, "__pycache__": true}
	extLang := map[string]string{".go": "Go", ".rs": "Rust", ".swift": "Swift", ".sh": "Shell", ".bash": "Shell", ".py": "Python", ".js": "JavaScript", ".ts": "JavaScript", ".jsx": "JavaScript", ".tsx": "JavaScript", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++"}

	langCount := map[string]int{}
	fileCount := 0
	totalLines := 0
	var tree []string
	sigs := map[string][]string{}
	manifests := map[string]string{}
	readme := ""

	filepath.Walk(abs, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(abs, p)
		if rel != "." && isIgnored(rel, pats) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] && rel != "." {
				return filepath.SkipDir
			}
			depth := strings.Count(rel, string(os.PathSeparator))
			if rel != "." && depth <= 1 {
				tree = append(tree, rel+"/")
			}
			return nil
		}
		fileCount++
		ext := filepath.Ext(p)
		if l, ok := extLang[ext]; ok {
			langCount[l]++
		}
		depth := strings.Count(rel, string(os.PathSeparator))
		if depth <= 1 {
			tree = append(tree, rel)
		}
		base := strings.ToLower(info.Name())
		if base == "readme.md" && readme == "" {
			b, _ := os.ReadFile(p)
			readme = truncStr(string(b), 1500)
		}
		if base == "go.mod" || base == "cargo.toml" || base == "package.json" || base == "pyproject.toml" || base == "package.swift" {
			b, _ := os.ReadFile(p)
			manifests[info.Name()] = truncStr(string(b), 800)
		}
		if l, ok := extLang[ext]; ok && info.Size() < 200*1024 && len(sigs[l]) < 200 {
			b, err := os.ReadFile(p)
			if err == nil {
				totalLines += bytes.Count(b, []byte("\n"))
				for _, line := range strings.Split(string(b), "\n") {
					t := strings.TrimSpace(line)
					if isSig(l, t) {
						sigs[l] = append(sigs[l], truncStr(t, 100))
					}
				}
			}
		}
		return nil
	})

	var md strings.Builder
	fmt.Fprintf(&md, "# Repo context: %s\n\n", name)
	fmt.Fprintf(&md, "Files: %d, Lines: %d, ~tokens: %d\n", fileCount, totalLines, totalLines*3)
	fmt.Fprintf(&md, "Languages: %s\n\n", joinCounts(langCount))
	md.WriteString("## Tree (depth 2)\n")
	for _, t := range tree[:minInt(len(tree), 80)] {
		md.WriteString("- " + t + "\n")
	}
	if readme != "" {
		md.WriteString("\n## README\n" + readme + "\n")
	}
	if len(manifests) > 0 {
		md.WriteString("\n## Manifests\n")
		for k, v := range manifests {
			md.WriteString("### " + k + "\n" + v + "\n")
		}
	}
	md.WriteString("\n## Signatures\n")
	for l, s := range sigs {
		md.WriteString("### " + l + "\n")
		for _, x := range s[:minInt(len(s), 60)] {
			md.WriteString("- " + x + "\n")
		}
	}
	out := truncStr(md.String(), budget)

	if asJSON {
		b, _ := json.MarshalIndent(map[string]interface{}{
			"name": name, "files": fileCount, "lines": totalLines, "estTokens": totalLines * 3,
			"languages": langCount, "tree": tree, "signatures": sigs,
			"manifests": manifests, "readme": readme,
		}, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println(out)
	}
}

func isSig(lang, t string) bool {
	switch lang {
	case "Go":
		return strings.HasPrefix(t, "func ") || strings.HasPrefix(t, "type ")
	case "Rust":
		return strings.HasPrefix(t, "fn ") || strings.HasPrefix(t, "pub fn ") || strings.HasPrefix(t, "struct ") || strings.HasPrefix(t, "enum ") || strings.HasPrefix(t, "trait ")
	case "Python":
		return strings.HasPrefix(t, "def ") || strings.HasPrefix(t, "class ")
	case "Swift":
		return strings.HasPrefix(t, "func ") || strings.HasPrefix(t, "class ") || strings.HasPrefix(t, "struct ") || strings.HasPrefix(t, "protocol ")
	case "Shell":
		return strings.HasSuffix(t, "() {") || strings.HasPrefix(t, "function ")
	case "JavaScript":
		return strings.HasPrefix(t, "function ") || strings.HasPrefix(t, "export ") || strings.HasPrefix(t, "class ")
	}
	return false
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated]"
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func joinCounts(m map[string]int) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s(%d)", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// ================= mcp: Model Context Protocol server (stdio) =================

func rpcResult(id interface{}, result interface{}) map[string]interface{} {
	return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result}
}
func rpcError(id interface{}, code int, msg string) map[string]interface{} {
	return map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": code, "message": msg}}
}

func mcpTools() []map[string]interface{} {
	str := func() map[string]interface{} { return map[string]interface{}{"type": "string"} }
	obj := func(props map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"type": "object", "properties": props}
	}
	return []map[string]interface{}{
		{"name": "review", "description": "Run full multi-language code review, returns report", "inputSchema": obj(map[string]interface{}{"path": str()})},
		{"name": "context", "description": "LLM-friendly repo digest (tree, signatures, manifests)", "inputSchema": obj(map[string]interface{}{"path": str(), "json": map[string]interface{}{"type": "boolean"}})},
		{"name": "triage", "description": "Prioritized summary of a review report", "inputSchema": obj(map[string]interface{}{"path": str()})},
		{"name": "exec", "description": "Execute a shell command", "inputSchema": obj(map[string]interface{}{"command": str()})},
		{"name": "read", "description": "Read a file", "inputSchema": obj(map[string]interface{}{"path": str()})},
		{"name": "write", "description": "Write a file", "inputSchema": obj(map[string]interface{}{"path": str(), "content": str()})},
		{"name": "find", "description": "Find files by pattern", "inputSchema": obj(map[string]interface{}{"pattern": str(), "path": str()})},
		{"name": "tree", "description": "Directory tree", "inputSchema": obj(map[string]interface{}{"path": str()})},
		{"name": "tools_status", "description": "Installed tools status", "inputSchema": obj(map[string]interface{}{})},
		{"name": "version", "description": "ai-tools version", "inputSchema": obj(map[string]interface{}{})},
	}
}

func mcpCall(self, name string, args map[string]interface{}) string {
	get := func(k string) string {
		if v, ok := args[k].(string); ok {
			return v
		}
		return ""
	}
	var a []string
	switch name {
	case "review":
		a = []string{"review"}
		if get("path") != "" {
			a = append(a, get("path"))
		}
	case "context":
		a = []string{"context"}
		if get("path") != "" {
			a = append(a, get("path"))
		}
		if b, ok := args["json"].(bool); ok && b {
			a = append(a, "--json")
		}
	case "triage":
		a = []string{"triage"}
		if get("path") != "" {
			a = append(a, get("path"))
		}
	case "exec":
		a = []string{"exec", "sh", "-c", get("command")}
	case "read":
		a = []string{"read", get("path")}
	case "write":
		a = []string{"write", get("path"), get("content")}
	case "find":
		a = []string{"find", get("pattern"), get("path")}
	case "tree":
		a = []string{"tree", get("path")}
	case "tools_status":
		a = []string{"tools", "status"}
	case "version":
		a = []string{"version"}
	default:
		return "unknown tool: " + name
	}
	cmd := exec.Command(self, a...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out) + "\n[error] " + err.Error()
	}
	return string(out)
}

func mcpCmd() {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	in := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var req struct {
			ID     interface{}            `json:"id"`
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if json.Unmarshal(line, &req) != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			enc.Encode(rpcResult(req.ID, map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "ai-tools", "version": Version},
			}))
		case "notifications/initialized", "notifications/cancelled":
		case "ping":
			enc.Encode(rpcResult(req.ID, map[string]interface{}{}))
		case "tools/list":
			enc.Encode(rpcResult(req.ID, map[string]interface{}{"tools": mcpTools()}))
		case "tools/call":
			name, _ := req.Params["name"].(string)
			args, _ := req.Params["arguments"].(map[string]interface{})
			text := mcpCall(self, name, args)
			enc.Encode(rpcResult(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{{"type": "text", "text": text}},
			}))
		default:
			if req.ID != nil {
				enc.Encode(rpcError(req.ID, -32601, "method not found"))
			}
		}
	}
}

// ================= triage: prioritized report summary =================

func triageCmd(reportPath string, asJSON bool) {
	if reportPath == "" {
		reportPath = "aitools-report.json"
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Println("No report found. Run `aitools review` first.")
		return
	}
	var report map[string][]map[string]interface{}
	if json.Unmarshal(data, &report) != nil {
		fmt.Println("Cannot parse report.")
		return
	}
	type item struct {
		Lang, Tool, Status string
		Count              int
		High               bool
	}
	var items []item
	for lang, results := range report {
		for _, r := range results {
			tool, _ := r["tool"].(string)
			status, _ := r["status"].(string)
			out, _ := r["output"].(string)
			count := 0
			for _, l := range strings.Split(out, "\n") {
				if strings.TrimSpace(l) != "" {
					count++
				}
			}
			high := strings.Contains(out, "CRITICAL") || strings.Contains(out, "HIGH")
			items = append(items, item{lang, tool, status, count, high})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].High != items[j].High {
			return items[i].High
		}
		return items[i].Count > items[j].Count
	})

	var md strings.Builder
	md.WriteString("# AI Tools Triage\n\n")
	md.WriteString("Prioritized findings (high-severity first, then volume):\n\n")
	md.WriteString("| Lang | Tool | Findings | High | Status |\n|---|---|---|---|---|\n")
	for _, it := range items {
		h := " "
		if it.High {
			h = "!"
		}
		fmt.Fprintf(&md, "| %s | %s | %d | %s | %s |\n", it.Lang, it.Tool, it.Count, h, it.Status)
	}
	md.WriteString("\nRecommendation: fix high-severity items first, then highest-volume tools.\n")

	if asJSON {
		b, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println(md.String())
	}
}
