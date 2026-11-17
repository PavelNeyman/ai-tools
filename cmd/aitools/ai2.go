package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---- flag helpers ----
func hasFlag(name string) bool {
	for _, a := range os.Args[2:] {
		if a == name {
			return true
		}
	}
	return false
}
func flagValue(name string) string {
	for _, a := range os.Args[2:] {
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"=")
		}
	}
	return ""
}

// ---- LLM backend: llm / aichat / OpenAI-compatible HTTP (with timeout) ----
var llmClient = &http.Client{Timeout: 60 * time.Second}

func llmComplete(prompt string) (string, error) {
	if p, err := exec.LookPath("llm"); err == nil {
		out, err := exec.Command(p, prompt).CombinedOutput()
		return string(out), err
	}
	if p, err := exec.LookPath("aichat"); err == nil {
		out, err := exec.Command(p, prompt).CombinedOutput()
		return string(out), err
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return "", fmt.Errorf("no LLM backend: install llm/aichat or set OPENAI_API_KEY")
	}
	base := os.Getenv("OPENAI_BASE_URL")
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	body, _ := json.Marshal(map[string]interface{}{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	req, _ := http.NewRequest("POST", base+"/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := llmClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var r struct {
		Choices []struct {
			Message struct{ Content string }
		}
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if len(r.Choices) > 0 {
		return r.Choices[0].Message.Content, nil
	}
	return "", fmt.Errorf("empty LLM response")
}

// getDiff - git diff для ревью изменений
func getDiff(dir, ref string) string {
	if ref == "" {
		ref = "HEAD~1"
	}
	out, err := exec.Command("git", "-C", dir, "diff", ref).CombinedOutput()
	if err != nil {
		out, _ = exec.Command("git", "-C", dir, "diff", ref+"...HEAD").CombinedOutput()
	}
	return string(out)
}

// readReport читает aitools-report.json в реальную структуру:
// {
//   "path": "...", "languages": [...], "timestamp": "...",
//   "Go": {"gosec": {...}, "staticcheck": {...}},
//   "Rust": {...}
// }
func readReport(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return report, nil
}

// aiReviewCmd: LLM-ревью findings + опц. diff
func aiReviewCmd(reportPath, diffRef, repoDir string) {
	if reportPath == "" {
		reportPath = "aitools-report.json"
	}
	report, err := readReport(reportPath)
	if err != nil {
		fmt.Println("Cannot read report:", err)
		fmt.Println("Run `aitools review` first.")
		return
	}
	var findings strings.Builder
	langs, _ := report["languages"].([]interface{})
	for _, langI := range langs {
		lang, _ := langI.(string)
		langReport, _ := report[lang].(map[string]interface{})
		for tool, result := range langReport {
			r, ok := result.(map[string]interface{})
			if !ok {
				continue
			}
			outRaw, _ := r["output"].(string)
			if strings.TrimSpace(outRaw) == "" {
				continue
			}
			fmt.Fprintf(&findings, "[%s/%s]\n%s\n", lang, tool, truncStr(outRaw, 1500))
		}
	}
	diff := ""
	if diffRef != "" {
		if repoDir == "" {
			repoDir = "."
		}
		diff = getDiff(repoDir, diffRef)
	}
	prompt := "You are a senior code reviewer. Below are static-analysis findings" +
		" and optionally a git diff. Produce a concise prioritized review: top critical issues, root causes, and concrete fix suggestions. Be specific.\n\nFINDINGS:\n" +
		truncStr(findings.String(), 6000)
	if diff != "" {
		prompt += "\n\nDIFF:\n" + truncStr(diff, 6000)
	}
	resp, err := llmComplete(prompt)
	if err != nil {
		fmt.Println("LLM unavailable:", err)
		fmt.Println("Falling back to heuristic triage: run `aitools triage`.")
		return
	}
	os.WriteFile("ai-review.md", []byte(resp), 0644)
	fmt.Println(resp)
	fmt.Println("\n[saved ai-review.md]")
}

// sarifCmd: SARIF 2.1.0 вывод
func sarifCmd(reportPath string) {
	if reportPath == "" {
		reportPath = "aitools-report.json"
	}
	report, err := readReport(reportPath)
	if err != nil {
		fmt.Println("Cannot read report:", err)
		fmt.Println("Run `aitools review` first.")
		return
	}
	var results []map[string]interface{}
	langs, _ := report["languages"].([]interface{})
	for _, langI := range langs {
		lang, _ := langI.(string)
		langReport, _ := report[lang].(map[string]interface{})
		for tool, result := range langReport {
			r, ok := result.(map[string]interface{})
			if !ok {
				continue
			}
			outRaw, _ := r["output"].(string)
			for _, line := range strings.Split(outRaw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				level := "warning"
				if strings.Contains(line, "HIGH") || strings.Contains(line, "CRITICAL") || strings.Contains(line, "error") {
					level = "error"
				}
				results = append(results, map[string]interface{}{
					"ruleId":  lang + "/" + tool,
					"level":   level,
					"message": map[string]string{"text": truncStr(line, 500)},
				})
			}
		}
	}
	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{"name": "ai-tools", "version": Version, "rules": []interface{}{}},
			},
			"results": results,
		}},
	}
	b, _ := json.MarshalIndent(sarif, "", "  ")
	os.WriteFile("aitools-report.sarif.json", b, 0644)
	fmt.Printf("✓ SARIF written: aitools-report.sarif.json (%d results)\n", len(results))
}

// triageCmd: приоритизация findings
func triageCmd(reportPath string, asJSON bool) {
	if reportPath == "" {
		reportPath = "aitools-report.json"
	}
	report, err := readReport(reportPath)
	if err != nil {
		fmt.Println("Cannot read report:", err)
		fmt.Println("Run `aitools review` first.")
		return
	}
	type item struct {
		Lang, Tool, Status string
		Count              int
		High               bool
	}
	var items []item
	langs, _ := report["languages"].([]interface{})
	for _, langI := range langs {
		lang, _ := langI.(string)
		langReport, _ := report[lang].(map[string]interface{})
		for tool, result := range langReport {
			r, ok := result.(map[string]interface{})
			if !ok {
				continue
			}
			outRaw, _ := r["output"].(string)
			status := "ok"
			if s, ok := r["status"].(string); ok {
				status = s
			}
			count := 0
			for _, l := range strings.Split(outRaw, "\n") {
				if strings.TrimSpace(l) != "" {
					count++
				}
			}
			high := strings.Contains(outRaw, "CRITICAL") || strings.Contains(outRaw, "HIGH")
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

// loadGitignore / isIgnored - для context (gitignore-aware)
func loadGitignore(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return nil
	}
	var pats []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		pats = append(pats, strings.TrimSuffix(l, "/"))
	}
	return pats
}
func isIgnored(rel string, pats []string) bool {
	base := filepath.Base(rel)
	for _, p := range pats {
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}
