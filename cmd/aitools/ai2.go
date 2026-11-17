package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// ---- LLM backend: llm / aichat / OpenAI-compatible HTTP ----
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
	resp, err := http.DefaultClient.Do(req)
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

// ---- aireview: LLM review of findings + optional diff ----
func aiReviewCmd(reportPath, diffRef string) {
	if reportPath == "" {
		reportPath = "aitools-report.json"
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Println("No report. Run `aitools review` first.")
		return
	}
	var report map[string][]map[string]interface{}
	json.Unmarshal(data, &report)
	var findings strings.Builder
	for lang, results := range report {
		for _, r := range results {
			tool, _ := r["tool"].(string)
			out, _ := r["output"].(string)
			if strings.TrimSpace(out) == "" {
				continue
			}
			fmt.Fprintf(&findings, "[%s/%s]\n%s\n", lang, tool, truncStr(out, 1500))
		}
	}
	diff := ""
	if diffRef != "" {
		diff = getDiff(".", diffRef)
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

// ---- sarif: standard static-analysis output ----
func sarifCmd(reportPath string) {
	if reportPath == "" {
		reportPath = "aitools-report.json"
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Println("No report. Run `aitools review` first.")
		return
	}
	var report map[string][]map[string]interface{}
	json.Unmarshal(data, &report)
	var results []map[string]interface{}
	for _, rs := range report {
		for _, r := range rs {
			tool, _ := r["tool"].(string)
			out, _ := r["output"].(string)
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				level := "warning"
				if strings.Contains(line, "HIGH") || strings.Contains(line, "CRITICAL") || strings.Contains(line, "error") {
					level = "error"
				}
				results = append(results, map[string]interface{}{
					"ruleId":  tool,
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

// ---- gitignore support for context ----
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
