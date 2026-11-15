# Qwen Tools — инструкция для ИИ-агента

Бинарник `qwen` + 11 анализаторов Go. Хранятся в **GitHub Release Assets**, не в git.
Релиз: v1.6.2. Последний: `GET /repos/PavelNeyman/qwen-tools/releases/latest`.

## 0. Ограничения песочницы

- Контейнер пересоздаётся, /tmp очищается — нужен bootstrap каждый раз.
- Вызов code_interpreter убивается через ~20 с — долгую работу запускать в фоне
  (subprocess.Popen(..., start_new_session=True)) и опрашивать лог.
- curl/wget часто ловят таймаут — качать через **Python urllib.request**.
- CDN релизов иногда режется — ретраи. api.github.com и codeload.github.com стабильнее.

## 1. Bootstrap (в /tmp/dl.py, запуск в фоне)

```python
import urllib.request, json, os, time, tarfile, io
LOG=open('/tmp/dl.log','a',buffering=1)
def fetch(u,t=90):
    r=urllib.request.Request(u,headers={'User-Agent':'Mozilla/5.0'})
    return urllib.request.urlopen(r,timeout=t).read()
rel=json.loads(fetch('https://api.github.com/repos/PavelNeyman/qwen-tools/releases/latest',20))
for a in rel['assets']:
    n=a['name'].replace('-linux-amd64',''); p='/tmp/'+n
    if os.path.exists(p) and os.path.getsize(p)>100000: continue
    for k in range(5):
        try:
            d=fetch(a['browser_download_url']); open(p,'wb').write(d)
            os.chmod(p,0o755); LOG.write('OK '+n+chr(10)); break
        except Exception:
            LOG.write('retry '+n+chr(10)); time.sleep(3)
LOG.write('TOOLS_DONE'+chr(10))
if not os.path.exists('/tmp/go/bin/go'):
    d=fetch('https://dl.google.com/go/go1.22.5.linux-amd64.tar.gz',180)
    tarfile.open(fileobj=io.BytesIO(d)).extractall('/tmp'); LOG.write('GO_DONE'+chr(10))
```

Запуск: subprocess.Popen(['nohup','python3','/tmp/dl.py'], stdout=open('/tmp/dl.out','w'),
stderr=subprocess.STDOUT, start_new_session=True). Опрос: open('/tmp/dl.log').read().
Повтор безопасен — уже скачанное пропускается.

Окружение Go:

```bash
export GOROOT=/tmp/go PATH=/tmp/go/bin:$PATH GOPATH=/tmp/gopath
export GOCACHE=/dev/shm/go-cache GOMODCACHE=/tmp/gopath/pkg/mod
export GOFLAGS=-mod=mod GOPROXY=https://goproxy.io,direct GOSUMDB=off
```

## 2. Команды qwen

```
qwen exec <cmd> [args...]     выполнить процесс
qwen read <path>              прочитать файл (в т.ч. /proc/*)
qwen write <path> <content>   записать файл
qwen find <pattern> <dir>     поиск по подстроке в пути
qwen tree <dir> [depth]       дерево, depth=3 по умолчанию
qwen http <METHOD> <url>      HTTP: статус + тело
qwen encrypt <file> <key>     -> file.enc  AES-256-GCM + base64
qwen decrypt <file.enc> <key> -> file      проверка GCM-тега
qwen tools list|status|fetch  управление анализаторами
qwen tools sync <file> <key>  зашифровать + залить на sendit.sh
```

Формат шифра: base64(nonce[12] || ciphertext || tag[16]). Ключ паддится нулями до 32 байт —
использовать случайную строку 32+ символа.

## 3. Анализаторы (лежат в /tmp/<имя>)

| Бинарник | Запуск | Ищет |
|---|---|---|
| staticcheck | -f json ./... | баги, упрощения, deprecated |
| gosec | -fmt json -quiet ./... | инъекции, TLS, права, секреты |
| errcheck | ./... | проигнорированные error |
| govulncheck | -json ./... | CVE в зависимостях |
| golangci-lint | run --timeout 5m | агрегатор линтеров |
| revive | ./... | стиль, именование |
| deadcode | ./... | недостижимый код |
| ineffassign | ./... | присваивания без эффекта |
| unconvert | ./... | лишние приведения типов |
| bodyclose | ./... | незакрытые http Response.Body |
| goimports | -l -w . | порядок импортов |

## 4. Прогон проекта (фон + опрос)

```python
import subprocess, os
os.makedirs('/tmp/out', exist_ok=True)
env=dict(os.environ, GOROOT='/tmp/go', PATH='/tmp/go/bin:'+os.environ['PATH'],
         GOPATH='/tmp/gopath', GOCACHE='/dev/shm/go-cache',
         GOMODCACHE='/tmp/gopath/pkg/mod', GOFLAGS='-mod=mod',
         GOPROXY='https://goproxy.io,direct', GOSUMDB='off')
script='''
cd /tmp/netductor-src
go mod download 2>/tmp/out/mod.log
/tmp/staticcheck -f json ./... >/tmp/out/staticcheck.json 2>/tmp/out/staticcheck.err
/tmp/gosec -fmt json -quiet ./... >/tmp/out/gosec.json 2>/tmp/out/gosec.err
/tmp/errcheck ./... >/tmp/out/errcheck.txt 2>&1
/tmp/govulncheck -json ./... >/tmp/out/govulncheck.json 2>/tmp/out/govulncheck.err
echo DONE > /tmp/out/status
'''
open('/tmp/run.sh','w').write(script)
subprocess.Popen(['nohup','bash','/tmp/run.sh'], stdout=open('/tmp/out/run.log','w'),
                 stderr=subprocess.STDOUT, env=env, start_new_session=True)
```

Исходники: https://codeload.github.com/OWNER/REPO/tar.gz/refs/heads/main -> распаковать в /tmp.

## 5. Безопасность результатов

- gosec/govulncheck — карта уязвимостей проекта, чувствительно.
- sendit.sh: доступ по непредсказуемой ссылке, без индексации, но публично по URL.
  Только бинарники и открытые данные.
- Чувствительное: qwen encrypt перед выгрузкой, либо в чат, либо приватный репо. Ключ — вне репо.

## 6. CI/CD

release.yml, триггер тег v*: сборка qwen (linux/amd64) -> 11 анализаторов -> UPX ->
sendit.sh (continue-on-error) -> softprops/action-gh-release прикрепляет ассеты.
Бинарники в git не коммитятся. Новый релиз: тег vX.Y.Z.
