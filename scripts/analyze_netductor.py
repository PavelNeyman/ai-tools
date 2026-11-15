#!/usr/bin/env python3
import urllib.request, json, os, subprocess, time

REPO_TOOLS = "PavelNeyman/qwen-tools"
REPO_TARGET = "PavelNeyman/netductor"
TAG = "v1.6.2"

def download_tools():
    print("=== Downloading tools ===")
    url = "https://api.github.com/repos/" + REPO_TOOLS + "/releases/tags/" + TAG
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        release = json.loads(r.read().decode())
    for asset in release["assets"]:
        name = asset["name"].replace("-linux-amd64", "")
        path = "/tmp/" + name
        if not os.path.exists(path):
            print("Downloading " + name + "...")
            req = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                with open(path, "wb") as f:
                    f.write(r.read())
            os.chmod(path, 0o755)
            time.sleep(2)

def analyze():
    print("\n=== Cloning target ===")
    if not os.path.exists("/tmp/netductor"):
        subprocess.run(["git", "clone", "--depth", "1",
                       "https://github.com/" + REPO_TARGET + ".git", "/tmp/netductor"], check=True)
    os.chdir("/tmp/netductor")
    print("\n=== Downloading dependencies ===")
    subprocess.run(["go", "mod", "download"], check=True)
    print("\n=== Running analysis ===")
    tools = [
        ("staticcheck", ["-f", "json", "./..."], "staticcheck.json"),
        ("gosec", ["-fmt", "json", "-quiet", "./..."], "gosec.json"),
        ("errcheck", ["./..."], "errcheck.txt"),
        ("govulncheck", ["-json", "./..."], "govulncheck.json"),
    ]
    for tool, args, output in tools:
        print("Running " + tool + "...")
        r = subprocess.run(["/tmp/" + tool] + args, capture_output=True, text=True, timeout=120)
        with open("/tmp/" + output, "w") as f:
            f.write(r.stdout)
        print("  Saved: /tmp/" + output)
    print("\n=== Analysis complete! ===")

if __name__ == "__main__":
    download_tools()
    analyze()
