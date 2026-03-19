import os
import sys
import json
import asyncio
import subprocess
import re
from dotenv import load_dotenv

load_dotenv()

DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")
METADATA_FILE = os.path.join(DOWNLOAD_DIR, "challenges.json")
SOLUTIONS_FILE = os.path.join(DOWNLOAD_DIR, "solutions_cli.json")

CTF_PROMPT_TEMPLATE = """
You are an elite CTF solver AI. Your goal is to systematically analyze challenges, extract hidden data, and recover flags efficiently.

## General Strategy

* Always start by identifying the input type (file, text, binary, network data, etc.)
* Extract as much information as possible using standard techniques (strings, metadata, structure, encoding)
* Assume the flag is hidden via encoding, steganography, memory exploitation, or logical checks
* Work iteratively and explain your reasoning step-by-step

## Workflow

1. Identify file/type and structure
2. Extract all visible and hidden data
3. Search for patterns (especially flag formats like `flag{}`, `picoCTF{}`, etc.)
4. Try transformations:
   * Encodings (base16/32/64/85, rot13, XOR)
   * Compression / archives
   * Byte-level inspection
5. Escalate to category-specific techniques

## Domain-Specific Heuristics

### Forensics / Stego

* Check metadata, strings, and embedded files (binwalk, steghide, zsteg)
* Inspect images (bit planes, LSB, headers, corruption)
* Analyze audio via spectrogram, SSTV, DTMF, morse
* Treat common formats (PNG, JPG, DOCX) as containers

### Binary Exploitation (Pwn)

* Check protections (NX, PIE, canary)
* Look for:

  * Buffer overflows
  * Format string vulnerabilities
* Strategy: leak memory → compute offsets → craft exploit (ROP / ret2libc)

### Reverse Engineering

* Decompile and analyze logic
* Identify checks, keys, and hidden conditions
* Watch for obfuscation and byte-by-byte comparisons

### Web Exploitation

* Enumerate endpoints and parameters
* Test for:
  * SQL injection
  * SSTI
  * XSS
  * Authentication flaws
* Modify requests and fuzz inputs

### Cryptography

* Identify encoding or cipher first
* Check for weak RSA (small e, factorable n, small d)
* Try classical ciphers and automated tools
* Use math or solvers when needed

### Networking / Boxes

* Scan services and enumerate access
* Look for misconfigurations and privilege escalation paths
* Upgrade shells to interactive environments

## Behavior Rules

* Be methodical, not random
* Prefer simple explanations before complex ones
* If stuck, pivot techniques rather than repeating the same approach
* Clearly state assumptions and next steps
* When possible, suggest exact commands or scripts to run

Solve this challenge using any tools available (Bash, file reads, web fetch, etc.).

Challenge: {name}
Category:  {category}
Points:    {points}

Description:
{description}
{url_info}
{file_info}

Potential Techniques by category:
- CRYPTO: Check for alphabet substitution (A=1,B=2..Z=26).
  CRITICAL: This encoding is BIDIRECTIONAL. If a number in the description decodes to a word
  AND the hint gives you another word as the answer, you MUST encode that word back to numbers
  using the SAME scheme before submitting.
  Example: 191311212 → SMALL confirms the cipher. "the flag is faraway" → encode FARAWAY:
  F=6, A=1, R=18, A=1, W=23, A=1, Y=25 → concatenate → "6118123125" → ZeroDays{{6118123125}}
  VERIFICATION STEP: count the letters in your answer word, then count your number groups —
  they must match. FARAWAY=7 letters → 7 groups (6,1,18,1,23,1,25) → 10 digits total.
  Always ask: does the answer word need to be converted back to numbers?
  Also try: Caesar/ROT, base64/32/hex, XOR, Vigenere.
- FORENSICS: For pcap/pcapng files:
  STEP 1 — always export HTTP objects first:
    "C:/Program Files/Wireshark/tshark.exe" -r file.pcapng --export-objects "http,/tmp/pcap_out" 2>/dev/null
  STEP 2 — list what was extracted: ls /tmp/pcap_out/
  STEP 3 — use the Read tool to view EVERY image file extracted (png, jpg, gif).
    The Read tool supports images — you will see them visually. Read each one.
    IMPORTANT: The flag will be literally written as ZeroDays{{ANSWER}} somewhere in one of the images.
    Look for that exact format. Do NOT invent a flag from other text you see — only submit text
    that is literally formatted as ZeroDays{{...}} in the image.
  STEP 4 — also run: strings /tmp/pcap_out/* | grep -i "ZeroDays\|flag\|CTF"
  For zip/tar: extract and run strings/grep on contents.
- REVERSING: Use strings, objdump, javap -c for .class files. Run the binary if safe.
- WEB: Visit the URL, check source/cookies/headers, try SQLi, path traversal, IDOR.

Work step by step. End your response with exactly this line (nothing after it):
SOLUTION: {{"flag": "ZeroDays{{ANSWER}}", "reasoning": "explanation of why this is the answer and the steps taken to get to it"}}

CRITICAL:  
- All flags use the format: ZeroDays{{ANSWER}}
- Expect the challenges to make jokes or references. These could or could not be part of the answer.
"""


VIDEO_DOMAINS = ("youtube.com", "youtu.be", "vimeo.com", "twitch.tv")


def is_video_url(url: str) -> bool:
    return any(d in url for d in VIDEO_DOMAINS)


def solve_challenge_cli(challenge: dict, model: str, incorrect_flags: list[str] | None = None, timeout: int = 60) -> dict:
    """Spawn a claude CLI instance to solve a single challenge."""
    challenge_url = challenge.get("challenge_url")
    if challenge_url and is_video_url(challenge_url):
        return {"flag": "SKIP: video challenge", "reasoning": f"Challenge URL is a video ({challenge_url}) — cannot watch video"}

    file_info = ""
    if challenge.get("attachment_filename"):
        filepath = os.path.join(DOWNLOAD_DIR, challenge["attachment_filename"])
        file_info = f"File: {filepath}" if os.path.exists(filepath) else f"Note: file '{challenge['attachment_filename']}' not found."

    url_info = f"URL: {challenge_url}" if challenge_url else ""

    incorrect_info = ""
    if incorrect_flags:
        flags_list = ", ".join(f'"{f}"' for f in incorrect_flags)
        incorrect_info = f"\nPREVIOUS INCORRECT ATTEMPTS: {flags_list}\nDo NOT submit any of these again. Re-examine the challenge from scratch with a different approach.\n"

    prompt = CTF_PROMPT_TEMPLATE.format(
        name=challenge["name"],
        category=challenge["category"],
        points=challenge["points"],
        description=challenge["description"],
        url_info=url_info,
        file_info=file_info,
    ) + incorrect_info

    try:
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        result = subprocess.run(
            ["claude", "--output-format", "json", "--model", model,
             "--allowedTools", "Bash,WebFetch,Read"],
            input=prompt, capture_output=True, text=True, timeout=timeout,
            cwd=DOWNLOAD_DIR, encoding="utf-8", env=env,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            print(f"    [!] claude CLI exit {result.returncode}: {err[:200]}")
            return {"flag": f"Error: exit {result.returncode}", "reasoning": err}
        try:
            output = json.loads(result.stdout).get("result", "")
        except json.JSONDecodeError:
            raw = (result.stdout or "").strip()
            print(f"    [!] claude CLI non-JSON output: {raw[:200]}")
            return {"flag": "Error: non-JSON output", "reasoning": raw}
    except subprocess.TimeoutExpired:
        return {"flag": "Error: timed out", "reasoning": f"claude CLI timed out after {timeout}s"}
    except Exception as e:
        return {"flag": f"Error: {e}", "reasoning": ""}

    # Parse SOLUTION: {"flag": ..., "reasoning": ...} from output
    match = re.search(r'SOLUTION:\s*(\{.*\})', output, re.DOTALL)
    if match:
        try:
            solution = json.loads(match.group(1))
            return {
                "flag": solution.get("flag", "No flag in SOLUTION block"),
                "reasoning": solution.get("reasoning", ""),
            }
        except json.JSONDecodeError:
            pass

    # Fallback: find ZeroDays{...} anywhere in the output
    flag_match = re.search(r'ZeroDays\{[^}]+\}', output)
    return {
        "flag": flag_match.group(0) if flag_match else "No flag found",
        "reasoning": output.strip(),
    }


def is_failed(flag: str) -> bool:
    return not flag or flag == "No flag found" or flag.startswith("Error:")


def should_retry(solution: dict) -> bool:
    """Retry if the flag failed outright, or if the user marked it incorrect."""
    return is_failed(solution.get("flag", "")) or solution.get("correct") is False


async def solve_challenge(challenge: dict, semaphore: asyncio.Semaphore, solutions: dict, timeout: int = 30, model: str = "claude-sonnet-4-6") -> None:
    name = challenge["name"]

    # Collect any previously marked-incorrect flags to feed back into the prompt
    existing = solutions.get(name, {})
    incorrect_flags = existing.get("incorrect_flags", [])
    if existing.get("correct") is False and existing.get("flag") and not is_failed(existing["flag"]):
        if existing["flag"] not in incorrect_flags:
            incorrect_flags = incorrect_flags + [existing["flag"]]

    async with semaphore:
        print(f"\n[*] Solving: {name} ({challenge['category']}, {challenge['points']}pts)")
        if incorrect_flags:
            print(f"    -> retrying, known incorrect: {incorrect_flags}")
        print(f"    -> claude CLI ({model})")

        result = await asyncio.get_event_loop().run_in_executor(
            None, solve_challenge_cli, challenge, model, incorrect_flags or None, timeout
        )

    flag = result["flag"]
    print(f"[+] {name}: {flag}")

    solutions[name] = {
        "flag": flag,
        "reasoning": result["reasoning"],
        "category": challenge["category"],
        "points": challenge["points"],
        "correct": None,
        "incorrect_flags": incorrect_flags,
    }
    with open(SOLUTIONS_FILE, "w") as f:
        json.dump(solutions, f, indent=2)


async def run_solver(dev: bool = False, retry: bool = False):
    if not os.path.exists(METADATA_FILE):
        print("[-] No challenges.json found. Run the crawler first.")
        return

    with open(METADATA_FILE) as f:
        all_challenges = json.load(f)

    solutions = {}
    if os.path.exists(SOLUTIONS_FILE):
        with open(SOLUTIONS_FILE) as f:
            solutions = json.load(f)

    if retry:
        challenges = [
            c for c in all_challenges
            if should_retry(solutions.get(c["name"], {}))
        ]
        if not challenges:
            print("[*] No failed challenges to retry.")
            return
        print(f"[*] Retrying {len(challenges)} failed/unsolved challenges...")
    else:
        challenges = all_challenges

    def sort_key(c):
        fname = c.get("attachment_filename")
        if not fname:
            return 0
        path = os.path.join(DOWNLOAD_DIR, fname)
        return os.path.getsize(path) if os.path.exists(path) else 0

    challenges.sort(key=sort_key)

    retry_hard = "--retry-hard" in sys.argv
    retry_ultra = "--retry-ultra-hard" in sys.argv

    if retry_ultra:
        model = "claude-opus-4-6"
        timeout = 600
    elif retry_hard:
        model = "claude-sonnet-4-6"
        timeout = 600
    elif retry:
        model = "claude-sonnet-4-6"
        timeout = 120
    elif dev:
        model = "claude-haiku-4-5-20251001"
        timeout = 30
    else:
        model = "claude-sonnet-4-6"
        timeout = 60

    print(f"[*] Solving {len(challenges)} challenges with {model} via claude CLI (sorted by file size)...")

    semaphore = asyncio.Semaphore(5)
    await asyncio.gather(
        *[solve_challenge(c, semaphore, solutions, timeout=timeout, model=model) for c in challenges]
    )

    print(f"\n[*] Done. Solutions saved to {SOLUTIONS_FILE}")


if __name__ == "__main__":
    dev = "--dev" in sys.argv
    retry = any(f in sys.argv for f in ("--retry", "--retry-hard", "--retry-ultra-hard"))
    asyncio.run(run_solver(dev=dev, retry=retry))
