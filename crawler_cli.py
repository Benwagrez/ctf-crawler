"""
CTF Crawler — pure HTTP/API version (no browser, no AI).
Uses the CTFd REST API to fetch challenge metadata and download attachments.
Much faster than the browser_use version.
"""
import os
import sys
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from urllib.parse import urljoin

load_dotenv()

USERNAME = os.getenv("CTF_USERNAME")
PASSWORD = os.getenv("CTF_PASSWORD")
LOGIN_URL = os.getenv("CTF_LOGIN_URL")
CHALLENGES_URL = os.getenv("CTF_CHALLENGES_URL")
BASE_URL = LOGIN_URL.rsplit("/login", 1)[0] if LOGIN_URL else ""

DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")
METADATA_FILE = os.path.join(DOWNLOAD_DIR, "challenges.json")

if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR)


def get_session() -> requests.Session:
    """Log in and return an authenticated session."""
    session = requests.Session()

    # Fetch login page to get CSRF nonce
    resp = session.get(LOGIN_URL)
    resp.raise_for_status()

    # CTFd embeds the nonce in a <input name="nonce"> field
    from html.parser import HTMLParser

    class NonceParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.nonce = None
        def handle_starttag(self, tag, attrs):
            if tag == "input":
                attrs = dict(attrs)
                if attrs.get("name") == "nonce":
                    self.nonce = attrs.get("value")

    parser = NonceParser()
    parser.feed(resp.text)
    nonce = parser.nonce

    payload = {"name": USERNAME, "password": PASSWORD, "_submit": "Submit"}
    if nonce:
        payload["nonce"] = nonce

    login_resp = session.post(LOGIN_URL, data=payload, allow_redirects=True)
    login_resp.raise_for_status()

    if "incorrect" in login_resp.text.lower() or login_resp.url.endswith("/login"):
        raise RuntimeError("Login failed — check CTF_USERNAME and CTF_PASSWORD")

    print(f"[*] Logged in as {USERNAME}")
    return session


def fetch_challenges(session: requests.Session, limit: int | None = None) -> list[dict]:
    """Fetch all challenges via the CTFd API."""
    api_url = urljoin(BASE_URL + "/", "api/v1/challenges")
    resp = session.get(api_url)
    resp.raise_for_status()
    data = resp.json()

    if data.get("success") is False:
        raise RuntimeError(f"API error: {data}")

    challenges = data.get("data", [])
    if limit:
        challenges = challenges[:limit]

    print(f"[*] Found {len(challenges)} challenges (limit: {limit or 'none'})")
    return challenges


def fetch_challenge_detail(session: requests.Session, challenge_id: int) -> dict:
    """Fetch full detail for a single challenge including files."""
    api_url = urljoin(BASE_URL + "/", f"api/v1/challenges/{challenge_id}")
    resp = session.get(api_url)
    resp.raise_for_status()
    return resp.json().get("data", {})


def download_file(session: requests.Session, file_url: str) -> str | None:
    """Download a file attachment. Returns the saved filename."""
    full_url = file_url if file_url.startswith("http") else urljoin(BASE_URL + "/", file_url)
    resp = session.get(full_url, stream=True)
    resp.raise_for_status()

    # Extract filename from URL path (before query string)
    filename = full_url.split("?")[0].split("/")[-1]
    if not filename:
        return None

    dest = os.path.join(DOWNLOAD_DIR, filename)
    # Avoid overwriting — append suffix if needed
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(dest):
        dest = os.path.join(DOWNLOAD_DIR, f"{base} ({counter}){ext}")
        counter += 1

    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

    saved_name = os.path.basename(dest)
    print(f"    Downloaded: {saved_name} ({os.path.getsize(dest):,} bytes)")
    return saved_name


def run_crawler(limit: int | None = None):
    print("[*] Starting CLI crawler (no browser, no AI)...")
    if limit:
        print(f"[*] Challenge limit: {limit}")

    # Clear previous metadata
    if os.path.exists(METADATA_FILE):
        os.remove(METADATA_FILE)

    session = get_session()
    challenges_summary = fetch_challenges(session, limit=limit)

    import re
    VIDEO_DOMAINS = ("youtube.com", "youtu.be", "vimeo.com", "twitch.tv")

    def process_challenge(ch: dict) -> dict:
        cid = ch["id"]
        detail = fetch_challenge_detail(session, cid)

        name = detail.get("name", ch.get("name", "Unknown"))
        category = detail.get("category", "Unknown")
        points = detail.get("value", 0)
        description = detail.get("description", "")
        files = detail.get("files", [])

        challenge_url = None
        for _m in re.finditer(r'https?://\S+', description):
            _url = _m.group(0).rstrip("\"'>)")
            if not any(d in _url for d in VIDEO_DOMAINS):
                challenge_url = _url
                break

        print(f"\n[*] {name} ({category}, {points}pts)")

        attachment_filename = None
        for file_url in files:
            fname = download_file(session, file_url)
            if fname:
                attachment_filename = fname
                break

        print(f"    Saved: {name}")
        return {
            "id": cid,
            "name": name,
            "category": category,
            "points": points,
            "description": description,
            "challenge_url": challenge_url,
            "attachment_filename": attachment_filename,
        }

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_challenge, ch): ch for ch in challenges_summary}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                ch = futures[future]
                print(f"[-] Error processing {ch.get('name', ch['id'])}: {e}")

    with open(METADATA_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[*] Crawler complete. {len(results)} challenges saved to {METADATA_FILE}")


if __name__ == "__main__":
    if not all([USERNAME, PASSWORD, LOGIN_URL, CHALLENGES_URL]):
        print("[-] Missing environment variables. Check your .env file.")
        sys.exit(1)

    limit = None
    if "--limit" in sys.argv:
        idx = sys.argv.index("--limit")
        limit = int(sys.argv[idx + 1])

    run_crawler(limit=limit)
