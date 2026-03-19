# CTF Crawler

An AI-driven agent that logs into a CTF platform, crawls all challenges, downloads attachments, and attempts to solve each challenge.

## Architecture

Two implementations:

### CLI versions (recommended)
- **`crawler_cli.py`** — Pure HTTP/API crawler. No browser, no AI. Uses the CTFd REST API to fetch metadata and download attachments.
- **`solver_cli.py`** — Spawns `claude` CLI subprocesses (one per challenge) to solve each challenge independently.

### Browser/SDK versions (original)
- **`crawler.py`** — `browser_use` agent (Haiku) navigates the CTF site and saves metadata.
- Solver is embedded in `crawler.py` — uses the Anthropic SDK directly with tool use.

## Setup

```bash
python -m venv venv
source venv/Scripts/activate   # Windows
pip install browser-use langchain-anthropic python-dotenv requests
```

`.env` requires:
```
ANTHROPIC_API_KEY=...
CTF_USERNAME=...
CTF_PASSWORD=...
CTF_LOGIN_URL=...
CTF_CHALLENGES_URL=...
```

## Usage — CLI (recommended)

```bash
# Crawl all challenges (fast, no AI)
python crawler_cli.py

# Crawl with limit
python crawler_cli.py --limit 5

# Solve with Haiku (dev/cheap)
python solver_cli.py --dev

# Solve with Sonnet (prod)
python solver_cli.py

# Solve with Sonnet (prod)
python solver_cli.py --retry

# Solve with Sonnet retry hard 10 minutes
python solver_cli.py --retry-hard

# Solve with Opus 10 minutes
python solver_cli.py --retry-ultra-hard


```

## Usage — Browser/SDK (original)

```bash
# Dev test — crawl first 2 challenges, solve with Haiku
python crawler.py both --limit 2 --dev

# Crawl only
python crawler.py crawl --limit 2

# Solve only (uses existing challenges.json)
python crawler.py solve --dev

# Full prod run — crawl all, solve with Sonnet
python crawler.py both
```

## Output

| File | Description |
|---|---|
| `downloads/challenges.json` | Challenge metadata: name, category, points, description, URL, attachment filename |
| `downloads/solutions_cli.json` | CLI solver results keyed by challenge name |
| `downloads/solutions.json` | SDK solver results keyed by challenge name |
| `downloads/<files>` | Downloaded challenge attachments |

## Models

| Role | Dev (`--dev`) | Prod (default) |
|---|---|---|
| CLI Crawler | — (no AI) | — (no AI) |
| CLI Solver | Haiku | Sonnet |
| Browser Crawler | Haiku | Haiku |
| SDK Solver | Haiku | Sonnet |

## Notes

- CLI crawler skips YouTube/video URLs when setting `challenge_url` — the solver skips challenges where the primary URL is a video
- Challenges are sorted by attachment file size (smallest first) to get fast results early
- For FORENSICS/pcap challenges, the solver uses `tshark --export-objects` and the Read tool to view extracted images
