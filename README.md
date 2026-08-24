# Bitcoin Random Key Scanner (Railway Free Tier Optimized)

High-performance, zero-allocation Bitcoin Private Key Random Generator & Matcher. Built to run 24/7 on **Railway.com Free / Hobby Tier** with zero crashes, strict memory limits (<50MB RAM), and integrated health checks.

---

## 🚀 Features

- **High-Speed Random Generation**: Generates cryptographically random 256-bit keys (or bounded puzzle bit ranges).
- **Zero-Allocation Hot Loop**: Pre-allocated buffers per worker thread ensure 0 bytes heap allocation per scan, preventing GC pauses and OOM crashes.
- **Railway Free Tier Protected**:
  - Memory ceiling enforced at 300MB (`debug.SetMemoryLimit`) to never exceed Railway's 512MB RAM cap.
  - Automatic Railway healthcheck endpoint at `/health`.
  - HTTP Server on `$PORT` to keep Railway deployment active and healthy.
- **Real-Time Live Web Dashboard**: Dark-mode web interface at `http://your-app.up.railway.app` showing live keys/sec, total scanned, matches, RAM usage, and uptime.
- **Instant Telegram Alerts**: Sends instant Telegram notifications with Address, Hex, Dec, and WIF when a match is found.
- **Target Address Flexibility**: Load target addresses from `TARGET_ADDRESSES` environment variable, local file (`addresses.txt` / `sample_addresses.txt`), or default Bitcoin puzzle list.

---

## 🛠️ How to Deploy on Railway.com (Free Tier)

### Method 1: Deploy via GitHub (Recommended)

1. **Create a GitHub Repository**:
   - Push this folder to a GitHub repository (e.g. `https://github.com/your-username/btc-random-scanner`).
   > *Note: Do not push large >100MB `addresses.txt` files to GitHub. Target addresses can be set via Railway Environment Variables or `sample_addresses.txt`.*

2. **Deploy on Railway**:
   - Go to [Railway.com](https://railway.com) and log in.
   - Click **"+ New Project"** -> **"Deploy from GitHub repo"**.
   - Select your repository.
   - Railway will automatically detect the `Dockerfile` and start building.

3. **Configure Environment Variables (Optional)**:
   - In Railway Dashboard, go to your project -> **"Variables"** tab:
     | Variable | Description | Example / Default |
     |---|---|---|
     | `TELEGRAM_BOT_TOKEN` | Your Telegram Bot Token | `8112140789:AAFs2...` |
     | `TELEGRAM_CHAT_ID` | Your Telegram Chat ID | `769770980` |
     | `TARGET_ADDRESSES` | Comma-separated target addresses | `13zb1hQbWVsc2S7ZTGarKFbe9M8UbUm2Yea,1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9` |
     | `PUZZLE_BITS` | Scan specific puzzle bit range (e.g. 66) | `66` (Leave blank for full 256-bit) |
     | `WORKERS` | Number of worker goroutines | `2` (Default: auto-detects CPU) |

4. **Generate Public Domain**:
   - In Railway Dashboard -> **"Settings"** -> **"Networking"** -> Click **"Generate Domain"**.
   - Open your URL in any browser to see the **Live Web Dashboard**!

---

## 🌐 Endpoints

- `/` : Live Dark-Mode Web Dashboard.
- `/health` : Railway JSON Healthcheck (`{"status":"healthy","uptime":...}`).
- `/stats` : Live metrics JSON API.
