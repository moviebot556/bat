package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

// Config & Defaults
var (
	DefaultBotToken = "8112140789:AAFs2PiS3b0rfNfVwkBnDth3ikrN2Uacq48"
	DefaultChatID   = "769770980"
	ResultsFile     = "matches.txt"
	DetailedFile    = "matches_detailed.json"
	MaxAddresses    = 500000 // Memory cap for Railway Free Tier (512MB RAM)
)

// Known Bitcoin Puzzle target addresses as safe fallback
var defaultPuzzleAddresses = []string{
	"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", // Puzzle #1
	"1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb", // Puzzle #3
	"1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9", // Puzzle #4
	"1EMxdcJsfN5jwtZRVRvztDns1LgquGUTwi", // Puzzle #42
	"13zb1hQbWVsc2S7ZTGarKFbe9M8UbUm2Yea", // Puzzle #66 (Unsolved)
	"1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9", // Puzzle #67 (Unsolved)
	"1MVDYgVaSN6iKKEsbzRUAYFrYJadwaaoCE", // Puzzle #68 (Unsolved)
	"19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG", // Puzzle #69 (Unsolved)
	"1KniyPkWssGk9r1i6m1y9j9w42i1b1z2e5", // Puzzle #70 (Unsolved)
	"1PitScNLzp2Ezcg2Mm55tPncp4nptkzpau", // Puzzle #71 (Unsolved)
}

// Secp256k1 Curve Order N - 1
var maxPrivKey, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)
var minPrivKey = big.NewInt(1)

// Base58 decoding map
var b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
var b58DecTable [256]byte

func init() {
	for i := range b58DecTable {
		b58DecTable[i] = 255
	}
	for i, c := range b58Alphabet {
		b58DecTable[c] = byte(i)
	}
}

// Base58Check Decoder (Extracts 20-byte Hash160)
func decodeBase58AddressToHash160(addr string) ([20]byte, bool) {
	var hash [20]byte
	if len(addr) < 26 || len(addr) > 35 {
		return hash, false
	}

	decoded := big.NewInt(0)
	radix := big.NewInt(58)
	for i := 0; i < len(addr); i++ {
		val := b58DecTable[addr[i]]
		if val == 255 {
			return hash, false
		}
		decoded.Mul(decoded, radix)
		decoded.Add(decoded, big.NewInt(int64(val)))
	}

	bytes := decoded.Bytes()
	zeros := 0
	for zeros < len(addr) && addr[zeros] == '1' {
		zeros++
	}

	fullPayload := make([]byte, zeros+len(bytes))
	copy(fullPayload[zeros:], bytes)

	if len(fullPayload) != 25 {
		return hash, false
	}

	h1 := sha256.Sum256(fullPayload[:21])
	h2 := sha256.Sum256(h1[:])
	if string(h2[:4]) != string(fullPayload[21:25]) {
		return hash, false
	}

	copy(hash[:], fullPayload[1:21])
	return hash, true
}

func base58Encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	var mod big.Int
	var out []byte

	for x.BitLen() > 0 {
		x.DivMod(x, base, &mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}

	for i := 0; i < len(b) && b[i] == 0; i++ {
		out = append(out, '1')
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func wifEncode(priv []byte) string {
	wif := make([]byte, 1+32+1+4)
	wif[0] = 0x80
	copy(wif[1:33], priv)
	wif[33] = 0x01 // compressed

	h1 := sha256.Sum256(wif[:34])
	h2 := sha256.Sum256(h1[:])
	copy(wif[34:], h2[:4])

	return base58Encode(wif)
}

type MatchRecord struct {
	Address    string `json:"address"`
	PrivateHex string `json:"private_key_hex"`
	PrivateDec string `json:"private_key_decimal"`
	PrivateBin string `json:"private_key_binary"`
	WIF        string `json:"wif"`
	FoundAt    string `json:"found_at"`
}

type ScannerStats struct {
	TotalScanned   uint64
	MatchesFound   uint64
	StartTime      time.Time
	TargetCount    int
	Workers        int
	RangeMinHex    string
	RangeMaxHex    string
	Mode           string
	TelegramActive bool
	RecentMatches  []MatchRecord
	matchLock      sync.RWMutex
}

var stats = ScannerStats{
	StartTime:     time.Now(),
	RecentMatches: make([]MatchRecord, 0),
}

var (
	matchChan    = make(chan MatchRecord, 100)
	telegramChan = make(chan MatchRecord, 100)
	fileLock     sync.Mutex
)

type RangeConfig struct {
	IsRanged bool
	Min      *big.Int
	Max      *big.Int
	Delta    *big.Int
}

func parseRangeConfig() RangeConfig {
	rangeMinStr := os.Getenv("KEY_RANGE_MIN")
	rangeMaxStr := os.Getenv("KEY_RANGE_MAX")
	puzzleBitsStr := os.Getenv("PUZZLE_BITS")

	if puzzleBitsStr != "" {
		bits, err := strconv.Atoi(puzzleBitsStr)
		if err == nil && bits >= 1 && bits <= 256 {
			min := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
			max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
			delta := new(big.Int).Sub(max, min)
			stats.Mode = fmt.Sprintf("Random Range (Puzzle #%d: %d bits)", bits, bits)
			stats.RangeMinHex = hex.EncodeToString(min.Bytes())
			stats.RangeMaxHex = hex.EncodeToString(max.Bytes())
			return RangeConfig{IsRanged: true, Min: min, Max: max, Delta: delta}
		}
	}

	if rangeMinStr != "" && rangeMaxStr != "" {
		min, ok1 := new(big.Int).SetString(strings.TrimPrefix(rangeMinStr, "0x"), 16)
		max, ok2 := new(big.Int).SetString(strings.TrimPrefix(rangeMaxStr, "0x"), 16)
		if ok1 && ok2 && max.Cmp(min) > 0 {
			delta := new(big.Int).Sub(max, min)
			stats.Mode = "Random Range (Custom Hex)"
			stats.RangeMinHex = hex.EncodeToString(min.Bytes())
			stats.RangeMaxHex = hex.EncodeToString(max.Bytes())
			return RangeConfig{IsRanged: true, Min: min, Max: max, Delta: delta}
		}
	}

	stats.Mode = "Full 256-bit Random"
	stats.RangeMinHex = "0000000000000000000000000000000000000000000000000000000000000001"
	stats.RangeMaxHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
	return RangeConfig{IsRanged: false, Min: minPrivKey, Max: maxPrivKey}
}

// Memory-Optimized Target Address Loader (<50MB RAM)
func loadTargetAddresses() map[[20]byte]string {
	targets := make(map[[20]byte]string)

	// 1. Check environment variable TARGET_ADDRESSES
	if envAddrs := os.Getenv("TARGET_ADDRESSES"); envAddrs != "" {
		list := strings.FieldsFunc(envAddrs, func(r rune) bool {
			return r == ',' || r == '\n' || r == ';' || r == ' '
		})
		for _, addr := range list {
			addr = strings.TrimSpace(addr)
			if hash, ok := decodeBase58AddressToHash160(addr); ok {
				targets[hash] = addr
			}
		}
		if len(targets) > 0 {
			fmt.Printf("✓ Loaded %d target addresses from TARGET_ADDRESSES environment variable\n", len(targets))
			stats.TargetCount = len(targets)
			return targets
		}
	}

	// 2. Check explicitly specified ADDRESSES_FILE or sample files
	var fileList []string
	if customFile := os.Getenv("ADDRESSES_FILE"); customFile != "" {
		fileList = []string{customFile}
	} else {
		fileList = []string{"addresses.txt", "addresses2.txt", "sample_addresses.txt"}
	}

	for _, fn := range fileList {
		file, err := os.Open(fn)
		if err == nil {
			scanner := bufio.NewScanner(file)
			count := 0
			for scanner.Scan() && count < MaxAddresses {
				addr := strings.TrimSpace(scanner.Text())
				if hash, ok := decodeBase58AddressToHash160(addr); ok {
					targets[hash] = addr
					count++
				}
			}
			file.Close()
			if count > 0 {
				fmt.Printf("✓ Loaded %d target addresses from %s\n", count, fn)
				stats.TargetCount = len(targets)
				return targets
			}
		}
	}

	// 3. Fallback to default puzzle addresses
	fmt.Println("! No address file found. Loading default Bitcoin puzzle target addresses...")
	for _, addr := range defaultPuzzleAddresses {
		if hash, ok := decodeBase58AddressToHash160(addr); ok {
			targets[hash] = addr
		}
	}
	fmt.Printf("✓ Loaded %d default puzzle target addresses\n", len(targets))
	stats.TargetCount = len(targets)
	return targets
}

func setupTelegramSender(botToken, chatID string) {
	if botToken == "" || chatID == "" {
		fmt.Println("! Telegram notifications disabled")
		return
	}
	stats.TelegramActive = true
	fmt.Printf("✓ Telegram notifications enabled for Chat ID: %s\n", chatID)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Telegram worker recovered from panic: %v\n", r)
			}
		}()

		for match := range telegramChan {
			msg := fmt.Sprintf("🎉 *BITCOIN MATCH FOUND!*\n\n"+
				"📍 *Address:* `%s`\n"+
				"🔑 *Private Key (HEX):* `%s`\n"+
				"🔢 *Private Key (DEC):* `%s`\n"+
				"⚡ *WIF:* `%s`\n"+
				"⏱ *Found At:* `%s`",
				match.Address, match.PrivateHex, match.PrivateDec, match.WIF, match.FoundAt)

			payload, _ := json.Marshal(map[string]string{
				"chat_id":    chatID,
				"text":       msg,
				"parse_mode": "Markdown",
			})

			url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
			for attempt := 0; attempt < 3; attempt++ {
				resp, err := client.Post(url, "application/json", strings.NewReader(string(payload)))
				if err == nil {
					resp.Body.Close()
					break
				}
				time.Sleep(2 * time.Second)
			}
		}
	}()
}

func setupMatchSaver() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Match saver recovered from panic: %v\n", r)
			}
		}()

		for match := range matchChan {
			stats.matchLock.Lock()
			stats.RecentMatches = append([]MatchRecord{match}, stats.RecentMatches...)
			if len(stats.RecentMatches) > 100 {
				stats.RecentMatches = stats.RecentMatches[:100]
			}
			stats.matchLock.Unlock()

			fmt.Printf("\n=======================================================\n")
			fmt.Printf("🎉 MATCH FOUND! %s\n", match.Address)
			fmt.Printf("HEX: %s\n", match.PrivateHex)
			fmt.Printf("DEC: %s\n", match.PrivateDec)
			fmt.Printf("WIF: %s\n", match.WIF)
			fmt.Printf("=======================================================\n\n")

			fileLock.Lock()
			f, err := os.OpenFile(ResultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				entry := fmt.Sprintf("Address: %s\nPrivate Key (HEX): %s\nPrivate Key (DEC): %s\nPrivate Key (BIN): %s\nWIF: %s\nFound At: %s\n%s\n\n",
					match.Address, match.PrivateHex, match.PrivateDec, match.PrivateBin, match.WIF, match.FoundAt, strings.Repeat("-", 70))
				f.WriteString(entry)
				f.Close()
			}

			fj, err := os.OpenFile(DetailedFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				data, _ := json.Marshal(match)
				fj.Write(append(data, '\n'))
				fj.Close()
			}
			fileLock.Unlock()

			select {
			case telegramChan <- match:
			default:
			}
		}
	}()
}

func runScannerWorker(ctx context.Context, id int, targets map[[20]byte]string, rangeCfg RangeConfig, counter *uint64, matches *uint64) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Worker %d recovered from panic: %v\n", id, r)
		}
	}()

	var (
		privBytes  [32]byte
		h160Buf    [20]byte
		localCount uint64
	)

	hasher := ripemd160.New()

	for {
		select {
		case <-ctx.Done():
			atomic.AddUint64(counter, localCount)
			return
		default:
		}

		if !rangeCfg.IsRanged {
			_, err := rand.Read(privBytes[:])
			if err != nil || privBytes == [32]byte{} {
				continue
			}
		} else {
			randVal, err := rand.Int(rand.Reader, rangeCfg.Delta)
			if err != nil {
				continue
			}
			keyNum := new(big.Int).Add(rangeCfg.Min, randVal)
			b := keyNum.Bytes()
			for i := range privBytes {
				privBytes[i] = 0
			}
			copy(privBytes[32-len(b):], b)
		}

		_, pubKey := btcec.PrivKeyFromBytes(privBytes[:])
		pubCompressed := pubKey.SerializeCompressed()

		sha := sha256.Sum256(pubCompressed)
		hasher.Reset()
		hasher.Write(sha[:])
		copy(h160Buf[:], hasher.Sum(nil))

		if matchedAddr, exists := targets[h160Buf]; exists {
			atomic.AddUint64(matches, 1)

			privNum := new(big.Int).SetBytes(privBytes[:])
			match := MatchRecord{
				Address:    matchedAddr,
				PrivateHex: hex.EncodeToString(privBytes[:]),
				PrivateDec: privNum.String(),
				PrivateBin: privNum.Text(2),
				WIF:        wifEncode(privBytes[:]),
				FoundAt:    time.Now().Format(time.RFC3339),
			}

			select {
			case matchChan <- match:
			default:
			}
		}

		localCount++
		if localCount >= 10000 {
			atomic.AddUint64(counter, localCount)
			localCount = 0
		}
	}
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BTC Random Key Scanner - Railway Node</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #090d16;
            --card-bg: rgba(18, 26, 43, 0.85);
            --card-border: rgba(255, 255, 255, 0.08);
            --accent: #f7931a;
            --accent-glow: rgba(247, 147, 26, 0.25);
            --green: #10b981;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at top right, #151f38, var(--bg));
            color: var(--text-primary);
            min-height: 100vh;
            padding: 24px 16px;
        }
        .container { max-width: 1050px; margin: 0 auto; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--card-border);
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .title-group { display: flex; align-items: center; gap: 14px; }
        .logo {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #f7931a, #e67e22);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            font-weight: bold;
            box-shadow: 0 0 20px var(--accent-glow);
        }
        .title { font-size: 22px; font-weight: 700; }
        .badge {
            background: rgba(16, 185, 129, 0.15);
            color: var(--green);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .pulse-dot {
            width: 8px;
            height: 8px;
            background: var(--green);
            border-radius: 50%;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.8); } 100% { opacity: 1; transform: scale(1); } }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 20px;
            backdrop-filter: blur(12px);
            transition: transform 0.2s, border-color 0.2s;
        }
        .card:hover { transform: translateY(-2px); border-color: rgba(247, 147, 26, 0.3); }
        .card-label { font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; font-weight: 500; }
        .card-value { font-size: 26px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
        .card-sub { font-size: 12px; color: var(--text-secondary); margin-top: 6px; }
        .highlight { color: var(--accent); }
        .section {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .section-title { font-size: 16px; font-weight: 600; margin-bottom: 16px; display: flex; justify-content: space-between; }
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #cbd5e1; word-break: break-all; }
        .table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        .table th, .table td { padding: 10px 12px; text-align: left; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .table th { color: var(--text-secondary); font-weight: 600; }
        .empty-state { text-align: center; padding: 32px 0; color: var(--text-secondary); font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title-group">
                <div class="logo">₿</div>
                <div>
                    <div class="title">Bitcoin Random Scanner</div>
                    <div style="font-size: 13px; color: var(--text-secondary);">Railway Free Tier Node</div>
                </div>
            </div>
            <div class="badge">
                <div class="pulse-dot"></div> ACTIVE & SCANNING
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-label">Instant Speed</div>
                <div class="card-value highlight" id="speed">0 k/s</div>
                <div class="card-sub" id="avg-speed">Avg: 0 k/s</div>
            </div>
            <div class="card">
                <div class="card-label">Total Keys Scanned</div>
                <div class="card-value" id="total-keys">0</div>
                <div class="card-sub" id="scanned-m">0.00 M Keys</div>
            </div>
            <div class="card">
                <div class="card-label">Target Matches</div>
                <div class="card-value" style="color: var(--green);" id="matches">0</div>
                <div class="card-sub" id="target-count">Loaded: 0 targets</div>
            </div>
            <div class="card">
                <div class="card-label">RAM / Memory</div>
                <div class="card-value" id="ram-usage">0 MB</div>
                <div class="card-sub">Railway Limit: 512 MB</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Node Configuration & Status</div>
            <table class="table">
                <tr><th>Scan Mode</th><td id="scan-mode">Random</td></tr>
                <tr><th>Active Workers</th><td id="worker-count">0</td></tr>
                <tr><th>Uptime</th><td id="uptime">0s</td></tr>
                <tr><th>Telegram Alerts</th><td id="tg-status">Checking...</td></tr>
                <tr><th>Key Space / Range</th><td class="mono" id="key-range">Full 256-bit Random</td></tr>
            </table>
        </div>

        <div class="section">
            <div class="section-title">
                <span>Recent Found Matches</span>
                <span style="font-size: 13px; color: var(--accent);" id="match-status-badge">0 Found</span>
            </div>
            <div id="matches-container">
                <div class="empty-state">No matches found yet. Scanner is actively searching keyspace...</div>
            </div>
        </div>
    </div>

    <script>
        let lastCount = 0;
        let lastTime = Date.now();

        async function updateStats() {
            try {
                const res = await fetch('/stats');
                const data = await res.json();
                const now = Date.now();
                const elapsedSec = Math.max((now - lastTime) / 1000, 0.5);

                const currentCount = data.total_scanned;
                const instantSpeed = (currentCount - lastCount) / elapsedSec;
                lastCount = currentCount;
                lastTime = now;

                document.getElementById('speed').innerText = (instantSpeed / 1000).toFixed(1) + ' k/s';
                document.getElementById('avg-speed').innerText = 'Avg: ' + (data.avg_speed_k).toFixed(1) + ' k/s';
                document.getElementById('total-keys').innerText = currentCount.toLocaleString();
                document.getElementById('scanned-m').innerText = (currentCount / 1000000).toFixed(2) + ' M Keys';
                document.getElementById('matches').innerText = data.matches_found;
                document.getElementById('target-count').innerText = 'Loaded: ' + data.target_count + ' targets';
                document.getElementById('ram-usage').innerText = data.memory_alloc_mb.toFixed(1) + ' MB';
                document.getElementById('scan-mode').innerText = data.mode;
                document.getElementById('worker-count').innerText = data.workers + ' Goroutines';
                document.getElementById('uptime').innerText = data.uptime;
                document.getElementById('tg-status').innerText = data.telegram_active ? '✓ Active' : 'Disabled';
                document.getElementById('key-range').innerText = data.range_min_hex + ' ... ' + data.range_max_hex;

                const matchBadge = document.getElementById('match-status-badge');
                matchBadge.innerText = data.matches_found + ' Found';

                const container = document.getElementById('matches-container');
                if (data.recent_matches && data.recent_matches.length > 0) {
                    let html = '<table class="table"><thead><tr><th>Address</th><th>HEX</th><th>WIF</th><th>Time</th></tr></thead><tbody>';
                    data.recent_matches.forEach(m => {
                        html += '<tr><td><strong>' + m.address + '</strong></td><td class="mono">' + m.private_key_hex + '</td><td class="mono">' + m.wif + '</td><td>' + m.found_at + '</td></tr>';
                    });
                    html += '</tbody></table>';
                    container.innerHTML = html;
                }
            } catch (err) {
                console.error('Stats poll error:', err);
            }
        }

        updateStats();
        setInterval(updateStats, 2000);
    </script>
</body>
</html>`

func startWebServer(port string, counter *uint64, matches *uint64) {
	tmpl, _ := template.New("dash").Parse(dashboardHTML)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "healthy",
			"uptime":        time.Since(stats.StartTime).Round(time.Second).String(),
			"total_scanned": atomic.LoadUint64(counter),
			"matches":       atomic.LoadUint64(matches),
		})
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		total := atomic.LoadUint64(counter)
		matchCount := atomic.LoadUint64(matches)
		elapsed := time.Since(stats.StartTime).Seconds()
		avgSpeed := float64(0)
		if elapsed > 0 {
			avgSpeed = (float64(total) / elapsed) / 1000.0
		}

		stats.matchLock.RLock()
		matchesCopy := make([]MatchRecord, len(stats.RecentMatches))
		copy(matchesCopy, stats.RecentMatches)
		stats.matchLock.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_scanned":   total,
			"matches_found":   matchCount,
			"avg_speed_k":     avgSpeed,
			"uptime":          time.Since(stats.StartTime).Round(time.Second).String(),
			"target_count":    stats.TargetCount,
			"workers":         stats.Workers,
			"mode":            stats.Mode,
			"range_min_hex":   stats.RangeMinHex,
			"range_max_hex":   stats.RangeMaxHex,
			"memory_alloc_mb": float64(mem.Alloc) / 1024 / 1024,
			"telegram_active": stats.TelegramActive,
			"recent_matches":  matchesCopy,
		})
	})

	addr := ":" + port
	fmt.Printf("✓ Live Web Dashboard & Railway Healthcheck listening on http://0.0.0.0:%s\n", port)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()
}

func main() {
	// Guard Railway Free Tier Memory (512MB hard limit -> keep Go under 300MB)
	debug.SetMemoryLimit(300 * 1024 * 1024)
	debug.SetGCPercent(50)

	fmt.Println("=======================================================")
	fmt.Println("🚀 BITCOIN RANDOM KEY SCANNER - RAILWAY FREE TIER NODE")
	fmt.Println("=======================================================")

	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		botToken = DefaultBotToken
	}
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if chatID == "" {
		chatID = DefaultChatID
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	workerCount := runtime.NumCPU()
	if wEnv := os.Getenv("WORKERS"); wEnv != "" {
		if w, err := strconv.Atoi(wEnv); err == nil && w > 0 {
			workerCount = w
		}
	}
	stats.Workers = workerCount

	var counter uint64
	var matches uint64

	// Start Web Server immediately so Railway healthcheck passes without delay
	startWebServer(port, &counter, &matches)

	rangeCfg := parseRangeConfig()
	targets := loadTargetAddresses()

	setupTelegramSender(botToken, chatID)
	setupMatchSaver()

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived shutdown signal. Stopping workers gracefully...")
		cancel()
	}()

	fmt.Printf("✓ Starting %d random scanning workers...\n", workerCount)
	fmt.Printf("✓ Mode: %s\n", stats.Mode)
	fmt.Printf("-------------------------------------------------------\n")

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runScannerWorker(ctx, workerID, targets, rangeCfg, &counter, &matches)
		}(i)
	}

	go func() {
		var lastCount uint64
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current := atomic.LoadUint64(&counter)
				matchCount := atomic.LoadUint64(&matches)
				speed := float64(current-lastCount) / 3.0
				lastCount = current

				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)

				fmt.Printf("\r⚡ Speed: %.1fk/s | Total: %dM | Matches: %d | RAM: %.1fMB | Uptime: %s",
					speed/1000.0, current/1000000, matchCount,
					float64(mem.Alloc)/1024/1024,
					time.Since(stats.StartTime).Round(time.Second).String())
			}
		}
	}()

	wg.Wait()
	close(matchChan)
	close(telegramChan)
	fmt.Println("\nScanner shutdown complete.")
}
