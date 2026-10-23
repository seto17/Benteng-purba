package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

//go:embed templates/log.html
var logsHTML embed.FS

//go:embed templates/waf.html
var wafPage embed.FS

type Backend struct {
	URL  string
	Host string
}

var domainMap = map[string]Backend{
	"sangiran.id":             {URL: "http://192.168.22.2:8090", Host: "sangiran.id"},
	"sangiran.xyz":            {URL: "http://192.168.14.2:8000", Host: "sangiran.xyz"},
	"museumdancagarbudaya.id": {URL: "http://192.168.14.2:8000", Host: "museumdancagarbudaya.id"},
}

var ipWhitelist = map[string]bool{
	"127.0.0.1":    true,
	"192.168.17.1": true,
}

func serveWAFPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(wafPage, "templates/waf.html")
	if err != nil {
		http.Error(w, "WAF Error Page tidak ditemukan", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = tmpl.Execute(w, nil)
}

func main() {
	http.HandleFunc("/", wafHandler)
	log.Println("🛡️  [WAF-GO] Engine aktif & listening di :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getClientIP(r *http.Request) string {
	// Prioritas 0: Baca Cf-Connecting-Ip jika melalui Cloudflare / Tunnel
	if cfip := r.Header.Get("Cf-Connecting-Ip"); cfip != "" {
		ip := strings.TrimSpace(cfip)
		if ip != "" && ip != "127.0.0.1" && ip != "::1" {
			return ip
		}
	}
	// Prioritas 1: Baca X-Forwarded-For jika di balik Caddy
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" && ip != "127.0.0.1" && ip != "::1" {
				return ip
			}
		}
	}
	// Prioritas 2: Baca X-Real-IP
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		ip := strings.TrimSpace(xrip)
		if ip != "" && ip != "127.0.0.1" && ip != "::1" {
			return ip
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	// Skip localhost
	if ip == "127.0.0.1" || ip == "::1" {
		return ""
	}
	return ip
}

func wafHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	clientIP := getClientIP(r)

	backend, ok := domainMap[host]
	if !ok {
		log.Printf("⚠️ [WAF] Domain tidak dikenal: %s dari IP: %s", host, clientIP)
		http.Error(w, "Domain tidak dikenal", http.StatusBadRequest)
		return
	}

	// Bypass WAF untuk IP whitelist, periksa malicious jika bukan whitelist
	malicious, pattern, bodyContent := isMalicious(r)
	if !ipWhitelist[clientIP] && malicious {
		fullURI := maskSensitiveData(r.URL.RequestURI())
		log.Printf("🚫 [WAF BLOCKED] Malicious pattern detected! IP: %s | Host: %s | URI: %s | Pattern: %s", clientIP, host, fullURI, pattern)
		serveWAFPage(w, r)
		go sendTelegramWAFAlert(clientIP, host, fullURI, pattern, bodyContent)
		go appendBlockedLog(clientIP, host, fullURI, pattern, bodyContent)
		return
	}

	// Reverse proxy
	proxyURL, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)

	// Fix Laravel HTTPS aware
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		/*xff := ip
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			// Selalu taruh IP client di depan
			xff = ip + ", " + prior
		}
		req.Header.Del("X-Forwarded-For")
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", ip)
		req.Host = backend.Host
		req.Header.Set("Host", backend.Host)
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
		*/
		// Ambil IP dari client
		clientIP := getClientIP(r)

		req.Host = backend.Host
		req.Header.Set("Host", backend.Host)
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Proto", "https")

		// Bersihin dulu
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-IP")

		// Set cuma IP publik
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Real-IP", clientIP)
		// Forward cookies
		for _, c := range r.Cookies() {
			req.AddCookie(c)
		}

		// Fix content-length for POST/PUT
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		//logger.Printf("🔁 Status=%d | Headers=%v", resp.StatusCode, resp.Header)

		// Rewrite Set-Cookie domain & remove Secure flag
		for i, cookie := range resp.Header["Set-Cookie"] {
			//logger.Printf("🍪 Set-Cookie Sebelum: %s", cookie)
			cookie = strings.ReplaceAll(cookie, "Domain="+backend.Host, "Domain="+r.Host)
			cookie = strings.ReplaceAll(cookie, " Secure;", "")
			cookie = strings.ReplaceAll(cookie, " Secure", "")
			cookie = strings.ReplaceAll(cookie, ";secure", "")
			cookie = strings.ReplaceAll(cookie, "; secure", "")
			cookie = strings.ReplaceAll(cookie, "secure;", "")
			cookie = strings.ReplaceAll(cookie, "secure", "")
			resp.Header["Set-Cookie"][i] = cookie
			//logger.Printf("🍪 Set-Cookie Sesudah: %s", cookie)
		}

		// Rewrite redirect Location header
		location := resp.Header.Get("Location")
		if location != "" {
			//logger.Printf("➡️ Redirect Sebelum: %s", location)
			backendURL, _ := url.Parse(backend.URL)
			if strings.HasPrefix(location, backendURL.String()) {
				location = strings.Replace(location, backendURL.String(), "https://"+r.Host, 1)
				resp.Header.Set("Location", location)
				//logger.Printf("➡️ Redirect Sesudah: %s", location)
			}
		}

		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		//logger.Printf("❌ Backend error: %v", e)
		http.Error(w, "Backend error", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

func hasAuthenticatedEmployeeSession(r *http.Request) bool {
	for _, c := range r.Cookies() {
		name := strings.ToLower(c.Name)
		if (strings.Contains(name, "laravel_session") || strings.Contains(name, "xsrf-token")) && len(c.Value) > 10 {
			return true
		}
	}
	return false
}

func isMalicious(r *http.Request) (bool, string, string) {
	// Pola Kritis & Sistem (Selalu diblokir di semua endpoint, baik URL maupun Form Body)
	criticalPatterns := []string{
		// XSS & Script Injection
		"<script", "javascript:", "onerror=", "onload=", "alert(", "<img", "document.cookie", "eval(", "setTimeout(",
		"<iframe", "<svg", "<body", "<video", "<input", "srcdoc=",
		"%3cscript", "%3ciframe", "%3csvg", "%3cimg",

		// Directory Traversal & Sensitive Files
		"/etc/passwd", "boot.ini", "/proc/", "/windows/", "win.ini",
		"/.env", "/.git", "/wp-config.php", "/.htaccess",

		// Command Injection & RCE
		"| sh", "| bash", "| nc", "| wget", "| curl", "| php", "| perl", "| python", "| ls", "| cat",

		// SSRF
		"127.0.0.1", "localhost", "::1", "169.254.169.254", "0.0.0.0", "metadata.google.internal",

		// System Functions & SQL Destructive/Time-Based Payloads
		"base64_decode", "system(", "shell_exec", "passthru(", "phpinfo(", "load_file(", "outfile", "information_schema",
		"sleep(", "benchmark(", "waitfor delay",
	}

	// Pola Kata Kunci SQL (Diblokir penuh di URL Query & Endpoint Publik, namun diizinkan pada teks Form Body Log Harian Pegawai Terautentikasi)
	sqlTextPatterns := []string{
		"union select", "select .* from", "insert into", "update .* set", "delete from",
		"drop table", "alter table", "exec(",
	}

	// Simpan isi body asli untuk dikembalikan nanti
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset agar backend bisa baca

	rawBody := string(bodyBytes)

	// Decode salinan isi body
	formData, _ := url.ParseQuery(rawBody)

	// Ambil query string dan kecualikan password
	query := ""
	for key, vals := range r.URL.Query() {
		if strings.ToLower(key) == "password" {
			continue
		}
		for _, val := range vals {
			query += key + "=" + val + "&"
		}
	}

	// Ambil body form kecuali password
	form := ""
	for key, vals := range formData {
		if strings.ToLower(key) == "password" {
			continue
		}
		for _, val := range vals {
			form += key + "=" + val + "&"
		}
	}

	urlPayload := strings.ToLower(r.URL.Path + query)
	fullPayload := strings.ToLower(r.URL.Path + query + form)

	// 1. Cek Pola Kritis (XSS, LFI, RCE, SSRF, Sensitive File, Time-based SQLi) pada SELURUH request (URL + Form Body)
	for _, pattern := range criticalPatterns {
		if strings.Contains(fullPayload, strings.ToLower(pattern)) {
			return true, pattern, maskSensitiveData(rawBody)
		}
	}

	// 2. Context-Aware Check untuk Kata Kunci SQL (union select, insert into, dll):
	// Selalu blokir jika ada di URL/Query String, ATAU jika bukan form POST/PUT pegawai terautentikasi di route internal (/pegawaic)
	isInternalEmployeeForm := (r.Method == http.MethodPost || r.Method == http.MethodPut) &&
		strings.HasPrefix(strings.ToLower(r.URL.Path), "/pegawaic") &&
		hasAuthenticatedEmployeeSession(r)

	for _, pattern := range sqlTextPatterns {
		patLower := strings.ToLower(pattern)
		// Jika ada di URL path / query string -> tetap blokir mutlak!
		if strings.Contains(urlPayload, patLower) {
			return true, pattern, maskSensitiveData(rawBody)
		}
		// Jika bukan form internal pegawai terautentikasi -> blokir juga di form body!
		if !isInternalEmployeeForm && strings.Contains(fullPayload, patLower) {
			return true, pattern, maskSensitiveData(rawBody)
		}
	}

	return false, "", ""
}

var sensitiveMaskRegex = regexp.MustCompile(`(?i)(password|pass|pwd|passwd|secret)=([^&]*)`)

func maskSensitiveData(raw string) string {
	return sensitiveMaskRegex.ReplaceAllString(raw, "$1=******")
}

func getTelegramConfig() (string, string) {
	token := "YOUR_TELEGRAM_BOT_TOKEN_HERE"
	chatID := "YOUR_CHAT_ID_HERE"

	configPaths := []string{
		"/home/cula/kirimbot/config.ini",
		"../kirimbot/config.ini",
		"config.ini",
	}

	for _, cp := range configPaths {
		if content, err := os.ReadFile(cp); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Token") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
						token = strings.TrimSpace(parts[1])
					}
				}
				if strings.HasPrefix(line, "ChatID") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
						chatID = strings.TrimSpace(parts[1])
					}
				}
			}
			break
		}
	}

	if envToken := os.Getenv("TELEGRAM_TOKEN"); envToken != "" {
		token = envToken
	}
	if envChatID := os.Getenv("TELEGRAM_CHAT_ID"); envChatID != "" {
		chatID = envChatID
	}

	return token, chatID
}

func sendTelegramWAFAlert(ip, host, path, pattern, body string) {
	token, chatID := getTelegramConfig()

	now := time.Now().Format("2006-01-02 15:04:05")
	bodyClean := strings.TrimSpace(body)
	if len(bodyClean) > 300 {
		bodyClean = bodyClean[:300] + "..."
	}
	if bodyClean == "" {
		bodyClean = "(Tidak ada payload body / serangan di URL query)"
	}

	// Gunakan format HTML agar kebal terhadap karakter unik SQLi (*, _, ', dll)
	text := fmt.Sprintf(
		"⚠️ <b>Pola Mencurigakan Terdeteksi oleh WAF Go</b>\n"+
			"🌐 <b>Host:</b> <code>%s</code>\n"+
			"🕒 %s\n"+
			"📍 <b>IP:</b> <code>%s</code>\n"+
			"🔗 <b>URI:</b> <code>%s</code>\n"+
			"📝 <b>Body:</b> <code>%s</code>\n"+
			"🔍 <b>Pattern:</b> <code>%s</code>",
		html.EscapeString(host),
		now,
		html.EscapeString(ip),
		html.EscapeString(path),
		html.EscapeString(bodyClean),
		html.EscapeString(pattern),
	)

	keyboard := map[string]interface{}{
		"inline_keyboard": [][]map[string]string{
			{
				{"text": "🔒 Blokir IP Ini", "callback_data": fmt.Sprintf("blockip:%s", ip)},
				{"text": "🧠 Minta Analisis AI", "callback_data": fmt.Sprintf("askai:%s", ip)},
			},
		},
	}
	keyboardJSON, _ := json.Marshal(keyboard)

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	formData := url.Values{
		"chat_id":      {chatID},
		"text":         {text},
		"parse_mode":   {"HTML"},
		"reply_markup": {string(keyboardJSON)},
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm(endpoint, formData)
	if err != nil {
		log.Printf("⚠️ [TELEGRAM WAF ERROR] Gagal koneksi ke Telegram API: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠️ [TELEGRAM WAF REJECTED] Status %d: %s", resp.StatusCode, string(respBody))
	} else {
		log.Printf("📢 [TELEGRAM WAF SENT] Alert terkirim ke Telegram untuk IP: %s (Pattern: %s)", ip, pattern)
	}
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	logBytes, err := os.ReadFile("blokir.txt")
	if err != nil {
		logBytes, _ = os.ReadFile("waf.log")
	}
	tmpl, err := template.ParseFS(logsHTML, "templates/log.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, string(logBytes))
}

func appendBlockedLog(ip, host, path, pattern, body string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	bodyClean := strings.TrimSpace(body)
	if len(bodyClean) > 200 {
		bodyClean = bodyClean[:200] + "..."
	}
	if bodyClean == "" {
		bodyClean = "(Tidak ada payload body)"
	}

	line := fmt.Sprintf("[%s] 🚫 BLOCKED | IP: %s | Host: %s | Path: %s | Pattern: %s | Body: %s\n",
		now, ip, host, path, pattern, bodyClean)

	f, err := os.OpenFile("blokir.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("⚠️ Gagal menulis ke blokir.txt: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(line); err != nil {
		log.Printf("⚠️ Gagal append baris ke blokir.txt: %v", err)
	}
}
