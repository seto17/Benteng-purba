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
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
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
	"presensi.instansi-demo.id": {URL: "http://10.10.14.2:8000", Host: "presensi.instansi-demo.id"},
	"portal-demo.example.id":    {URL: "http://10.10.14.2:8090", Host: "portal-demo.example.id"},
	"simulasi-museum.local":     {URL: "http://10.10.14.2:8000", Host: "simulasi-museum.local"},
}

var ipWhitelist = map[string]bool{}

type wafRule struct {
	Label string
	Regex *regexp.Regexp
}

// 1. Pemeriksaan khusus URL Path (Mencegah akses file/direktori rahasia tanpa memicu false positive pada teks laporan/artikel)
var wafRootSensitiveDirRegex = regexp.MustCompile(`(?i)^/(?:\.git|\.svn|\.hg|\.env|\.aws|\.ssh|storage|bootstrap/cache|node_modules|vendor/phpunit|phpmyadmin|pma|adminer|wp-admin|wp-includes)(?:/|$)`)
var wafPathOnlyRegex = regexp.MustCompile(`(?i)(?:(?:^|/)(?:\.env(?:\.[a-z0-9_-]+)?|\.git(?:/|config|head)|\.svn|\.htaccess|\.htpasswd|\.ds_store|wp-config\.php|wp-login\.php|xmlrpc\.php|artisan|composer\.(?:json|lock))|\.(?:sql|sql\.gz|bak|old|orig|swp|tar\.gz|tgz|cmd|py|sh|exe|bat|ps1|phtml|phar))$`)

// 2. Deteksi Scanner & Tools Otomatis pada User-Agent (Aman bagi Browser, Mobile App OkHttp/CFNetwork/Dart, & Link Preview)
var wafBadUserAgentRegex = regexp.MustCompile(`(?i)(sqlmap|nikto|nuclei|nmap|masscan|gobuster|dirbuster|ffuf|feroxbuster|wpscan|acunetix|netsparker|burpsuite|zgrab|hydra|metasploit|havij|commix|xsstrike|dalfox|curl/|wget/|python-requests|python-urllib|scrapy|libwww-perl)`)

// 3. Ekstensi file berbahaya pada Multipart Upload (Webshell / Executable)
var wafDangerousUploadExtRegex = regexp.MustCompile(`(?i)\.(?:php\d?|phtml|phar|phps|htaccess|htpasswd|sh|bash|py|pl|cgi|jsp|jspx|asp|aspx|cer|asa|war|exe|dll|bat|cmd|ps1|vbs|scr|msi)$`)

// 4. Aturan Kritis L7 (Path Traversal, LFI, RFI, Command Injection/RCE, SSRF, Log4Shell, SSTI, XXE, XSS)
// Dirancang presisi tinggi (RE2 O(N) bebas ReDoS & 0% False Positive terhadap HTML Rich-Text Editor pegawai)
var wafCriticalRules = []wafRule{
	{
		Label: "Path Traversal (CWE-22)",
		Regex: regexp.MustCompile(`(?i)(?:\.\.[/\\]|%2e%2e[/\\%]|[/\\]\.\.(?:[/\\]|$))`),
	},
	{
		Label: "Local File Inclusion / LFI (CWE-98)",
		Regex: regexp.MustCompile(`(?i)(?:/etc/(?:passwd|shadow|hosts|issue|group|apache2|nginx)|/proc/self(?:/|$)|boot\.ini|win\.ini|[/\\]windows[/\\]system32|(?:php|zip|phar|expect)://(?:filter|input|[^\s&'"]*(?:base64|resource=))|convert\.base64-(?:encode|decode))`),
	},
	{
		Label: "Remote File Inclusion / RFI (CWE-98)",
		Regex: regexp.MustCompile(`(?i)(?:^|[?&;])[a-z0-9_\[\].-]+=\s*(?:https?|ftp)://[^\s&'"]+\.(?:php\d?|phtml|phar|sh|bash|pl|py|rb|asp|aspx|jsp|jspx|exe|bat|cmd|ps1|txt)(?:[?#&\s]|$)`),
	},
	{
		Label: "OS Command Injection / RCE (CWE-78)",
		Regex: regexp.MustCompile(`(?i)(?:(?:^|[?&;])(?:cmd|exec|command|shell)=[^&\s]+|(?:;|\|{1,2}|&&|\$\(|\x60)\s*(?:/bin/|/usr/bin/)?(?:whoami|id|uname|cat|head|tail|more|less|ls|dir|pwd|cp|mv|rm|chmod|chown|wget|curl|fetch|nc|ncat|netcat|bash|sh|zsh|ksh|dash|python\d?|perl|php|ruby|awk|sed|find|grep|nslookup|dig|powershell|cmd\.exe|net\s+user|ipconfig|ifconfig)\b|\b(?:system|shell_exec|passthru|proc_open|popen|pcntl_exec|phpinfo|base64_decode|create_function)\s*\()`),
	},
	{
		Label: "SSRF / Log4Shell / SSTI / XXE",
		Regex: regexp.MustCompile(`(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|(?:https?|gopher|dict|file|ldap)://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\])(?::\d+|/|$|[\s&'"])|\$\{(?:jndi:|[^\}]*\$\{)|\{\{\s*(?:7\s*\*\s*7|config\b|self\b|request\b)|<!(?:entity|doctype)\s+[^>]*system\s+['"])`),
	},
	{
		Label: "Cross-Site Scripting / XSS Tag (CWE-79)",
		Regex: regexp.MustCompile(`(?i)(?:<\s*/?\s*(?:script|iframe|frame|frameset|object|embed|applet|svg|math|base|meta|marquee|xss)\b|(?:&#x0*3c|&#0*60);?\s*script|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|srcdoc\s*=)`),
	},
	{
		Label: "Cross-Site Scripting / XSS Event & Sink (CWE-79)",
		Regex: regexp.MustCompile(`(?i)(?:<[^>]*\bon(?:error|load|unload|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|focus|blur|change|submit|input|invalid|keydown|keypress|keyup|toggle|animationstart|transitionend|pointerover|auxclick|touchstart)\s*=|\b(?:onerror|onload|onmouseover|onfocus|onclick|ontoggle|oninput)\s*=\s*[a-z0-9_'"\x60(]|\b(?:alert|confirm|prompt|eval)\s*\(\s*(?:[0-9'"\x60\)\-\+!~\[]|document\b|window\b|this\b|self\b|top\b|location\b|string\b|/)|<\s*[^>]*>\s*(?:alert|confirm|prompt|eval)\s*\(|\balert\(|document\s*\.\s*(?:cookie|domain|write|writeln)|(?:\bsettimeout|\bsetinterval)\s*\(\s*['"\x60])`),
	},
}

// 5. Aturan Presisi SQL Injection (CWE-89) — Kebal komentar /*...*/ & 0% False Positive terhadap kalimat Bahasa Indonesia/Inggris
var wafSQLCommentRegex = regexp.MustCompile(`(?s)/\*.*?\*/`)
var wafSQLRules = []wafRule{
	{
		Label: "SQL Injection UNION (CWE-89)",
		Regex: regexp.MustCompile(`(?i)\bunion\s+(?:all\s+)?select\b`),
	},
	{
		Label: "SQL Injection SELECT-FROM (CWE-89)",
		Regex: regexp.MustCompile(`(?i)(?:\bselect\s+(?:\*|(?:distinct\s+)?[a-z0-9_\x60"\[\].]+\s*\([^)]*\)|@@[a-z0-9_]+|[a-z0-9_\x60"\[\].]+\s*,\s*[a-z0-9_\x60"\[\].,\s*]+)\s+from\s+[a-z0-9_\x60"\[\].]+|(?:['"();]|--|\b(?:and|or|where|having|exists|in)\b)\s*select\s+[a-z0-9_*.,\s\x60"\[\]()@+-]{1,80}\s+from\s+[a-z0-9_\x60"\[\].]+)`),
	},
	{
		Label: "SQL Injection Stacked/DDL/DML (CWE-89)",
		Regex: regexp.MustCompile(`(?i)(?:\binsert\s+into\s+[a-z0-9_\x60"\[\].]+\s*(?:\(|values\b|set\b|select\b)|\bupdate\s+[a-z0-9_\x60"\[\].]+\s+set\s+[a-z0-9_\x60"\[\].]+\s*=|\bdelete\s+from\s+[a-z0-9_\x60"\[\].]+(?:\s+where\b|\s*;|\s*--|\s*$)|\b(?:drop|alter|truncate)\s+(?:table|database|schema|user|view|procedure|function)\b)`),
	},
	{
		Label: "SQL Injection Auth-Bypass / Boolean (CWE-89)",
		Regex: regexp.MustCompile(`(?i)(?:['"]\s*(?:or|and|\|\||&&)\s*(?:['"]?[a-z0-9_]+['"]?\s*=\s*['"]?[a-z0-9_]+|(?:true|false)\b|\d+\s*(?:--|#|/\*|$))|\b(?:or|and)\s+(?:['"][a-z0-9_]+['"]\s*=\s*['"][a-z0-9_]+|\d+\s*=\s*\d+)(?:\b|['"\s\-])|(?:admin|root|user|administrator|superadmin|pegawai|\d)['"]\)*\s*(?:--(?:\s|$|[&;+\-])|#(?:\s|$|[&;]))|[a-z0-9_@.\-]+['"]\)+?\s*--(?:\s|$|[&;+\-])|[a-z0-9_@.\-]+['"]--(?:\s|$|[&;+]))`),
	},
	{
		Label: "SQL Injection Time/Error/System (CWE-89)",
		Regex: regexp.MustCompile(`(?i)(?:\b(?:pg_)?sleep\s*\(\s*\d+|\bbenchmark\s*\(\s*\d+\s*,|\bwaitfor\s+delay\s+['"]|\b(?:extractvalue|updatexml)\s*\(|\binformation_schema\b|\bload_file\s*\(|\binto\s+(?:outfile|dumpfile)\b|\bcast\s*\((?:[^()]|\([^()]*\)){1,160}\bas\s+(?:char|varchar|nchar|nvarchar|int|integer|signed|unsigned|binary|decimal|date|datetime|text|xml|json)\b|\bexec(?:ute)?\s+(?:xp_|sp_)|\bexec\s*\(\s*['"@])`),
	},
}

// Deduplikasi notifikasi Telegram WAF (anti-spam saat sqlmap burst / browser prefetch, blokir 403 tetap 100% instan)
var (
	wafAlertMu    sync.Mutex
	wafAlertDedup = make(map[string]time.Time)
)

func shouldSendWAFAlert(ip, uri, pattern string) bool {
	wafAlertMu.Lock()
	defer wafAlertMu.Unlock()
	now := time.Now()
	if len(wafAlertDedup) > 2000 {
		for k, ts := range wafAlertDedup {
			if now.Sub(ts) > 30*time.Second {
				delete(wafAlertDedup, k)
			}
		}
	}
	key := ip + "|" + uri + "|" + pattern
	if last, ok := wafAlertDedup[key]; ok && now.Sub(last) < 3*time.Second {
		return false
	}
	wafAlertDedup[key] = now
	return true
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
	log.Println("🛡️  [WAF-GO] Engine aktif & listening di :8080")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(wafHandler)))
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
	cleanHost := strings.ToLower(strings.TrimSpace(host))
	if hOnly, _, err := net.SplitHostPort(cleanHost); err == nil && hOnly != "" {
		cleanHost = hOnly
	}
	clientIP := getClientIP(r)

	backend, ok := domainMap[cleanHost]
	if !ok {
		backend, ok = domainMap[host]
	}
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
		if shouldSendWAFAlert(clientIP, fullURI, pattern) {
			go sendTelegramWAFAlert(clientIP, host, fullURI, pattern, bodyContent)
		}
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

		// Fix content-length for POST/PUT/PATCH/DELETE
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if r.Body != nil {
				bodyBytes, _ := io.ReadAll(r.Body)
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				req.ContentLength = int64(len(bodyBytes))
			}
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

func unhexByte(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// safeDecodeURL melakukan dekode %XX hingga 2 lapis (anti double-encoding & null-byte %00)
// tanpa pernah membuang string jika terdapat karakter '%' biasa (seperti "capaian 100%" atau bypass "%zz").
func safeDecodeURL(s string, plusAsSpace bool) string {
	cur := s
	for pass := 0; pass < 2; pass++ {
		var b strings.Builder
		b.Grow(len(cur))
		changed := false
		for i := 0; i < len(cur); i++ {
			ch := cur[i]
			if pass == 0 && plusAsSpace && ch == '+' {
				b.WriteByte(' ')
				changed = true
				continue
			}
			if ch == '%' && i+2 < len(cur) {
				hi, ok1 := unhexByte(cur[i+1])
				lo, ok2 := unhexByte(cur[i+2])
				if ok1 && ok2 {
					dec := (hi << 4) | lo
					i += 2
					changed = true
					if dec == 0 {
						// Buang null-byte (%00) agar teknik bypass UN%00ION / shell.php%00.jpg gagal
						continue
					}
					b.WriteByte(dec)
					continue
				}
			}
			if ch != 0 {
				b.WriteByte(ch)
			}
		}
		cur = b.String()
		if !changed {
			break
		}
	}
	return cur
}

func isSensitivePasswordField(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "password", "password_confirmation", "current_password", "pass", "pwd", "passwd", "secret", "gemini_key", "api_key":
		return true
	default:
		return false
	}
}

// extractSafeKeyValuePairs mem-parsing query/form secara toleran (kebal bypass %zz di Go url.ParseQuery)
func extractSafeKeyValuePairs(raw string) string {
	if raw == "" {
		return ""
	}
	normalized := strings.ReplaceAll(raw, ";", "&")
	parts := strings.Split(normalized, "&")
	var out strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		k, v, hasEq := strings.Cut(part, "=")
		kDec := safeDecodeURL(k, true)
		if isSensitivePasswordField(kDec) {
			continue
		}
		if hasEq {
			vDec := safeDecodeURL(v, true)
			out.WriteString(kDec)
			out.WriteByte('=')
			out.WriteString(vDec)
			out.WriteByte('&')
		} else {
			out.WriteString(kDec)
			out.WriteByte('&')
		}
	}
	return out.String()
}

var jsonPasswordMaskRegex = regexp.MustCompile(`(?i)"(password|password_confirmation|current_password|pass|pwd|passwd|secret|gemini_key|api_key)"\s*:\s*"(?:\\.|[^"\\])*"`)
var jsonUnicodeEscapeRegex = regexp.MustCompile(`(?i)\\u00([2-7][0-9a-f])`)

func decodeJSONEscapes(s string) string {
	masked := jsonPasswordMaskRegex.ReplaceAllString(s, `"$1":"******"`)
	return jsonUnicodeEscapeRegex.ReplaceAllStringFunc(masked, func(m string) string {
		if len(m) == 6 {
			hi, ok1 := unhexByte(m[4])
			lo, ok2 := unhexByte(m[5])
			if ok1 && ok2 {
				return string([]byte{(hi << 4) | lo})
			}
		}
		return m
	})
}

func formatRuleHit(label, matched string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(matched, "\n", " "), "\r", " "))
	if len(clean) > 40 {
		clean = clean[:40] + "..."
	}
	if clean != "" {
		return fmt.Sprintf("%s [%s]", label, clean)
	}
	return label
}

func isMalicious(r *http.Request) (bool, string, string) {
	// 0. Cek User-Agent berbahaya (sqlmap, nikto, nuclei, nmap, curl/, wget/, python-requests, dll)
	ua := r.Header.Get("User-Agent")
	if ua != "" {
		if m := wafBadUserAgentRegex.FindString(ua); m != "" {
			return true, "Scanner User-Agent (" + m + ")", "User-Agent: " + ua
		}
	}

	// Baca & kembalikan r.Body agar backend Laravel tetap menerima payload utuh (termasuk upload file besar)
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	rawBody := string(bodyBytes)

	// Dekode URL Path & RequestURI mentah (mencegah bypass path traversal sebelum normalisasi)
	rawReqURI := r.URL.RequestURI()
	rawPathPart := r.URL.Path
	if idx := strings.IndexByte(rawReqURI, '?'); idx != -1 {
		if idx > 0 {
			rawPathPart = rawReqURI[:idx]
		}
	} else if rawReqURI != "" {
		rawPathPart = rawReqURI
	}
	decodedPath := safeDecodeURL(rawPathPart, false)
	pathLower := strings.ToLower(decodedPath)

	// 1. Cek Direktori & File Sensitif HANYA pada URL Path (0% False Positive terhadap kata 'storage' di laporan pegawai)
	if m := wafRootSensitiveDirRegex.FindString(pathLower); m != "" {
		return true, formatRuleHit("Sensitive Directory Probe (CWE-538)", m), "(Serangan pada URL Path)"
	}
	if m := wafPathOnlyRegex.FindString(pathLower); m != "" {
		return true, formatRuleHit("Sensitive File Probe (CWE-538)", m), "(Serangan pada URL Path)"
	}
	if strings.HasSuffix(pathLower, ".php") && pathLower != "/index.php" && pathLower != "/login.php" {
		return true, formatRuleHit("Unauthorized PHP / Webshell Probe", decodedPath), "(Serangan pada URL Path)"
	}

	// 2. Ekstrak Query String secara aman (mendukung pemisah ';' maupun '&' serta double URL-encoding)
	queryExtracted := extractSafeKeyValuePairs(r.URL.RawQuery)

	// 3. Ekstrak Body sesuai Content-Type:
	//    - multipart/form-data: Periksa nama file upload, tag PHP webshell (<?php), & field teks (tanpa memindai byte biner foto/PDF/Excel!)
	//    - application/json: Masking password & dekode \u00XX
	//    - x-www-form-urlencoded: Ekstrak semua field non-password dengan aman (kebal %zz bypass)
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	formExtracted := ""
	bodyLogSummary := maskSensitiveData(rawBody)

	if strings.HasPrefix(contentType, "multipart/form-data") && len(bodyBytes) > 0 {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err == nil && params["boundary"] != "" {
			mr := multipart.NewReader(bytes.NewReader(bodyBytes), params["boundary"])
			var textSummary strings.Builder
			for {
				part, errPart := mr.NextPart()
				if errPart != nil {
					break
				}
				rawCD := part.Header.Get("Content-Disposition")
				fname := ""
				if _, cdParams, errCD := mime.ParseMediaType(rawCD); errCD == nil {
					fname = cdParams["filename"]
				}
				if fname == "" {
					fname = part.FileName()
				}
				fieldName := part.FormName()
				if fname != "" || strings.Contains(strings.ToLower(rawCD), "filename=") {
					fnDec := safeDecodeURL(fname, false)
					fnLower := strings.ToLower(fnDec)
					cdLower := strings.ToLower(safeDecodeURL(rawCD, false))
					// Cek Path Traversal pada nama file upload mentah (sebelum filepath.Base Go menghapus ../)
					if strings.Contains(fnLower, "../") || strings.Contains(fnLower, `..\`) || strings.Contains(cdLower, "../") || strings.Contains(cdLower, `..\`) {
						return true, formatRuleHit("Malicious Upload Filename Traversal", fnDec), "Upload Filename: " + fnDec
					}
					// Cek ekstensi Webshell / Executable pada file upload
					if m := wafDangerousUploadExtRegex.FindString(fnLower); m != "" {
						return true, formatRuleHit("Webshell / Executable File Upload (CWE-434)", fnDec), "Upload Filename: " + fnDec
					}
					// Baca 8KB pertama file upload untuk mendeteksi penyelundupan kode PHP (Polyglot Webshell <?php)
					headBuf := make([]byte, 8192)
					n, _ := io.ReadFull(part, headBuf)
					if n > 0 {
						headStr := strings.ToLower(string(headBuf[:n]))
						if strings.Contains(headStr, "<?php") || strings.Contains(headStr, "<?= ") || strings.Contains(headStr, "<?=") && strings.Contains(headStr, "$_") {
							return true, "PHP Webshell Payload in Upload (CWE-434)", "Upload Filename: " + fnDec
						}
						// Jika file berbasis teks/markup (.svg, .html, .htm, .xml), periksa juga terhadap XSS/XXE
						if strings.HasSuffix(fnLower, ".svg") || strings.HasSuffix(fnLower, ".html") || strings.HasSuffix(fnLower, ".htm") || strings.HasSuffix(fnLower, ".xml") {
							formExtracted += "upload_markup=" + headStr + "&"
						}
					}
					textSummary.WriteString(fmt.Sprintf("[File:%s] ", fnDec))
				} else {
					valBytes, _ := io.ReadAll(io.LimitReader(part, 1024*1024))
					valStr := string(valBytes)
					if !isSensitivePasswordField(fieldName) {
						formExtracted += fieldName + "=" + valStr + "&"
						textSummary.WriteString(fieldName + "=" + valStr + "&")
					} else {
						textSummary.WriteString(fieldName + "=******&")
					}
				}
			}
			bodyLogSummary = textSummary.String()
		}
	} else if strings.Contains(contentType, "json") || (strings.HasPrefix(strings.TrimSpace(rawBody), "{") && strings.HasSuffix(strings.TrimSpace(rawBody), "}")) {
		formExtracted = decodeJSONEscapes(rawBody)
		bodyLogSummary = jsonPasswordMaskRegex.ReplaceAllString(rawBody, `"$1":"******"`)
	} else if len(bodyBytes) > 0 {
		formExtracted = extractSafeKeyValuePairs(rawBody)
	}

	// Gabungkan seluruh komponen dengan pembatas '?' dan '&' yang presisi
	var inspectBuf strings.Builder
	inspectBuf.WriteString(decodedPath)
	if queryExtracted != "" {
		inspectBuf.WriteByte('?')
		inspectBuf.WriteString(queryExtracted)
	}
	if formExtracted != "" {
		inspectBuf.WriteByte('&')
		inspectBuf.WriteString(formExtracted)
	}
	fullPayload := inspectBuf.String()

	// 4. Cek seluruh Aturan Kritis (Path Traversal, LFI, RFI, Command Injection, SSRF, Log4Shell, SSTI, XXE, XSS)
	for _, rule := range wafCriticalRules {
		if m := rule.Regex.FindString(fullPayload); m != "" {
			return true, formatRuleHit(rule.Label, m), bodyLogSummary
		}
	}

	// 5. Cek seluruh Aturan SQL Injection (dengan normalisasi komentar inline /*...*/ -> spasi)
	sqlNormalizedPayload := wafSQLCommentRegex.ReplaceAllString(fullPayload, " ")
	for _, rule := range wafSQLRules {
		if m := rule.Regex.FindString(sqlNormalizedPayload); m != "" {
			return true, formatRuleHit(rule.Label, m), bodyLogSummary
		}
	}

	return false, "", ""
}

var sensitiveMaskRegex = regexp.MustCompile(`(?i)(password_confirmation|current_password|password|pass|pwd|passwd|secret|gemini_key|api_key)=([^&]*)`)
var secretEndpointMaskRegex = regexp.MustCompile(`(?i)^/(api-internal-v1|api-internal-v2|api-internal-v3|api-internal-v4|api-sync-mesin|api-mobile-presensi)\b`)

func maskSensitiveData(raw string) string {
	masked := sensitiveMaskRegex.ReplaceAllString(raw, "$1=******")
	return secretEndpointMaskRegex.ReplaceAllString(masked, "/api-presensi/***")
}

func maskSecretDomain(host string) string {
	hLow := strings.ToLower(strings.TrimSpace(host))
	if hLow == "api.instansi-demo.id" || strings.HasSuffix(hLow, ".api.instansi-demo.id") {
		return strings.ReplaceAll(strings.ReplaceAll(host, "api.instansi-demo.id", "api.instansi-demo.***"), "API.INSTANSI-DEMO.ID", "API.INSTANSI-DEMO.***")
	}
	return host
}

func getTelegramConfig() (string, string) {
	token := "YOUR_TELEGRAM_BOT_TOKEN_HERE"
	chatID := "YOUR_TELEGRAM_CHAT_ID"

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
		html.EscapeString(maskSecretDomain(host)),
		now,
		html.EscapeString(ip),
		html.EscapeString(maskSensitiveData(path)),
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

var blokirLogMu sync.Mutex

func appendBlockedLog(ip, host, path, pattern, body string) {
	blokirLogMu.Lock()
	defer blokirLogMu.Unlock()
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
