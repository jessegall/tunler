package client

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxExchanges = 200      // ring buffer size
	maxBodyKeep  = 64 << 10 // bytes of each body kept for the inspector
)

// Exchange is one observed HTTP request/response pair flowing through the
// tunnel. Parsing is purely observational: the byte relay never depends on
// it, so a parse failure can never break traffic.
type Exchange struct {
	ID         int           `json:"id"`
	Start      time.Time     `json:"start"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	ReqHeader  http.Header   `json:"req_header"`
	ReqBody    []byte        `json:"req_body,omitempty"`
	ReqSize    int64         `json:"req_size"`
	StatusCode int           `json:"status_code"`
	RespHeader http.Header   `json:"resp_header,omitempty"`
	RespBody   []byte        `json:"resp_body,omitempty"`
	RespSize   int64         `json:"resp_size"`
	Duration   time.Duration `json:"duration"`
	Done       bool          `json:"done"`
}

// Inspector keeps recent exchanges, prints ngrok-style log lines, and can
// serve a local web UI.
type Inspector struct {
	mu   sync.Mutex
	ring []*Exchange
	next int
}

func NewInspector() *Inspector { return &Inspector{} }

func (ins *Inspector) add(e *Exchange) {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	ins.next++
	e.ID = ins.next
	ins.ring = append(ins.ring, e)
	if len(ins.ring) > maxExchanges {
		ins.ring = ins.ring[len(ins.ring)-maxExchanges:]
	}
}

func (ins *Inspector) snapshot() []*Exchange {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	out := make([]*Exchange, len(ins.ring))
	copy(out, ins.ring)
	return out
}

func (ins *Inspector) byID(id int) *Exchange {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	for _, e := range ins.ring {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// observe parses the two tee'd byte streams of one tunnel connection.
// reqR carries visitor->local bytes (requests), respR local->visitor
// (responses). Both readers MUST be drained or the relay stalls, so every
// exit path falls through to io.Copy(io.Discard, ...).
func (ins *Inspector) observe(reqR, respR io.Reader) {
	queue := make(chan *Exchange, 64)

	go func() {
		defer close(queue)
		defer io.Copy(io.Discard, reqR)
		br := bufio.NewReader(reqR)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			e := &Exchange{
				Start:     time.Now(),
				Method:    req.Method,
				Path:      req.URL.RequestURI(),
				ReqHeader: req.Header.Clone(),
			}
			e.ReqBody, e.ReqSize, err = captureBody(req.Body)
			ins.add(e)
			queue <- e
			if err != nil || isUpgrade(req.Header) {
				return // stop parsing (e.g. websocket frames follow)
			}
		}
	}()

	defer io.Copy(io.Discard, respR)
	defer drainExchanges(queue) // keep the request parser from blocking on a full queue
	br := bufio.NewReader(respR)
	for e := range queue {
		resp, err := http.ReadResponse(br, &http.Request{Method: e.Method})
		if err != nil {
			return
		}
		e.StatusCode = resp.StatusCode
		e.RespHeader = resp.Header.Clone()
		e.RespBody, e.RespSize, err = captureBody(resp.Body)
		e.Duration = time.Since(e.Start)
		e.Done = true
		log.Printf("%-4s %-40s %d %s  %s  %s",
			e.Method, truncate(e.Path, 40), e.StatusCode,
			http.StatusText(e.StatusCode), e.Duration.Round(100*time.Microsecond),
			byteCount(e.RespSize))
		if err != nil || resp.StatusCode == http.StatusSwitchingProtocols {
			return
		}
	}
}

// drainExchanges keeps the request-parsing goroutine from blocking on a full
// queue once the response side has stopped reading. The queue is closed by
// the request goroutine at EOF, so this terminates.
func drainExchanges(queue <-chan *Exchange) {
	go func() {
		for range queue {
		}
	}()
}

// captureBody drains rc completely (mandatory for parser sync), keeping at
// most maxBodyKeep bytes, and reports the true size.
func captureBody(rc io.ReadCloser) ([]byte, int64, error) {
	if rc == nil {
		return nil, 0, nil
	}
	defer rc.Close()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(rc, maxBodyKeep))
	if err != nil {
		return buf.Bytes(), n, err
	}
	rest, err := io.Copy(io.Discard, rc)
	return buf.Bytes(), n + rest, err
}

func isUpgrade(h http.Header) bool {
	return strings.EqualFold(h.Get("Upgrade"), "websocket") ||
		strings.Contains(strings.ToLower(h.Get("Connection")), "upgrade")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func byteCount(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// Serve starts the local inspector UI. If the port is taken (another tunler
// running) it walks forward up to 20 ports. Returns the address it bound.
func (ins *Inspector) Serve(port int) (string, error) {
	var ln net.Listener
	var err error
	for p := port; p < port+20; p++ {
		ln, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, inspectorHTML)
	})
	mux.HandleFunc("/api/exchanges", func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			ID       int    `json:"id"`
			Time     string `json:"time"`
			Method   string `json:"method"`
			Path     string `json:"path"`
			Status   int    `json:"status"`
			Duration string `json:"duration"`
			Size     string `json:"size"`
			Done     bool   `json:"done"`
		}
		var rows []row
		for _, e := range ins.snapshot() {
			rows = append(rows, row{
				ID: e.ID, Time: e.Start.Format("15:04:05"), Method: e.Method,
				Path: e.Path, Status: e.StatusCode,
				Duration: e.Duration.Round(100 * time.Microsecond).String(),
				Size:     byteCount(e.RespSize), Done: e.Done,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
	})
	mux.HandleFunc("/api/exchange", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		e := ins.byID(id)
		if e == nil {
			http.NotFound(w, r)
			return
		}
		out := map[string]any{
			"id": e.ID, "method": e.Method, "path": e.Path, "status": e.StatusCode,
			"duration": e.Duration.String(), "req_header": e.ReqHeader,
			"resp_header": e.RespHeader,
			"req_body":    string(e.ReqBody), "resp_body": string(e.RespBody),
			"req_size": e.ReqSize, "resp_size": e.RespSize,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})

	go http.Serve(ln, mux)
	return "http://" + ln.Addr().String(), nil
}

//go:embed inspector.html
var inspectorHTML string
