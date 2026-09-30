package client

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
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
	maxTapBuffer = 1 << 20  // bytes a tap holds for a lagging parser before giving up
)

// errTapOverflow ends inspection of a connection whose parser fell too far
// behind; the relay itself carries on.
var errTapOverflow = errors.New("inspector fell behind")

// tap receives a copy of one direction of a relayed connection. Unlike an
// io.Pipe, Write never blocks: the bytes are buffered for the parser, and
// if the parser falls maxTapBuffer behind (it can wait on the other
// direction, e.g. for a request body while the app already answers) the tap
// drops inspection instead of stalling traffic.
type tap struct {
	mu      sync.Mutex
	cond    *sync.Cond
	buf     bytes.Buffer
	closed  bool // writer is done: the reader gets EOF once drained
	dropped bool // overflowed: the reader gets errTapOverflow
}

func newTap() *tap {
	t := &tap{}
	t.cond = sync.NewCond(&t.mu)
	return t
}

func (t *tap) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed || t.dropped:
	case t.buf.Len()+len(p) > maxTapBuffer:
		t.dropped = true
		t.buf.Reset()
		t.cond.Broadcast()
	default:
		t.buf.Write(p)
		t.cond.Broadcast()
	}
	return len(p), nil // the relay's copy never fails because of the tap
}

func (t *tap) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for t.buf.Len() == 0 && !t.closed && !t.dropped {
		t.cond.Wait()
	}
	switch {
	case t.dropped:
		return 0, errTapOverflow
	case t.buf.Len() > 0:
		return t.buf.Read(p)
	default:
		return 0, io.EOF
	}
}

// Close marks the end of the relayed stream.
func (t *tap) Close() error {
	t.mu.Lock()
	t.closed = true
	t.cond.Broadcast()
	t.mu.Unlock()
	return nil
}

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
// (responses). Every exit path drains both readers to the end, so a tap
// stops buffering once the parser has given up.
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
		resp, err := readFinalResponse(br, e.Method)
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

// readFinalResponse reads the response that answers a request, skipping
// interim 1xx responses such as 100 Continue (but not 101, which ends HTTP
// on the connection).
func readFinalResponse(br *bufio.Reader, method string) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, err
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

	go http.Serve(ln, localOnly(mux))
	return "http://" + ln.Addr().String(), nil
}

// localOnly refuses requests whose Host is not a loopback name. The UI shows
// captured headers and bodies, and a web page could otherwise read them by
// rebinding its own hostname to 127.0.0.1 (DNS rebinding).
func localOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		switch host {
		case "127.0.0.1", "localhost", "::1":
			h.ServeHTTP(w, r)
		default:
			http.Error(w, "forbidden host", http.StatusForbidden)
		}
	})
}

//go:embed inspector.html
var inspectorHTML string
