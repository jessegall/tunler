package client

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestCaptureBody(t *testing.T) {
	small := io.NopCloser(strings.NewReader("hello"))
	body, size, err := captureBody(small)
	if err != nil || string(body) != "hello" || size != 5 {
		t.Fatalf("small body: %q, %d, %v", body, size, err)
	}

	big := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), maxBodyKeep+500)))
	body, size, err = captureBody(big)
	if err != nil {
		t.Fatalf("big body: %v", err)
	}
	if len(body) != maxBodyKeep {
		t.Fatalf("kept %d bytes, want cap %d", len(body), maxBodyKeep)
	}
	if size != int64(maxBodyKeep+500) {
		t.Fatalf("size = %d, want %d (must count drained bytes)", size, maxBodyKeep+500)
	}

	if body, size, err := captureBody(nil); body != nil || size != 0 || err != nil {
		t.Fatalf("nil body: %q, %d, %v", body, size, err)
	}
}

func TestObserve(t *testing.T) {
	ins := NewInspector()

	reqStream := "POST /webhook?x=1 HTTP/1.1\r\nHost: my-app.example.com\r\nContent-Length: 7\r\n\r\npayload"
	respStream := "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"

	done := make(chan struct{})
	go func() {
		ins.observe(strings.NewReader(reqStream), strings.NewReader(respStream))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observe did not finish")
	}

	exchanges := ins.snapshot()
	if len(exchanges) != 1 {
		t.Fatalf("got %d exchanges, want 1", len(exchanges))
	}
	e := exchanges[0]
	if e.Method != "POST" || e.Path != "/webhook?x=1" {
		t.Errorf("request = %s %s", e.Method, e.Path)
	}
	if string(e.ReqBody) != "payload" {
		t.Errorf("req body = %q", e.ReqBody)
	}
	if !e.Done || e.StatusCode != 201 || string(e.RespBody) != "ok" {
		t.Errorf("response = done:%v %d %q", e.Done, e.StatusCode, e.RespBody)
	}
	if e.RespHeader.Get("Content-Type") != "text/plain" {
		t.Errorf("resp header lost: %v", e.RespHeader)
	}
}

func TestObserveGarbageDoesNotBlock(t *testing.T) {
	ins := NewInspector()
	done := make(chan struct{})
	go func() {
		// Non-HTTP bytes must be drained without stalling the relay.
		ins.observe(strings.NewReader("not http at all"), strings.NewReader("garbage"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observe blocked on garbage input")
	}
}

func TestRingBuffer(t *testing.T) {
	ins := NewInspector()
	for i := 0; i < maxExchanges+50; i++ {
		ins.add(&Exchange{})
	}
	if got := len(ins.snapshot()); got != maxExchanges {
		t.Fatalf("ring size = %d, want %d", got, maxExchanges)
	}
	if first := ins.snapshot()[0].ID; first != 51 {
		t.Fatalf("oldest kept ID = %d, want 51", first)
	}
}

func TestByteCount(t *testing.T) {
	cases := map[int64]string{0: "0B", 512: "512B", 2048: "2.0KB", 3 << 20: "3.0MB"}
	for in, want := range cases {
		if got := byteCount(in); got != want {
			t.Errorf("byteCount(%d) = %q, want %q", in, got, want)
		}
	}
}
