package sshserver

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"
)

// maxRecording keeps one session's recording bounded; output past it is
// dropped and the recording says so.
const maxRecording = 30 << 20

// recorder captures session output as an asciinema v2 file: a JSON header
// line, then one [seconds, "o", data] event per write. Input is not
// recorded, so passwords typed at prompts don't end up in recordings.
type recorder struct {
	mu        sync.Mutex
	start     time.Time
	buf       bytes.Buffer
	truncated bool
}

func newRecorder(w Window, term string) *recorder {
	r := &recorder{start: time.Now()}
	cols, rows := w.Cols, w.Rows
	if cols == 0 {
		cols, rows = 80, 24
	}
	hdr := map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": r.start.Unix()}
	if term != "" {
		hdr["env"] = map[string]string{"TERM": term}
	}
	b, _ := json.Marshal(hdr)
	r.buf.Write(b)
	r.buf.WriteByte('\n')
	return r
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.truncated {
		return len(p), nil
	}
	ev, _ := json.Marshal([]any{time.Since(r.start).Seconds(), "o", string(p)})
	if r.buf.Len()+len(ev) > maxRecording {
		r.truncated = true
		ev, _ = json.Marshal([]any{time.Since(r.start).Seconds(), "o", "\r\n[whalescale: recording size limit reached]\r\n"})
	}
	r.buf.Write(ev)
	r.buf.WriteByte('\n')
	return len(p), nil
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}
