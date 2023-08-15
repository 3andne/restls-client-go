// #Restls# Begin

package tls

import (
	"fmt"
	"hash"
	"math/rand"
	"strings"
	"sync/atomic"

	"lukechampine.com/blake3"
)

type RestlsPlugin struct {
	isClient              bool
	isInbound             bool
	numCipherChange       int
	backupCipher          any
	writingClientFinished bool
	clientFinished        []byte
	ConnId                int64
}

func (r *RestlsPlugin) initAsClientInbound(id int64) {
	r.isClient = true
	r.isInbound = true
	r.ConnId = id
}

func (r *RestlsPlugin) initAsClientOutbound(id int64) {
	r.isClient = true
	r.isInbound = false
	r.ConnId = id
}

var IDCounter = atomic.Int64{}

func initRestlsPlugin(inPlugin *RestlsPlugin, outPlugin *RestlsPlugin) {
	id := IDCounter.Add(1)
	inPlugin.initAsClientInbound(id)
	outPlugin.initAsClientOutbound(id)
}

func (r *RestlsPlugin) setBackupCipher(backupCipher ...any) {
	if r.isClient && r.isInbound {
		if len(backupCipher) != 1 {
			panic("must provide exact 1 backup cipher")
		}
		r.backupCipher = backupCipher[0]
	}
}

func (r *RestlsPlugin) changeCipher() {
	debugf(nil, "[%d]RestlsPlugin changeCipher\n", r.ConnId)
	r.numCipherChange += 1
}

func (r *RestlsPlugin) expectServerAuth(rType recordType) any {
	if rType != recordTypeChangeCipherSpec && r.isClient && r.isInbound && r.numCipherChange == 1 && r.backupCipher != nil {
		cipher := r.backupCipher
		r.backupCipher = nil
		return cipher
	} else {
		return nil
	}
}

func (r *RestlsPlugin) captureClientFinished(record []byte) {
	if r.isClient && !r.isInbound && r.writingClientFinished {
		debugf(nil, "[%d]ClientFinished captured %v", r.ConnId, record)
		r.writingClientFinished = false
		r.clientFinished = append([]byte(nil), record...)
	}
}

func (r *RestlsPlugin) WritingClientFinished() {
	if !(r.isClient && !r.isInbound) {
		panic("invalid operation")
	}
	r.writingClientFinished = true
}

func (r *RestlsPlugin) takeClientFinished() []byte {
	if len(r.clientFinished) > 0 {
		ret := r.clientFinished
		r.clientFinished = nil
		return ret
	}
	return nil
}

func RestlsHmac(key []byte) hash.Hash {
	return blake3.New(32, key)
}

type Line struct {
	targetLen TargetLength
	command   restlsCommand
}

type restlsCommand interface {
	toBytes() [2]byte
	needInterrupt() bool
}

type ActResponse int8

func (a ActResponse) toBytes() [2]byte {
	return [2]byte{0x01, byte(a)}
}

func (a ActResponse) needInterrupt() bool {
	return true
}

type ActNoop struct{}

func (a ActNoop) toBytes() [2]byte {
	return [2]byte{0x00, 0}
}

func (a ActNoop) needInterrupt() bool {
	return false
}

func parseCommand(buf []byte) (restlsCommand, error) {
	if buf[0] == 0 {
		return ActNoop{}, nil
	} else if buf[0] == 1 {
		return ActResponse(buf[1]), nil
	} else {
		return nil, fmt.Errorf("unsupported restls command")
	}
}

type TargetLength [2]int16

func (t TargetLength) Len() int {
	if t[1] != 0 {
		return int(t[0] + int16(rand.Intn(int(t[1]))))
	}
	return int(t[0])
}

func parseRecordScript(script string) []Line {
	script_split := strings.Split(strings.ReplaceAll(script, " ", ""), ",")
	lines := []Line{}
	for _, line_raw := range script_split {
		if len(line_raw) == 0 {
			continue
		}
		line_bytes := []byte(line_raw)
		targetLen := TargetLength{getInteger(&line_bytes)}
		if len(line_bytes) == 0 {
			lines = append(lines, Line{targetLen, ActNoop{}})
			continue
		} else if line_bytes[0] == '~' || line_bytes[0] == '?' {
			t := line_bytes[0]
			line_bytes = line_bytes[1:]
			randomRange := getInteger(&line_bytes)
			if int(randomRange)+int(targetLen[0]) > 32768 {
				panic("random target len > 32768")
			}
			targetLen[1] = randomRange
			if t == '?' {
				targetLen[0] = int16(targetLen.Len())
				targetLen[1] = 0
			}
		}

		if len(line_bytes) == 0 {
			lines = append(lines, Line{targetLen, ActNoop{}})
			continue
		} else if line_bytes[0] == '<' {
			line_bytes = line_bytes[1:]
			numResponse := getInteger(&line_bytes)
			lines = append(lines, Line{targetLen, ActResponse(numResponse)})
		} else {
			panic(fmt.Sprintf("invalid script %s, %v", line_raw, line_bytes))
		}
	}
	debugf(nil, "script: %v\n", lines)
	return lines
}

func getInteger(script *[]byte) int16 {
	res := 0
	i := 0
	for i = 0; i < len(*script); i++ {
		b := (*script)[i]
		if b <= '9' && b >= '0' {
			res = res*10 + int(b-'0')
		} else {
			break
		}
		if res > 32768 {
			panic("target len > 32768")
		}
	}
	*script = (*script)[i:]
	return int16(res)
}

var curveIDMap = map[CurveID]int{
	X25519:    0,
	CurveP256: 1,
	CurveP384: 2,
}
var curveIDList = []CurveID{X25519, CurveP256, CurveP384}

var versionMap = map[string]versionHint{
	"tls12": TLS12Hint,
	"tls13": TLS13Hint,
}

var clientIDMap = map[string]*ClientHelloID{
	"chrome":  &HelloChrome_Auto,
	"firefox": &HelloFirefox_Auto,
	"safari":  &HelloSafari_Auto,
	"ios":     &HelloIOS_Auto,
}

var tls12GCMCiphers = []uint16{0xc02f, 0xc02b, 0xc030, 0xc02c}

var defaultRestlsScript = "250?100<1,350~100<1,600~100,300~200,300~100"

const debugLog = true

func debugf(conn *Conn, format string, a ...any) {
	if debugLog {
		if conn != nil {
			fmt.Printf("[%d]"+format, append([]any{conn.in.restlsPlugin.ConnId}, a...)...)
		} else {
			fmt.Printf(format, a...)
		}
	}
}

func NewRestlsConfig(serverName string, password string, versionHintString string, restlsScript string, clientIDStr string) (*Config, error) {
	key := make([]byte, 32)
	blake3.DeriveKey(key, "restls-traffic-key", []byte(password))
	versionHint, ok := versionMap[strings.ToLower(versionHintString)]
	if !ok {
		return nil, fmt.Errorf("invalid version hint: should be either tls12 or tls13")
	}

	sessionTicketsDisabled := true
	if versionHint == TLS12Hint {
		sessionTicketsDisabled = false
	}
	if len(restlsScript) == 0 {
		restlsScript = defaultRestlsScript
	}
	clientIDPtr, ok := clientIDMap[clientIDStr]
	if !ok {
		clientIDPtr = &HelloChrome_Auto
	}
	clientID := atomic.Pointer[ClientHelloID]{}
	clientID.Store(clientIDPtr)
	return &Config{RestlsSecret: key, VersionHint: versionHint, ServerName: serverName, RestlsScript: parseRecordScript(restlsScript), ClientSessionCache: NewLRUClientSessionCache(100), ClientID: &clientID, SessionTicketsDisabled: sessionTicketsDisabled}, nil
}

func AnyTrue[T any](vals []T, predicate func(T) bool) bool {
	for _, v := range vals {
		if predicate(v) {
			return true
		}
	}
	return false
}

// #Restls# End
