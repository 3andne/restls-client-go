// #Restls# Begin

package restls

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
}

func (r *RestlsPlugin) initAsClientInbound() {
	r.isClient = true
	r.isInbound = true
}

func (r *RestlsPlugin) initAsClientOutbound() {
	r.isClient = true
	r.isInbound = false
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
}

type ActResponse int8

func (a ActResponse) toBytes() [2]byte {
	return [2]byte{0x01, byte(a)}
}

type ActNoop struct{}

func (a ActNoop) toBytes() [2]byte {
	return [2]byte{0x00, 0}
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
	// fmt.Printf("script: %v", lines)
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

var curveIDMap = map[string]CurveID{
	"CurveP256": CurveP256,
	"CurveP384": CurveP384,
	"CurveP521": CurveP521,
	"X25519":    X25519,
}

var versionMap = map[string]versionHint{
	"tls12": TLS12Hint,
	"tls13": TLS13Hint,
}

var defaultRestlsScript = "250?100<1,350~100<1,600~100,300~200,300~100"

func NewRestlsConfig(serverName string, password string, versionHintString string, CurveIDHintString string, restlsScript string) (*Config, error) {
	key := make([]byte, 32)
	blake3.DeriveKey(key, "restls-traffic-key", []byte(password))
	versionHint, ok := versionMap[versionHintString]
	if !ok {
		return nil, fmt.Errorf("invalid version hint: should be either tls12 or tls13")
	}
	curveIDHint, ok := curveIDMap[CurveIDHintString]
	if !ok && versionHint != TLS13Hint {
		return nil, fmt.Errorf("you must provide a curveIDHint for restls 1.2")
	}
	_hint := atomic.Uint32{}
	_hint.Store(uint32(curveIDHint))
	if len(restlsScript) == 0 {
		restlsScript = defaultRestlsScript
	}
	return &Config{RestlsSecret: key, CurveIDHint: _hint, VersionHint: versionHint, ServerName: serverName, RestlsScript: parseRecordScript(restlsScript), ClientSessionCache: NewLRUClientSessionCache(100)}, nil
}

// #Restls# End
