// #Restls# Begin

package restls

import "hash"

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
	return macSHA1(key)
}

// #Restls# End
