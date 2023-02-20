// #Restls# Begin

package restls

type RestlsFlow struct {
	isClientInbound bool
	numCipherChange int
	backupCipher    any
}

func (r *RestlsFlow) initAsClientInbound() {
	r.isClientInbound = true
}

func (r *RestlsFlow) setBackupCipher(backupCipher ...any) {
	if r.isClientInbound {
		if len(backupCipher) != 1 {
			panic("must provide exact 1 backup cipher")
		}
		r.backupCipher = backupCipher[0]
	}
}

func (r *RestlsFlow) changeCipher() {
	r.numCipherChange += 1
}

func (r *RestlsFlow) expectServerAuth(rType recordType) any {
	if rType != recordTypeChangeCipherSpec && r.isClientInbound && r.numCipherChange == 1 && r.backupCipher != nil {
		cipher := r.backupCipher
		r.backupCipher = nil
		return cipher
	} else {
		return nil
	}
}

// #Restls# End
