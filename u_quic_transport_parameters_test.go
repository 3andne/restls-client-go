package tls

import (
	"bytes"
	"testing"
)

func TestMarshal(t *testing.T) {
	t.Run("Firefox", testTransportParametersFirefox)
}

func testTransportParametersFirefox(t *testing.T) {
	if !bytes.Equal(_inputTransportParametersFirefox.Marshal(), _truthTransportParametersFirefox) {
		t.Errorf("TransportParameters.Marshal() = %v, want %v", _inputTransportParametersFirefox.Marshal(), _truthTransportParametersFirefox)
	}
}

var (
	_inputTransportParametersFirefox = TransportParameters{
		InitialMaxStreamDataBidiRemote(0x100000),
		InitialMaxStreamsBidi(16),
		MaxDatagramFrameSize(1200),
		MaxIdleTimeout(30000),
		ActiveConnectionIDLimit(8),
		&GREASEQUICBit{},
		&VersionInformation{
			ChoosenVersion: 0x00000001,
			AvailableVersions: []uint32{
				0x8acafaea,
				0x00000001,
			},
			LegacyID: true,
		},
		InitialMaxStreamsUni(16),
		&GREASETransportParameter{
			IdOverride: 0xff02de1a,
			ValueOverride: []byte{
				0x43, 0xe8,
			},
		},
		InitialMaxStreamDataBidiLocal(0xc00000),
		InitialMaxStreamDataUni(0x100000),
		InitialSourceConnectionID([]byte{0x53, 0xf0, 0xb2}),
		MaxAckDelay(20),
		InitialMaxData(0x1800000),
		&DisableActiveMigration{},
	}
	_truthTransportParametersFirefox = []byte{
		0x06, 0x04, 0x80, 0x10,
		0x00, 0x00, 0x08, 0x01,
		0x10, 0x20, 0x02, 0x44,
		0xb0, 0x01, 0x04, 0x80,
		0x00, 0x75, 0x30, 0x0e,
		0x01, 0x08, 0x6a, 0xb2,
		0x00, 0x80, 0xff, 0x73,
		0xdb, 0x0c, 0x00, 0x00,
		0x00, 0x01, 0x8a, 0xca,
		0xfa, 0xea, 0x00, 0x00,
		0x00, 0x01, 0x09, 0x01,
		0x10, 0xc0, 0x00, 0x00,
		0x00, 0xff, 0x02, 0xde,
		0x1a, 0x02, 0x43, 0xe8,
		0x05, 0x04, 0x80, 0xc0,
		0x00, 0x00, 0x07, 0x04,
		0x80, 0x10, 0x00, 0x00,
		0x0f, 0x03, 0x53, 0xf0,
		0xb2, 0x0b, 0x01, 0x14,
		0x04, 0x04, 0x81, 0x80,
		0x00, 0x00, 0x0c, 0x00,
	}
)
