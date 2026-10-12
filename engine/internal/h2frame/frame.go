package h2frame

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var paddingBuckets = [...]int{256, 512, 768, 1024, 1280, 1536}

var framePool = sync.Pool{
	New: func() any {
		return make([]byte, 4+1536)
	},
}

func PaddedLength(n int) int {
	for _, bucket := range paddingBuckets {
		if n <= bucket {
			return bucket
		}
	}
	return n
}

func Write(w io.Writer, packet []byte, pad bool) error {
	packetLen := len(packet)
	if packetLen <= 0 || packetLen > 65535 {
		return fmt.Errorf("MIST stream: invalid packet length %d", packetLen)
	}
	recordLen := packetLen
	if pad {
		recordLen = PaddedLength(packetLen)
	}
	if recordLen > 65535 {
		return fmt.Errorf("MIST stream: invalid record length %d", recordLen)
	}

	need := 4 + recordLen
	frame := framePool.Get().([]byte)
	if cap(frame) < need {
		frame = make([]byte, need)
	} else {
		frame = frame[:need]
	}
	defer framePool.Put(frame[:cap(frame)])

	binary.BigEndian.PutUint16(frame[0:2], uint16(packetLen))
	binary.BigEndian.PutUint16(frame[2:4], uint16(recordLen))
	copy(frame[4:4+packetLen], packet)
	if recordLen > packetLen {
		if _, err := rand.Read(frame[4+packetLen : 4+recordLen]); err != nil {
			return fmt.Errorf("MIST stream: generate padding: %w", err)
		}
	}

	// A single Write is important for streaming transports. In particular,
	// io.Pipe writes are synchronous; splitting header / packet / padding into
	// separate writes creates three hand-offs for every IP packet.
	_, err := w.Write(frame)
	return err
}

func Read(r io.Reader, dst []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	packetLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	recordLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if packetLen <= 0 || recordLen < packetLen {
		return 0, errors.New("MIST stream: malformed packet frame")
	}
	if recordLen > len(dst) {
		if _, err := io.CopyN(io.Discard, r, int64(recordLen)); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("MIST stream: record %d exceeds receive buffer %d", recordLen, len(dst))
	}

	// Read packet and padding in one operation. The caller only observes the
	// first packetLen bytes; trailing padding is overwritten by the next frame.
	if _, err := io.ReadFull(r, dst[:recordLen]); err != nil {
		return 0, err
	}
	return packetLen, nil
}
