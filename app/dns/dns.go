package dns

import (
	"encoding/binary"
)

const (
	FLAG_RCODE_NOERROR = 0       // Response Code (No Error)
	FLAG_Z             = 1 << 4  // Reserved
	FLAG_RA            = 1 << 7  // Recursion Available
	FLAG_RD            = 1 << 8  // Recursion Desired
	FLAG_TC            = 1 << 9  // Truncated Message
	FLAG_AA            = 1 << 10 // Authoritative Answer
	FLAG_OPCODE_QUERY  = 1 << 11 // Operation Code (Query)
	FLAG_QR            = 1 << 15 // Query Response
)

// Header represents a DNS message header section.
type Header struct {
	ID      uint16 // Packet Identifier
	Flag    uint16 // Flag consisting of: QR, OPCODE, AA, TC, RD, RA, Z, and RCODE
	QDCOUNT uint16 // Question Count
	ANCOUNT uint16 // Answer Count
	NSCOUNT uint16 // Authority Count
	ARCOUNT uint16 // Additional Count
}

// Message represents a DNS message.
type Message struct {
	Header
}

// NewMessage constructs a new DNS message.
func NewMessage() Message {
	return Message{
		Header: Header{
			ID:      1234,
			Flag:    FLAG_QR,
			QDCOUNT: 0,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
	}
}

const headerSize = 12

// Byte creates a byte slice containing all the sections of the message.
func (m Message) Byte() []byte {
	b := make([]byte, headerSize)
	binary.BigEndian.PutUint16(b[0:2], m.Header.ID)
	binary.BigEndian.PutUint16(b[2:4], m.Header.Flag)
	binary.BigEndian.PutUint16(b[4:6], m.Header.QDCOUNT)
	binary.BigEndian.PutUint16(b[6:8], m.Header.ANCOUNT)
	binary.BigEndian.PutUint16(b[8:10], m.Header.NSCOUNT)
	binary.BigEndian.PutUint16(b[10:12], m.Header.ARCOUNT)
	return b
}
