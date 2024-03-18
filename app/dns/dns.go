package dns

import (
	"encoding/binary"
	"strings"
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

const (
	TYPE_A     = iota + 1 // a host address
	TYPE_NS               // an authoritative name server
	TYPE_MD               // a mail destination (Obsolete - use MX)
	TYPE_MF               // a mail forwarder (Obsolete - use MX)
	TYPE_CNAME            // the canonical name for an alias
	TYPE_SOA              // marks the start of a zone of authority
	TYPE_MB               // a mailbox domain name (EXPERIMENTAL)
	TYPE_MG               // a mail group member (EXPERIMENTAL)
	TYPE_MR               // a mail rename domain name (EXPERIMENTAL)
	TYPE_NULL             // a null RR (EXPERIMENTAL)
	TYPE_WKS              // a well known service description
	TYPE_PTR              // a domain name pointer
	TYPE_HINFO            // host information
	TYPE_MINFO            // mailbox or mail list information
	TYPE_MX               // mail exchange
	TYPE_TXT              // text strings
)

const (
	CLASS_IN = iota + 1 // the Internet
	CLASS_CS            // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH            // the CHAOS class
	CLASS_HS            // Hesiod
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

// Question represents a DNS message question section.
type Question struct {
	Name  string // Domain name
	Type  uint16 // Record type
	Class uint16 // Class code
}

// Message represents a DNS message.
type Message struct {
	Header
	Question
}

// NewMessage constructs a new DNS message.
func NewMessage() Message {
	return Message{
		Header: Header{
			ID:      1234,
			Flag:    FLAG_QR,
			QDCOUNT: 1,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Question: Question{
			Name:  "codecrafters.io",
			Type:  TYPE_A,
			Class: CLASS_IN,
		},
	}
}

func encodeDomainName(name string) []byte {
	b := make([]byte, 0)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	return b
}

const headerSize = 12

// Byte creates a byte slice containing all the sections of the message.
func (m Message) Byte() []byte {
	b := make([]byte, headerSize)
	// Header section.
	binary.BigEndian.PutUint16(b[0:2], m.Header.ID)
	binary.BigEndian.PutUint16(b[2:4], m.Header.Flag)
	binary.BigEndian.PutUint16(b[4:6], m.Header.QDCOUNT)
	binary.BigEndian.PutUint16(b[6:8], m.Header.ANCOUNT)
	binary.BigEndian.PutUint16(b[8:10], m.Header.NSCOUNT)
	binary.BigEndian.PutUint16(b[10:12], m.Header.ARCOUNT)
	// Question section.
	b = append(b, encodeDomainName(m.Question.Name)...)
	b = binary.BigEndian.AppendUint16(b, m.Question.Type)
	b = binary.BigEndian.AppendUint16(b, m.Question.Class)
	return b
}
