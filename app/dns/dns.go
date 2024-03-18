package dns

import (
	"encoding/binary"
	"strings"
)

const (
	FLAG_RCODE_NOERROR = 0       // Response Code (No Error)
	FLAG_RCODE_NOTIMP  = 4       // Response Code (Not Implemented)
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

// Query represents a single question query.
type Query struct {
	Name  string // Domain name
	Type  uint16 // Record type
	Class uint16 // Class code
}

// Question represents a DNS message question section.
type Question struct {
	Queries []Query
}

// Record represents a single Resource Record (RR).
type Record struct {
	Name  string // Domain name
	Type  uint16 // Record type
	Class uint16 // Class code
	TTL   uint32 // Time-to-live
	Len   uint16 // Data length
	Data  []byte // Data specific to the record type
}

// Answer represents a DNS message answer section.
type Answer struct {
	Records []Record
}

// Message represents a DNS message.
type Message struct {
	Header
	Question
	Answer
}

// NewRequest constructs a new DNS message from an incoming request.
func NewRequest(b []byte) Message {
	m := Message{}
	// Header section.
	m.Header.ID = binary.BigEndian.Uint16(b[0:2])
	m.Header.Flag = binary.BigEndian.Uint16(b[2:4])
	m.Header.QDCOUNT = binary.BigEndian.Uint16(b[4:6])
	m.Header.ANCOUNT = binary.BigEndian.Uint16(b[6:8])
	m.Header.NSCOUNT = binary.BigEndian.Uint16(b[8:10])
	m.Header.ARCOUNT = binary.BigEndian.Uint16(b[10:12])
	// Question section.
	i := headerSize
	m.Question = Question{Queries: make([]Query, m.Header.QDCOUNT)}
	for j := 0; j < int(m.Header.QDCOUNT); j++ {
		m.Question.Queries[j].Name, i = decodeDomainName(b, i)
		m.Question.Queries[j].Type = binary.BigEndian.Uint16(b[i : i+2])
		m.Question.Queries[j].Class = binary.BigEndian.Uint16(b[i+2 : i+4])
		i += 4
	}
	// Answer section.
	m.Answer = Answer{Records: make([]Record, m.Header.ANCOUNT)}
	for j := 0; j < int(m.Header.ANCOUNT); j++ {
		m.Answer.Records[j].Name, i = decodeDomainName(b, i)
		m.Answer.Records[j].Type = binary.BigEndian.Uint16(b[i : i+2])
		m.Answer.Records[j].Class = binary.BigEndian.Uint16(b[i+2 : i+4])
		m.Answer.Records[j].TTL = binary.BigEndian.Uint32(b[i+4 : i+8])
		m.Answer.Records[j].Len = binary.BigEndian.Uint16(b[i+8 : i+10])
		m.Answer.Records[j].Data = make([]byte, m.Answer.Records[j].Len)
		i += 10
		for k := 0; k < int(m.Answer.Records[j].Len); k++ {
			m.Answer.Records[j].Data[k] = b[i+k]
		}
		i += int(m.Answer.Records[j].Len)
	}
	return m
}

// NewResponse constructs a new DNS message in response to an incoming request.
func NewResponse(r Message) Message {
	opcode := r.Header.Flag >> 11 & 0xF
	opcodeFlag := opcode << 11
	rd := r.Header.Flag >> 8 & 0x1
	rdFlag := rd << 8
	var rcodeFlag uint16
	if opcode == 0 {
		rcodeFlag = FLAG_RCODE_NOERROR
	} else {
		rcodeFlag = FLAG_RCODE_NOTIMP
	}
	queries := make([]Query, r.Header.QDCOUNT)
	for i := 0; i < int(r.Header.QDCOUNT); i++ {
		queries[i] = Query{
			Name:  r.Question.Queries[i].Name,
			Type:  TYPE_A,
			Class: CLASS_IN,
		}
	}
	records := make([]Record, r.Header.QDCOUNT)
	for i := 0; i < int(r.Header.QDCOUNT); i++ {
		b := byte(i + 1)
		records[i] = Record{
			Name:  r.Question.Queries[i].Name,
			Type:  TYPE_A,
			Class: CLASS_IN,
			TTL:   60,
			Len:   4,
			Data:  []byte{b, b, b, b},
		}
	}
	m := Message{
		Header: Header{
			ID:      r.Header.ID,
			Flag:    FLAG_QR | opcodeFlag | rdFlag | rcodeFlag,
			QDCOUNT: r.Header.QDCOUNT,
			ANCOUNT: r.Header.QDCOUNT,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Question: Question{Queries: queries},
		Answer:   Answer{Records: records},
	}
	return m
}

func decodeDomainName(b []byte, start int) (string, int) {
	var sb strings.Builder
	i := start
	useCompression := false
	for {
		// Check if the compression pointer indicator exist.
		p := binary.BigEndian.Uint16(b[i : i+2])
		if p&0xC000 == 0xC000 {
			useCompression = true
			offset := p ^ 0xC000
			name, _ := decodeDomainName(b, int(offset))
			sb.WriteString(name)
			i += 2
		} else if b[i] != 0 {
			n := int(b[i])
			sb.Write(b[i+1 : i+1+n])
			i += n + 1
			if b[i] != 0 {
				sb.WriteByte('.')
			}
		} else {
			break
		}
	}
	if useCompression {
		return sb.String(), i
	}
	return sb.String(), i + 1
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
	for _, query := range m.Question.Queries {
		b = append(b, encodeDomainName(query.Name)...)
		b = binary.BigEndian.AppendUint16(b, query.Type)
		b = binary.BigEndian.AppendUint16(b, query.Class)
	}
	// Answer section.
	for _, record := range m.Answer.Records {
		b = append(b, encodeDomainName(record.Name)...)
		b = binary.BigEndian.AppendUint16(b, record.Type)
		b = binary.BigEndian.AppendUint16(b, record.Class)
		b = binary.BigEndian.AppendUint32(b, record.TTL)
		b = binary.BigEndian.AppendUint16(b, record.Len)
		b = append(b, record.Data...)
	}
	return b
}
