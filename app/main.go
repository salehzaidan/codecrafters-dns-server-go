package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

func main() {
	resolver := flag.String("resolver", "", "resolver address")
	flag.Parse()

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		log.Fatal("Failed to resolve UDP address:", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal("Failed to bind to address:", err)
	}
	defer udpConn.Close()

	var (
		resolverAddr *net.UDPAddr
		resolverConn *net.UDPConn
	)
	if *resolver != "" {
		resolverAddr, err = net.ResolveUDPAddr("udp", *resolver)
		if err != nil {
			log.Fatal("Failed to resolve resolver UDP address:", err)
		}

		resolverConn, err = net.DialUDP("udp", nil, resolverAddr)
		if err != nil {
			log.Fatal("Failed to dial to resolver address:", err)
		}
		defer resolverConn.Close()
	}

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			continue
		}

		receivedData := buf[:size]
		fmt.Printf("Received %d bytes from %s\n", size, source)

		var res dns.Message
		if *resolver != "" {
			res = handleWithResolver(receivedData, resolverAddr, resolverConn)
		} else {
			req := dns.NewRequest(receivedData)
			res = dns.NewResponse(req, false)
		}

		if size, err = udpConn.WriteToUDP(res.Byte(), source); err != nil {
			fmt.Println("Failed to send response:", err)
		}
		fmt.Printf("Written %d bytes to %s\n", size, source)
	}
}

func forwardRequest(r dns.Message, resolverAddr *net.UDPAddr, resolverConn *net.UDPConn) (dns.Message, error) {
	buf := make([]byte, 512)
	size, err := resolverConn.Write(r.Byte())
	if err != nil {
		return dns.Message{}, fmt.Errorf("resolver: %w", err)
	}
	fmt.Printf("Written %d bytes to %s\n", size, resolverAddr)

	size, _, err = resolverConn.ReadFromUDP(buf)
	if err != nil {
		return dns.Message{}, fmt.Errorf("resolver: %w", err)
	}
	receivedData := buf[:size]
	fmt.Printf("Received %d bytes from %s\n", size, resolverAddr)

	request := dns.NewRequest(receivedData)
	return dns.NewResponse(request, true), nil
}

func handleWithResolver(data []byte, resolverAddr *net.UDPAddr, resolverConn *net.UDPConn) dns.Message {
	req := dns.NewRequest(data)
	if req.Header.QDCOUNT > 1 {
		responses := make([]dns.Message, req.Header.QDCOUNT)
		for i, r := range dns.SplitMessageQuestions(req) {
			res, err := forwardRequest(r, resolverAddr, resolverConn)
			if err != nil {
				fmt.Println(err)
				continue
			}
			responses[i] = res
		}
		return dns.MergeMessageAnswers(responses)
	}

	res, err := forwardRequest(req, resolverAddr, resolverConn)
	if err != nil {
		fmt.Println(err)
	}
	return res
}
