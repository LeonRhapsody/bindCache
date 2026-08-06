package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:15353", "listen address")
	flag.Parse()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")})
			}
		}
		_ = w.WriteMsg(m)
	})
	udp := &dns.Server{Addr: *listen, Net: "udp", Handler: handler}
	tcp := &dns.Server{Addr: *listen, Net: "tcp", Handler: handler}
	go func() {
		if err := tcp.ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	fmt.Println("DNS benchmark stub:", *listen)
	if err := udp.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
