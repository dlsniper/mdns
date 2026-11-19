// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipv4mdns              = "224.0.0.251"
	ipv6mdns              = "ff02::fb"
	mdnsPort              = 5353
	forceUnicastResponses = false

	// RFC 6762 section 8.3: "The Multicast DNS responder MUST send at least two
	// unsolicited responses, one second apart."
	announceCount    = 2
	announceInterval = time.Second

	// defaultEnumAddr is where the DNS-SD walk starts for a Zone that is not an
	// Announcer (RFC 6763 section 9).
	defaultEnumAddr = enumPrefix + "local."

	// enumPrefix starts the name of a service type enumeration PTR in any
	// domain (RFC 6763 section 9).
	enumPrefix = "_services._dns-sd._udp."
)

var (
	ipv4Addr = &net.UDPAddr{
		IP:   net.ParseIP(ipv4mdns),
		Port: mdnsPort,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   net.ParseIP(ipv6mdns),
		Port: mdnsPort,
	}
)

// Config is used to configure the mDNS server
type Config struct {
	// Zone must be provided to support responding to queries
	Zone Zone

	// Iface if provided binds the multicast listener to the given
	// interface. If not provided, the system default multicase interface
	// is used.
	Iface *net.Interface

	// LogEmptyResponses indicates the server should print an informative message
	// when there is an mDNS query for which the server has no response.
	LogEmptyResponses bool

	// Logger can optionally be set to use an alternative logger instead of the default.
	Logger *log.Logger
}

// mDNS server is used to listen for mDNS queries and respond if we
// have a matching local record
type Server struct {
	config *Config

	ipv4List *net.UDPConn
	ipv6List *net.UDPConn

	// groups holds the multicast group of each listener that opened; the
	// announcements and the goodbyes go to every one of them.
	groups []*net.UDPAddr

	// send writes a packed message to an address. It is writeTo outside the
	// tests, which replace it so they need no real multicast.
	send func(buf []byte, to *net.UDPAddr) error

	// announcing tracks the announce routine, so Shutdown sends the goodbyes
	// after the last announcement and never before one.
	announcing sync.WaitGroup

	shutdown   atomic.Int32
	shutdownCh chan struct{}
}

// NewServer is used to create a new mDNS server from a config
func NewServer(config *Config) (*Server, error) {
	// Create the listeners
	ipv4List, _ := net.ListenMulticastUDP("udp4", config.Iface, ipv4Addr)
	ipv6List, _ := net.ListenMulticastUDP("udp6", config.Iface, ipv6Addr)

	// Check if we have any listener
	if ipv4List == nil && ipv6List == nil {
		return nil, fmt.Errorf("no multicast listeners could be started")
	}

	if config.Logger == nil {
		config.Logger = log.Default()
	}

	s := &Server{
		config:     config,
		ipv4List:   ipv4List,
		ipv6List:   ipv6List,
		shutdownCh: make(chan struct{}),
	}
	s.send = s.writeTo

	// ListenMulticastUDP joins the group on the interface and turns multicast
	// loopback off. Loopback has to be on for the queriers on this host to get
	// the multicast responses, and the interface multicast is sent from has to
	// be set too, or the responses leave through the system default one.
	if ipv4List != nil {
		p := ipv4.NewPacketConn(ipv4List)
		if err := p.SetMulticastLoopback(true); err != nil {
			config.Logger.Printf("[ERR] mdns: Failed to enable IPv4 multicast loopback: %v", err)
		}
		if config.Iface != nil {
			if err := p.SetMulticastInterface(config.Iface); err != nil {
				config.Logger.Printf("[ERR] mdns: Failed to set the IPv4 multicast interface: %v", err)
			}
		}
		s.groups = append(s.groups, ipv4Addr)
	}
	if ipv6List != nil {
		p := ipv6.NewPacketConn(ipv6List)
		if err := p.SetMulticastLoopback(true); err != nil {
			config.Logger.Printf("[ERR] mdns: Failed to enable IPv6 multicast loopback: %v", err)
		}
		group := *ipv6Addr
		if config.Iface != nil {
			if err := p.SetMulticastInterface(config.Iface); err != nil {
				config.Logger.Printf("[ERR] mdns: Failed to set the IPv6 multicast interface: %v", err)
			}
			group.Zone = config.Iface.Name
		}
		s.groups = append(s.groups, &group)
	}

	s.start()

	return s, nil
}

// start runs the receive routines and the announce routine
func (s *Server) start() {
	if s.ipv4List != nil {
		go s.recv(s.ipv4List)
	}

	if s.ipv6List != nil {
		go s.recv(s.ipv6List)
	}

	s.announcing.Go(s.announce)
}

// Shutdown is used to shutdown the listener
func (s *Server) Shutdown() error {
	if !s.shutdown.CompareAndSwap(0, 1) {
		// something else already closed us
		return nil
	}

	close(s.shutdownCh)

	// RFC 6762 section 10.1: records that stop being valid are sent once more
	// with a TTL of zero, so the caches on the link drop them at once instead
	// of keeping them for the rest of their TTL. The sockets have to still be
	// open for it.
	s.announcing.Wait()
	s.multicast(goodbye(s.announcements()))

	if s.ipv4List != nil {
		s.ipv4List.Close()
	}
	if s.ipv6List != nil {
		s.ipv6List.Close()
	}
	return nil
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv(c *net.UDPConn) {
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	for s.shutdown.Load() == 0 {
		n, from, err := c.ReadFrom(buf)

		if err != nil {
			continue
		}
		if err := s.parsePacket(buf[:n], from); err != nil {
			s.config.Logger.Printf("[ERR] mdns: Failed to handle query: %v", err)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(packet []byte, from net.Addr) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		s.config.Logger.Printf("[ERR] mdns: Failed to unpack packet: %v", err)
		return err
	}
	return s.handleQuery(&msg, from)
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, from net.Addr) error {
	addr, ok := from.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("mdns: received query from non-UDP address %v", from)
	}
	if query.Response {
		// The group also delivers the responses of every responder on the link,
		// this server's own included. Only queries are answered.
		return nil
	}
	if query.Opcode != dns.OpcodeQuery {
		// "In both multicast query and multicast response messages, the OPCODE MUST
		// be zero on transmission (only standard queries are currently supported
		// over multicast).  Multicast DNS messages received with an OPCODE other
		// than zero MUST be silently ignored."  Note: OpcodeQuery == 0
		return fmt.Errorf("mdns: received query with non-zero Opcode %v: %v", query.Opcode, *query)
	}
	if query.Rcode != 0 {
		// "In both multicast query and multicast response messages, the Response
		// Code MUST be zero on transmission.  Multicast DNS messages received with
		// non-zero Response Codes MUST be silently ignored."
		return fmt.Errorf("mdns: received query with non-zero Rcode %v: %v", query.Rcode, *query)
	}

	// TODO(reddaly): Handle "TC (Truncated) Bit":
	//    In query messages, if the TC bit is set, it means that additional
	//    Known-Answer records may be following shortly.  A responder SHOULD
	//    record this fact, and wait for those additional Known-Answer records,
	//    before deciding whether to respond.  If the TC bit is clear, it means
	//    that the querying host has no additional Known Answers.
	if query.Truncated {
		return fmt.Errorf("[ERR] mdns: support for DNS requests with high truncated bit not implemented: %v", *query)
	}

	// RFC 6762 section 6.7: a query from a source port other than 5353 comes
	// from a legacy one-shot querier, which does not listen on the group. Its
	// whole answer goes back by unicast, whatever the unicast bit says.
	legacy := addr.Port != mdnsPort

	var unicastAnswer, multicastAnswer []dns.RR

	// Handle each question
	for _, q := range query.Question {
		mrecs, urecs := s.handleQuestion(q)
		if legacy {
			urecs = append(urecs, mrecs...)
			mrecs = nil
		}
		multicastAnswer = append(multicastAnswer, mrecs...)
		unicastAnswer = append(unicastAnswer, urecs...)
	}

	resp := func(unicast bool) *dns.Msg {
		// 18.1: ID (Query Identifier)
		// 0 for multicast response, query.Id for unicast response
		id := uint16(0)
		answer := multicastAnswer
		if unicast {
			id = query.Id
			answer = unicastAnswer
		}
		if len(answer) == 0 {
			return nil
		}

		msg := newResponse(id, answer)
		if unicast && legacy {
			// RFC 6762 section 6.7: the legacy unicast response "MUST repeat the
			// query ID and the question given in the query message". Every other
			// response carries no question (section 6).
			msg.Question = query.Question
		}
		return msg
	}

	if s.config.LogEmptyResponses && len(multicastAnswer) == 0 && len(unicastAnswer) == 0 {
		questions := make([]string, len(query.Question))
		for i, q := range query.Question {
			questions[i] = q.Name
		}
		s.config.Logger.Printf("no responses for query with questions: %s", strings.Join(questions, ", "))
	}

	if mresp := resp(false); mresp != nil {
		if err := s.sendResponse(mresp, addr, false); err != nil {
			return fmt.Errorf("mdns: error sending multicast response: %v", err)
		}
	}
	if uresp := resp(true); uresp != nil {
		if err := s.sendResponse(uresp, addr, true); err != nil {
			return fmt.Errorf("mdns: error sending unicast response: %v", err)
		}
	}
	return nil
}

// newResponse builds a response message carrying the given answers.
// See section 18 of RFC 6762 for rules about DNS headers.
func newResponse(id uint16, answer []dns.RR) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: id,

			// 18.2: QR (Query/Response) Bit - must be set to 1 in response.
			Response: true,

			// 18.3: OPCODE - must be zero in response (OpcodeQuery == 0)
			Opcode: dns.OpcodeQuery,

			// 18.4: AA (Authoritative Answer) Bit - must be set to 1
			Authoritative: true,

			// The following fields must all be set to 0:
			// 18.5: TC (TRUNCATED) Bit
			// 18.6: RD (Recursion Desired) Bit
			// 18.7: RA (Recursion Available) Bit
			// 18.8: Z (Zero) Bit
			// 18.9: AD (Authentic Data) Bit
			// 18.10: CD (Checking Disabled) Bit
			// 18.11: RCODE (Response Code)
		},
		// 18.12 pertains to questions (handled by handleQuestion)
		// 18.13 pertains to resource records (handled by handleQuestion)

		// 18.14: Name Compression - responses should be compressed (though see
		// caveats in the RFC), so set the Compress bit (part of the dns library
		// API, not part of the DNS packet) to true.
		Compress: true,

		Answer: answer,
	}
}

// handleQuestion is used to handle an incoming question
//
// The response to a question may be transmitted over multicast, unicast, or
// both.  The return values are DNS records for each transmission type.
func (s *Server) handleQuestion(q dns.Question) (multicastRecs, unicastRecs []dns.RR) {
	records := s.config.Zone.Records(q)

	if len(records) == 0 {
		return nil, nil
	}

	// Handle unicast and multicast responses.
	// TODO(reddaly): The decision about sending over unicast vs. multicast is not
	// yet fully compliant with RFC 6762.  For example, the unicast bit should be
	// ignored if the records in question are close to TTL expiration.  For now,
	// we just use the unicast bit to make the decision, as per the spec:
	//     RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	//     Section
	//
	//     In the Question Section of a Multicast DNS query, the top bit of the
	//     qclass field is used to indicate that unicast responses are preferred
	//     for this particular question.  (See Section 5.4.)
	if q.Qclass&(1<<15) != 0 || forceUnicastResponses {
		return nil, records
	}
	return records, nil
}

// sendResponse is used to send a response packet, to the querier when unicast
// is set and to the multicast group the query arrived on otherwise.
func (s *Server) sendResponse(resp *dns.Msg, from *net.UDPAddr, unicast bool) error {
	buf, err := resp.Pack()
	if err != nil {
		return err
	}

	// RFC 6762 section 6: a response goes to the multicast group unless the
	// querier asked for unicast (section 5.4) or is a legacy one (section 6.7).
	// A host can run several mDNS stacks on port 5353, and a unicast packet to
	// that port reaches only one of them.
	to := from
	if !unicast {
		to = groupFor(from)
	}
	return s.send(buf, to)
}

// groupFor returns the multicast group of the address family a query arrived
// on. The IPv6 group is link-local, so it takes the querier's zone.
func groupFor(from *net.UDPAddr) *net.UDPAddr {
	if from.IP.To4() != nil {
		return ipv4Addr
	}
	group := *ipv6Addr
	group.Zone = from.Zone
	return &group
}

// writeTo sends a packet from the listener of the address family of to
func (s *Server) writeTo(buf []byte, to *net.UDPAddr) error {
	c := s.ipv6List
	if to.IP.To4() != nil {
		c = s.ipv4List
	}
	if c == nil {
		return fmt.Errorf("no listener to reach %v", to)
	}
	_, err := c.WriteToUDP(buf, to)
	return err
}

// announce is a routine that sends the zone's records unsolicited, as RFC 6762
// section 8.3 asks of a starting responder. Without it a querier that asked
// before the server started learns of the service only at its next query.
func (s *Server) announce() {
	recs := s.announcements()
	wait := time.Duration(0)
	for range announceCount {
		select {
		case <-s.shutdownCh:
			return
		case <-time.After(wait):
		}
		s.multicast(recs)
		wait = announceInterval
	}
}

// multicast sends the records as an unsolicited response to the multicast
// group of every listener that opened
func (s *Server) multicast(recs []dns.RR) {
	if len(recs) == 0 {
		return
	}
	buf, err := newResponse(0, recs).Pack()
	if err != nil {
		s.config.Logger.Printf("[ERR] mdns: Failed to pack unsolicited response: %v", err)
		return
	}
	for _, group := range s.groups {
		if err := s.send(buf, group); err != nil {
			s.config.Logger.Printf("[ERR] mdns: Failed to send unsolicited response to %v: %v", group, err)
		}
	}
}

// goodbye returns copies of the records with a TTL of zero. The service type
// enumeration PTR is left out: every responder offering the same service type
// on the link owns an identical one, so it is not this server's to withdraw.
func goodbye(recs []dns.RR) []dns.RR {
	byes := make([]dns.RR, 0, len(recs))
	for _, rr := range recs {
		if strings.HasPrefix(rr.Header().Name, enumPrefix) {
			continue
		}
		bye := dns.Copy(rr)
		bye.Header().Ttl = 0
		byes = append(byes, bye)
	}
	return byes
}

// announcements returns the records the zone wants announced. The Zone
// interface can only answer questions, so a zone that is not an Announcer is
// walked the way a DNS-SD browser does it (RFC 6763): from the service type
// enumeration of the default domain, following each PTR to its target and each
// SRV to its host's addresses.
func (s *Server) announcements() []dns.RR {
	if a, ok := s.config.Zone.(Announcer); ok {
		return a.Announcements()
	}

	var recs []dns.RR
	seen := make(map[string]bool)
	asked := make(map[dns.Question]bool)
	questions := []dns.Question{{Name: defaultEnumAddr, Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
	ask := func(name string, qtypes ...uint16) {
		for _, qtype := range qtypes {
			questions = append(questions, dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET})
		}
	}
	for len(questions) > 0 {
		q := questions[0]
		questions = questions[1:]
		if asked[q] {
			continue
		}
		asked[q] = true

		for _, rr := range s.config.Zone.Records(q) {
			if key := rr.String(); !seen[key] {
				seen[key] = true
				recs = append(recs, rr)
			}
			switch rr := rr.(type) {
			case *dns.PTR:
				ask(rr.Ptr, dns.TypeANY)
			case *dns.SRV:
				ask(rr.Target, dns.TypeA, dns.TypeAAAA)
			}
		}
	}
	return recs
}
