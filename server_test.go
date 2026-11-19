// Copyright IBM Corp. 2014, 2025
// SPDX-License-Identifier: MIT

package mdns

import (
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
)

func TestServer_StartStop(t *testing.T) {
	// Not a service type real devices have: the goodbye for a shared record
	// makes every other owner on the link announce theirs again (RFC 6762
	// section 10.1), and the next test's client would read those.
	s := makeServiceWithServiceName(t, "_startstop._tcp")
	serv, err := NewServer(&Config{Zone: s})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := serv.Shutdown(); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestServer_Lookup(t *testing.T) {
	serv, err := NewServer(&Config{Zone: makeServiceWithServiceName(t, "_foobar._tcp")})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer func() {
		if err := serv.Shutdown(); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	entries := make(chan *ServiceEntry, 1)
	params := &QueryParam{
		Service:     "_foobar._tcp",
		Domain:      "local",
		Timeout:     50 * time.Millisecond,
		Entries:     entries,
		DisableIPv6: true,
	}
	err = Query(params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// The entry is read once Query has returned: the client keeps writing to
	// an entry it has already delivered when a later packet repeats its
	// records, and the server's announcements are such packets.
	select {
	case e := <-entries:
		if e.Name != "hostname._foobar._tcp.local." {
			t.Fatalf("Entry has the wrong name: %+v", e)
		}
		if e.Port != 80 {
			t.Fatalf("Entry has the wrong port: %+v", e)
		}
		if e.Info != "Local web server" {
			t.Fatalf("Entry as the wrong Info: %+v", e)
		}
	default:
		t.Fatalf("Timed out waiting for response")
	}
}

// sentPacket is a message the server sent and where it sent it.
type sentPacket struct {
	msg *dns.Msg
	to  *net.UDPAddr
}

// sendRecorder stands in for the server's sockets.
type sendRecorder struct {
	mu   sync.Mutex
	sent []sentPacket
}

func (r *sendRecorder) send(buf []byte, to *net.UDPAddr) error {
	msg := new(dns.Msg)
	if err := msg.Unpack(buf); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sentPacket{msg: msg, to: to})
	return nil
}

func (r *sendRecorder) packets() []sentPacket {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent)
}

// makeRecordedServer returns a server with both listeners "open" that sends
// into the returned recorder instead of the network. It is not started.
func makeRecordedServer(t *testing.T, zone Zone) (*Server, *sendRecorder) {
	t.Helper()
	rec := &sendRecorder{}
	return &Server{
		config:     &Config{Zone: zone, Logger: log.Default()},
		groups:     []*net.UDPAddr{ipv4Addr, ipv6Addr},
		send:       rec.send,
		shutdownCh: make(chan struct{}),
	}, rec
}

func rrStrings(recs []dns.RR) []string {
	out := make([]string, len(recs))
	for i, rr := range recs {
		out[i] = rr.String()
	}
	slices.Sort(out)
	return out
}

func TestServer_QueryResponseDestination(t *testing.T) {
	const quBit = 1 << 15
	v6Group := &net.UDPAddr{IP: ipv6Addr.IP, Port: mdnsPort, Zone: "en0"}

	for _, test := range []struct {
		name         string
		from         *net.UDPAddr
		qclass       uint16
		wantTo       *net.UDPAddr
		wantID       uint16
		wantQuestion bool
	}{
		{
			name:   "multicast query on IPv4 is answered on the IPv4 group",
			from:   &net.UDPAddr{IP: net.IPv4(192, 168, 0, 10), Port: mdnsPort},
			qclass: dns.ClassINET,
			wantTo: ipv4Addr,
		},
		{
			name:   "multicast query on IPv6 is answered on the IPv6 group of its link",
			from:   &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: mdnsPort, Zone: "en0"},
			qclass: dns.ClassINET,
			wantTo: v6Group,
		},
		{
			name:   "QU query is answered by unicast with the ID echoed",
			from:   &net.UDPAddr{IP: net.IPv4(192, 168, 0, 10), Port: mdnsPort},
			qclass: dns.ClassINET | quBit,
			wantTo: &net.UDPAddr{IP: net.IPv4(192, 168, 0, 10), Port: mdnsPort},
			wantID: 4242,
		},
		{
			name:         "legacy query is answered by unicast with the ID and the question echoed",
			from:         &net.UDPAddr{IP: net.IPv4(192, 168, 0, 10), Port: 40000},
			qclass:       dns.ClassINET,
			wantTo:       &net.UDPAddr{IP: net.IPv4(192, 168, 0, 10), Port: 40000},
			wantID:       4242,
			wantQuestion: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			serv, rec := makeRecordedServer(t, makeService(t))

			query := new(dns.Msg)
			query.Id = 4242
			query.Question = []dns.Question{{Name: "_http._tcp.local.", Qtype: dns.TypePTR, Qclass: test.qclass}}
			if err := serv.handleQuery(query, test.from); err != nil {
				t.Fatalf("err: %v", err)
			}

			sent := rec.packets()
			if len(sent) != 1 {
				t.Fatalf("sent %d packets, want 1: %+v", len(sent), sent)
			}
			got := sent[0]
			if got.to.String() != test.wantTo.String() {
				t.Fatalf("sent to %v, want %v", got.to, test.wantTo)
			}
			if got.msg.Id != test.wantID {
				t.Fatalf("response ID %d, want %d", got.msg.Id, test.wantID)
			}
			if !got.msg.Response || !got.msg.Authoritative {
				t.Fatalf("response header is not an authoritative response: %+v", got.msg.MsgHdr)
			}
			if len(got.msg.Answer) == 0 {
				t.Fatalf("response has no answers")
			}
			if hasQuestion := len(got.msg.Question) == 1; hasQuestion != test.wantQuestion {
				t.Fatalf("response questions %+v, want echoed: %v", got.msg.Question, test.wantQuestion)
			}
			if test.wantQuestion && got.msg.Question[0] != query.Question[0] {
				t.Fatalf("response question %+v, want %+v", got.msg.Question[0], query.Question[0])
			}
		})
	}
}

func TestServer_IgnoresResponses(t *testing.T) {
	serv, rec := makeRecordedServer(t, makeService(t))

	// A response read back from the group, with a question as a legacy
	// unicast response carries one.
	msg := newResponse(0, nil)
	msg.Question = []dns.Question{{Name: "_http._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
	if err := serv.handleQuery(msg, &net.UDPAddr{IP: net.IPv4(192, 168, 0, 10), Port: mdnsPort}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if sent := rec.packets(); len(sent) != 0 {
		t.Fatalf("answered a response: %+v", sent)
	}
}

// checkUnsolicited checks the packets are one unsolicited response per group
// carrying the service's records with the given TTL.
func checkUnsolicited(t *testing.T, sent []sentPacket, zone *MDNSService, ttl uint32) {
	t.Helper()
	if len(sent) != 2 {
		t.Fatalf("sent %d packets, want one per group: %+v", len(sent), sent)
	}
	want := zone.Announcements()
	if ttl == 0 {
		// A goodbye leaves the shared service type enumeration PTR alone.
		want = slices.DeleteFunc(want, func(rr dns.RR) bool {
			return strings.HasPrefix(rr.Header().Name, enumPrefix)
		})
	}
	for i, rr := range want {
		want[i] = dns.Copy(rr)
		want[i].Header().Ttl = ttl
	}
	for i, group := range []*net.UDPAddr{ipv4Addr, ipv6Addr} {
		got := sent[i]
		if got.to.String() != group.String() {
			t.Fatalf("packet %d sent to %v, want %v", i, got.to, group)
		}
		if got.msg.Id != 0 || !got.msg.Response || !got.msg.Authoritative || len(got.msg.Question) != 0 {
			t.Fatalf("packet %d is not an unsolicited response: %+v", i, got.msg)
		}
		if !slices.Equal(rrStrings(got.msg.Answer), rrStrings(want)) {
			t.Fatalf("packet %d answers:\n%v\nwant:\n%v", i, rrStrings(got.msg.Answer), rrStrings(want))
		}
	}
}

func TestServer_AnnouncesOnStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		zone := makeService(t)
		serv, rec := makeRecordedServer(t, zone)
		serv.start()

		// The first announcement goes out at once, the second a second later.
		synctest.Wait()
		checkUnsolicited(t, rec.packets(), zone, defaultTTL)

		time.Sleep(announceInterval - time.Millisecond)
		synctest.Wait()
		if sent := rec.packets(); len(sent) != 2 {
			t.Fatalf("sent %d packets before the interval passed, want 2", len(sent))
		}

		time.Sleep(time.Millisecond)
		synctest.Wait()
		sent := rec.packets()
		if len(sent) != 4 {
			t.Fatalf("sent %d packets after the interval, want 4", len(sent))
		}
		checkUnsolicited(t, sent[2:], zone, defaultTTL)

		// Nothing more follows the last announcement.
		time.Sleep(10 * announceInterval)
		synctest.Wait()
		if sent := rec.packets(); len(sent) != 4 {
			t.Fatalf("sent %d packets, want 4", len(sent))
		}
	})
}

func TestServer_ShutdownSendsGoodbye(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		zone := makeService(t)
		serv, rec := makeRecordedServer(t, zone)
		serv.start()
		synctest.Wait()

		// Shut down between the two announcements.
		if err := serv.Shutdown(); err != nil {
			t.Fatalf("err: %v", err)
		}
		sent := rec.packets()
		if len(sent) != 4 {
			t.Fatalf("sent %d packets, want one announcement and one goodbye per group", len(sent))
		}
		checkUnsolicited(t, sent[2:], zone, 0)

		// The second announcement must not follow the goodbye, and a second
		// Shutdown must not repeat it.
		if err := serv.Shutdown(); err != nil {
			t.Fatalf("err: %v", err)
		}
		time.Sleep(10 * announceInterval)
		synctest.Wait()
		if sent := rec.packets(); len(sent) != 4 {
			t.Fatalf("sent %d packets after Shutdown, want 4", len(sent))
		}
	})
}

// plainZone hides the Announcer of the Zone it wraps.
type plainZone struct {
	Zone
}

func TestServer_AnnouncementsOfPlainZone(t *testing.T) {
	zone := makeService(t)
	serv, _ := makeRecordedServer(t, plainZone{zone})

	got, want := rrStrings(serv.announcements()), rrStrings(zone.Announcements())
	if !slices.Equal(got, want) {
		t.Fatalf("announcements:\n%v\nwant:\n%v", got, want)
	}
	if len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Fatalf("announcements have duplicates: %v", got)
	}
}
