package dnsforward

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpd"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/hashprefix"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/safesearch"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testTimeout is the common timeout for tests.
//
// TODO(a.garipov): Use more.
const testTimeout = 1 * time.Second

// testQuestionTarget is the common question target for tests.
//
// TODO(a.garipov): Use more.
const testQuestionTarget = "target.example"

const (
	tlsServerName     = "testdns.adguard.com"
	testMessagesCount = 10
)

// testClientAddr is the common net.Addr for tests.
//
// TODO(a.garipov): Use more.
var testClientAddr net.Addr = &net.TCPAddr{
	IP:   net.IP{1, 2, 3, 4},
	Port: 12345,
}

func startDeferStop(t *testing.T, s *Server) {
	t.Helper()

	err := s.Start()
	require.NoErrorf(t, err, "failed to start server: %s", err)

	testutil.CleanupAndRequireSuccess(t, s.Stop)
}

func createTestServer(
	t *testing.T,
	filterConf *filtering.Config,
	forwardConf ServerConfig,
	localUps upstream.Upstream,
) (s *Server) {
	t.Helper()

	rules := `||nxdomain.example.org
||NULL.example.org^
127.0.0.1	host.example.org
@@||whitelist.example.org^
||127.0.0.255`
	filters := []filtering.Filter{{
		ID: 0, Data: []byte(rules),
	}}

	f, err := filtering.New(filterConf, filters)
	require.NoError(t, err)

	f.SetEnabled(true)

	s, err = NewServer(DNSCreateParams{
		DHCPServer:  testDHCP,
		DNSFilter:   f,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(t, err)

	if forwardConf.BlockingMode == "" {
		forwardConf.BlockingMode = BlockingModeDefault
	}

	err = s.Prepare(&forwardConf)
	require.NoError(t, err)

	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	// TODO(e.burkov):  Try to move it higher.
	if localUps != nil {
		ups := []upstream.Upstream{localUps}
		s.localResolvers.UpstreamConfig.Upstreams = ups
		s.conf.UsePrivateRDNS = true
		s.dnsProxy.PrivateRDNSUpstreamConfig = &proxy.UpstreamConfig{
			Upstreams: ups,
		}
	}

	return s
}

func createServerTLSConfig(t *testing.T) (*tls.Config, []byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoErrorf(t, err, "cannot generate RSA key: %s", err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoErrorf(t, err, "failed to generate serial number: %s", err)

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * timeutil.Day)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AdGuard Tests"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.DNSNames = append(template.DNSNames, tlsServerName)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
	require.NoErrorf(t, err, "failed to create certificate: %s", err)

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoErrorf(t, err, "failed to create certificate: %s", err)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   tlsServerName,
		MinVersion:   tls.VersionTLS12,
	}, certPem, keyPem
}

func createTestTLS(t *testing.T, tlsConf TLSConfig) (s *Server, certPem []byte) {
	t.Helper()

	var keyPem []byte
	_, certPem, keyPem = createServerTLSConfig(t)

	s = createTestServer(t, &filtering.Config{}, ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			EDNSClientSubnet: &EDNSClientSubnet{Enabled: false},
		},
	}, nil)

	tlsConf.CertificateChainData, tlsConf.PrivateKeyData = certPem, keyPem
	s.conf.TLSConfig = tlsConf

	err := s.Prepare(&s.conf)
	require.NoErrorf(t, err, "failed to prepare server: %s", err)

	return s, certPem
}

const googleDomainName = "google-public-dns-a.google.com."

func createGoogleATestMessage() *dns.Msg {
	return createTestMessage(googleDomainName)
}

func newGoogleUpstream() (u upstream.Upstream) {
	return &aghtest.UpstreamMock{
		OnAddress: func() (addr string) { return "google.upstream.example" },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			return aghalg.Coalesce(
				aghtest.MatchedResponse(req, dns.TypeA, googleDomainName, "8.8.8.8"),
				new(dns.Msg).SetRcode(req, dns.RcodeNameError),
			), nil
		},
		OnClose: func() (err error) { return nil },
	}
}

func createTestMessage(host string) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

func createTestMessageWithType(host string, qtype uint16) *dns.Msg {
	req := createTestMessage(host)
	req.Question[0].Qtype = qtype

	return req
}

// newResp returns the new DNS response with response code set to rcode, req
// used as request, and rrs added.
func newResp(rcode int, req *dns.Msg, ans []dns.RR) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, rcode)
	resp.RecursionAvailable = true
	resp.Compress = true
	resp.Answer = ans

	return resp
}

func assertGoogleAResponse(t *testing.T, reply *dns.Msg) {
	assertResponse(t, reply, net.IP{8, 8, 8, 8})
}

func assertResponse(t *testing.T, reply *dns.Msg, ip net.IP) {
	t.Helper()

	require.Lenf(t, reply.Answer, 1, "dns server returned reply with wrong number of answers - %d", len(reply.Answer))

	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "dns server returned wrong answer type instead of A: %v", reply.Answer[0])
	assert.Truef(t, a.A.Equal(ip), "dns server returned wrong answer instead of %s: %s", ip, a.A)
}

// sendTestMessagesAsync sends messages in parallel to check for race issues.
//
//lint:ignore U1000 it's called from the function which is skipped for now.
func sendTestMessagesAsync(t *testing.T, conn *dns.Conn) {
	t.Helper()

	wg := &sync.WaitGroup{}

	for i := 0; i < testMessagesCount; i++ {
		msg := createGoogleATestMessage()
		wg.Add(1)

		go func() {
			defer wg.Done()

			err := conn.WriteMsg(msg)
			require.NoErrorf(t, err, "cannot write message: %s", err)

			res, err := conn.ReadMsg()
			require.NoErrorf(t, err, "cannot read response to message: %s", err)

			assertGoogleAResponse(t, res)
		}()
	}

	wg.Wait()
}

func sendTestMessages(t *testing.T, conn *dns.Conn) {
	t.Helper()

	for i := 0; i < testMessagesCount; i++ {
		req := createGoogleATestMessage()
		err := conn.WriteMsg(req)
		assert.NoErrorf(t, err, "cannot write message #%d: %s", i, err)

		res, err := conn.ReadMsg()
		assert.NoErrorf(t, err, "cannot read response to message #%d: %s", i, err)
		assertGoogleAResponse(t, res)
	}
}

func TestServer(t *testing.T) {
	s := createTestServer(t, &filtering.Config{}, ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			EDNSClientSubnet: &EDNSClientSubnet{Enabled: false},
		},
	}, nil)
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{newGoogleUpstream()}
	startDeferStop(t, s)

	testCases := []struct {
		name  string
		net   string
		proto proxy.Proto
	}{{
		name:  "message_over_udp",
		net:   "",
		proto: proxy.ProtoUDP,
	}, {
		name:  "message_over_tcp",
		net:   "tcp",
		proto: proxy.ProtoTCP,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := s.dnsProxy.Addr(tc.proto)
			client := dns.Client{Net: tc.net}

			reply, _, err := client.Exchange(createGoogleATestMessage(), addr.String())
			require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)

			assertGoogleAResponse(t, reply)
		})
	}
}

func TestServer_timeout(t *testing.T) {
	t.Run("custom", func(t *testing.T) {
		srvConf := &ServerConfig{
			UpstreamTimeout: testTimeout,
			FilteringConfig: FilteringConfig{
				BlockingMode:     BlockingModeDefault,
				EDNSClientSubnet: &EDNSClientSubnet{Enabled: false},
			},
		}

		s, err := NewServer(DNSCreateParams{DNSFilter: &filtering.DNSFilter{}})
		require.NoError(t, err)

		err = s.Prepare(srvConf)
		require.NoError(t, err)

		assert.Equal(t, testTimeout, s.conf.UpstreamTimeout)
	})

	t.Run("default", func(t *testing.T) {
		s, err := NewServer(DNSCreateParams{DNSFilter: &filtering.DNSFilter{}})
		require.NoError(t, err)

		s.conf.FilteringConfig.BlockingMode = BlockingModeDefault
		s.conf.FilteringConfig.EDNSClientSubnet = &EDNSClientSubnet{
			Enabled: false,
		}
		err = s.Prepare(&s.conf)
		require.NoError(t, err)

		assert.Equal(t, DefaultTimeout, s.conf.UpstreamTimeout)
	})
}

func TestServerWithProtectionDisabled(t *testing.T) {
	s := createTestServer(t, &filtering.Config{}, ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			EDNSClientSubnet: &EDNSClientSubnet{Enabled: false},
		},
	}, nil)
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{newGoogleUpstream()}
	startDeferStop(t, s)

	// Message over UDP.
	req := createGoogleATestMessage()
	addr := s.dnsProxy.Addr(proxy.ProtoUDP)
	client := &dns.Client{}

	reply, _, err := client.Exchange(req, addr.String())
	require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)
	assertGoogleAResponse(t, reply)
}

func TestDoTServer(t *testing.T) {
	s, certPem := createTestTLS(t, TLSConfig{
		TLSListenAddrs: []*net.TCPAddr{{}},
	})
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{newGoogleUpstream()}
	startDeferStop(t, s)

	// Add our self-signed generated config to roots.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPem)
	tlsConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}

	// Create a DNS-over-TLS client connection.
	addr := s.dnsProxy.Addr(proxy.ProtoTLS)
	conn, err := dns.DialWithTLS("tcp-tls", addr.String(), tlsConfig)
	require.NoErrorf(t, err, "cannot connect to the proxy: %s", err)

	sendTestMessages(t, conn)
}

func TestDoQServer(t *testing.T) {
	s, _ := createTestTLS(t, TLSConfig{
		QUICListenAddrs: []*net.UDPAddr{{IP: net.IP{127, 0, 0, 1}}},
	})
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{newGoogleUpstream()}
	startDeferStop(t, s)

	// Create a DNS-over-QUIC upstream.
	addr := s.dnsProxy.Addr(proxy.ProtoQUIC)
	opts := &upstream.Options{InsecureSkipVerify: true}
	u, err := upstream.AddressToUpstream(fmt.Sprintf("%s://%s", proxy.ProtoQUIC, addr), opts)
	require.NoError(t, err)

	// Send the test message.
	req := createGoogleATestMessage()
	res, err := u.Exchange(req)
	require.NoError(t, err)

	assertGoogleAResponse(t, res)
}

func TestServerRace(t *testing.T) {
	t.Skip("TODO(e.burkov): inspect the golibs/cache package for locks")

	filterConf := &filtering.Config{
		SafeBrowsingEnabled:   true,
		SafeBrowsingCacheSize: 1000,
		SafeSearchConf:        filtering.SafeSearchConfig{Enabled: true},
		SafeSearchCacheSize:   1000,
		ParentalCacheSize:     1000,
		CacheTime:             30,
	}
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			UpstreamDNS:       []string{"8.8.8.8:53", "8.8.4.4:53"},
		},
		ConfigModified: func() {},
	}
	s := createTestServer(t, filterConf, forwardConf, nil)
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{newGoogleUpstream()}
	startDeferStop(t, s)

	// Message over UDP.
	addr := s.dnsProxy.Addr(proxy.ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoErrorf(t, err, "cannot connect to the proxy: %s", err)

	sendTestMessagesAsync(t, conn)
}

func TestSafeSearch(t *testing.T) {
	resolver := &aghtest.Resolver{
		OnLookupIP: func(_ context.Context, _, host string) (ips []net.IP, err error) {
			ip4, ip6 := aghtest.HostToIPs(host)

			return []net.IP{ip4, ip6}, nil
		},
	}

	safeSearchConf := filtering.SafeSearchConfig{
		Enabled:        true,
		Google:         true,
		Yandex:         true,
		CustomResolver: resolver,
	}

	filterConf := &filtering.Config{
		SafeSearchConf:      safeSearchConf,
		SafeSearchCacheSize: 1000,
		CacheTime:           30,
	}
	safeSearch, err := safesearch.NewDefault(
		safeSearchConf,
		"",
		filterConf.SafeSearchCacheSize,
		time.Minute*time.Duration(filterConf.CacheTime),
	)
	require.NoError(t, err)

	filterConf.SafeSearch = safeSearch
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, filterConf, forwardConf, nil)
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP).String()
	client := &dns.Client{}

	yandexIP := net.IP{213, 180, 193, 56}
	googleIP, _ := aghtest.HostToIPs("forcesafesearch.google.com")

	testCases := []struct {
		host string
		want net.IP
	}{{
		host: "yandex.com.",
		want: yandexIP,
	}, {
		host: "yandex.by.",
		want: yandexIP,
	}, {
		host: "yandex.kz.",
		want: yandexIP,
	}, {
		host: "yandex.ru.",
		want: yandexIP,
	}, {
		host: "www.google.com.",
		want: googleIP,
	}, {
		host: "www.google.com.af.",
		want: googleIP,
	}, {
		host: "www.google.be.",
		want: googleIP,
	}, {
		host: "www.google.by.",
		want: googleIP,
	}}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			req := createTestMessage(tc.host)

			var reply *dns.Msg
			reply, _, err = client.Exchange(req, addr)
			require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)
			assertResponse(t, reply, tc.want)
		})
	}
}

func TestInvalidRequest(t *testing.T) {
	s := createTestServer(t, &filtering.Config{}, ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}, nil)
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP).String()
	req := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
	}

	// Send a DNS request without question.
	_, _, err := (&dns.Client{
		Timeout: testTimeout,
	}).Exchange(&req, addr)

	assert.NoErrorf(t, err, "got a response to an invalid query")
}

func TestBlockedRequest(t *testing.T) {
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeDefault,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, &filtering.Config{}, forwardConf, nil)
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// Default blocking.
	req := createTestMessage("nxdomain.example.org.")

	reply, err := dns.Exchange(req, addr.String())
	require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)

	assert.Equal(t, dns.RcodeSuccess, reply.Rcode)

	require.Len(t, reply.Answer, 1)
	assert.True(t, reply.Answer[0].(*dns.A).A.IsUnspecified())
}

func TestServerCustomClientUpstream(t *testing.T) {
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, &filtering.Config{}, forwardConf, nil)
	s.conf.GetCustomUpstreamByClient = func(_ string) (conf *proxy.UpstreamConfig, err error) {
		ups := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
			return aghalg.Coalesce(
				aghtest.MatchedResponse(req, dns.TypeA, "host", "192.168.0.1"),
				new(dns.Msg).SetRcode(req, dns.RcodeNameError),
			), nil
		})

		return &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		}, nil
	}
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// Send test request.
	req := createTestMessage("host.")

	reply, err := dns.Exchange(req, addr.String())
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeSuccess, reply.Rcode)
	require.NotEmpty(t, reply.Answer)

	require.Len(t, reply.Answer, 1)
	assert.Equal(t, net.IP{192, 168, 0, 1}, reply.Answer[0].(*dns.A).A)
}

// testCNAMEs is a map of names and CNAMEs necessary for the TestUpstream work.
var testCNAMEs = map[string][]string{
	"badhost.":               {"NULL.example.org."},
	"whitelist.example.org.": {"NULL.example.org."},
}

// testIPv4 is a map of names and IPv4s necessary for the TestUpstream work.
var testIPv4 = map[string][]net.IP{
	"NULL.example.org.": {{1, 2, 3, 4}},
	"example.org.":      {{127, 0, 0, 255}},
}

func TestBlockCNAMEProtectionEnabled(t *testing.T) {
	s := createTestServer(t, &filtering.Config{}, ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}, nil)
	testUpstm := &aghtest.Upstream{
		CName: testCNAMEs,
		IPv4:  testIPv4,
	}
	s.conf.ProtectionEnabled = false
	s.dnsProxy.UpstreamConfig = &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{testUpstm},
	}
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// 'badhost' has a canonical name 'NULL.example.org' which should be
	// blocked by filters, but protection is disabled so it is not.
	req := createTestMessage("badhost.")

	reply, err := dns.Exchange(req, addr.String())
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeSuccess, reply.Rcode)
}

func TestBlockCNAME(t *testing.T) {
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeDefault,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, &filtering.Config{}, forwardConf, nil)
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{
		&aghtest.Upstream{
			CName: testCNAMEs,
			IPv4:  testIPv4,
		},
	}
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP).String()

	testCases := []struct {
		name string
		host string
		want bool
	}{{
		name: "block_request",
		host: "badhost.",
		// 'badhost' has a canonical name 'NULL.example.org' which is
		// blocked by filters: response is blocked.
		want: true,
	}, {
		name: "allowed",
		host: "whitelist.example.org.",
		// 'whitelist.example.org' has a canonical name
		// 'NULL.example.org' which is blocked by filters
		// but 'whitelist.example.org' is in a whitelist:
		// response isn't blocked.
		want: false,
	}, {
		name: "block_response",
		host: "example.org.",
		// 'example.org' has a canonical name 'cname1' with IP
		// 127.0.0.255 which is blocked by filters: response is blocked.
		want: true,
	}}

	for _, tc := range testCases {
		req := createTestMessage(tc.host)

		t.Run(tc.name, func(t *testing.T) {
			reply, err := dns.Exchange(req, addr)
			require.NoError(t, err)

			assert.Equal(t, dns.RcodeSuccess, reply.Rcode)
			if tc.want {
				require.Len(t, reply.Answer, 1)

				ans := reply.Answer[0]
				a, ok := ans.(*dns.A)
				require.True(t, ok)

				assert.True(t, a.A.IsUnspecified())
			}
		})
	}
}

func TestClientRulesForCNAMEMatching(t *testing.T) {
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			FilterHandler: func(_ net.IP, _ string, settings *filtering.Settings) {
				settings.FilteringEnabled = false
			},
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, &filtering.Config{}, forwardConf, nil)
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{
		&aghtest.Upstream{
			CName: testCNAMEs,
			IPv4:  testIPv4,
		},
	}
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// 'badhost' has a canonical name 'NULL.example.org' which is blocked by
	// filters: response is blocked.
	req := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Question: []dns.Question{{
			Name:   "badhost.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	// However, in our case it should not be blocked as filtering is
	// disabled on the client level.
	reply, err := dns.Exchange(&req, addr.String())
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeSuccess, reply.Rcode)
}

func TestNullBlockedRequest(t *testing.T) {
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeNullIP,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, &filtering.Config{}, forwardConf, nil)
	startDeferStop(t, s)
	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// Nil filter blocking.
	req := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   "NULL.example.org.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	reply, err := dns.Exchange(&req, addr.String())
	require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)
	require.Lenf(t, reply.Answer, 1, "dns server %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))
	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "dns server %s returned wrong answer type instead of A: %v", addr, reply.Answer[0])
	assert.Truef(t, a.A.IsUnspecified(), "dns server %s returned wrong answer instead of 0.0.0.0: %v", addr, a.A)
}

func TestBlockedCustomIP(t *testing.T) {
	rules := "||nxdomain.example.org^\n||NULL.example.org^\n127.0.0.1	host.example.org\n@@||whitelist.example.org^\n||127.0.0.255\n"
	filters := []filtering.Filter{{
		ID:   0,
		Data: []byte(rules),
	}}

	f, err := filtering.New(&filtering.Config{}, filters)
	require.NoError(t, err)

	s, err := NewServer(DNSCreateParams{
		DHCPServer:  testDHCP,
		DNSFilter:   f,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(t, err)

	conf := &ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeCustomIP,
			BlockingIPv4:      nil,
			UpstreamDNS:       []string{"8.8.8.8:53", "8.8.4.4:53"},
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}

	// Invalid BlockingIPv4.
	err = s.Prepare(conf)
	assert.Error(t, err)

	conf.BlockingIPv4 = net.IP{0, 0, 0, 1}
	conf.BlockingIPv6 = net.ParseIP("::1")

	err = s.Prepare(conf)
	require.NoError(t, err)

	f.SetEnabled(true)
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	req := createTestMessageWithType("NULL.example.org.", dns.TypeA)
	reply, err := dns.Exchange(req, addr.String())
	require.NoError(t, err)

	require.Len(t, reply.Answer, 1)

	a, ok := reply.Answer[0].(*dns.A)
	require.True(t, ok)

	assert.True(t, net.IP{0, 0, 0, 1}.Equal(a.A))

	req = createTestMessageWithType("NULL.example.org.", dns.TypeAAAA)
	reply, err = dns.Exchange(req, addr.String())
	require.NoError(t, err)

	require.Len(t, reply.Answer, 1)

	a6, ok := reply.Answer[0].(*dns.AAAA)
	require.True(t, ok)

	assert.Equal(t, "::1", a6.AAAA.String())
}

func TestBlockedByHosts(t *testing.T) {
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeDefault,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}

	s := createTestServer(t, &filtering.Config{}, forwardConf, nil)
	startDeferStop(t, s)
	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// Hosts blocking.
	req := createTestMessage("host.example.org.")

	reply, err := dns.Exchange(req, addr.String())
	require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)
	require.Lenf(t, reply.Answer, 1, "dns server %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))
	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "dns server %s returned wrong answer type instead of A: %v", addr, reply.Answer[0])
	assert.Equalf(t, net.IP{127, 0, 0, 1}, a.A, "dns server %s returned wrong answer instead of 8.8.8.8: %v", addr, a.A)
}

func TestBlockedBySafeBrowsing(t *testing.T) {
	const (
		hostname  = "wmconvirus.narod.ru"
		cacheTime = 10 * time.Minute
		cacheSize = 10000
	)

	sbChecker := hashprefix.New(&hashprefix.Config{
		CacheTime: cacheTime,
		CacheSize: cacheSize,
		Upstream:  aghtest.NewBlockUpstream(hostname, true),
	})

	ans4, _ := aghtest.HostToIPs(hostname)

	filterConf := &filtering.Config{
		SafeBrowsingEnabled: true,
		SafeBrowsingChecker: sbChecker,
	}
	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			SafeBrowsingBlockHost: ans4.String(),
			ProtectionEnabled:     true,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	s := createTestServer(t, filterConf, forwardConf, nil)
	startDeferStop(t, s)
	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	// SafeBrowsing blocking.
	req := createTestMessage(hostname + ".")

	reply, err := dns.Exchange(req, addr.String())
	require.NoErrorf(t, err, "couldn't talk to server %s: %s", addr, err)
	require.Lenf(t, reply.Answer, 1, "dns server %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))

	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "dns server %s returned wrong answer type instead of A: %v", addr, reply.Answer[0])
	assert.Equal(t, ans4, a.A, "dns server %s returned wrong answer: %v", addr, a.A)
}

func TestRewrite(t *testing.T) {
	c := &filtering.Config{
		Rewrites: []*filtering.LegacyRewrite{{
			Domain: "test.com",
			Answer: "1.2.3.4",
			Type:   dns.TypeA,
		}, {
			Domain: "alias.test.com",
			Answer: "test.com",
			Type:   dns.TypeCNAME,
		}, {
			Domain: "my.alias.example.org",
			Answer: "example.org",
			Type:   dns.TypeCNAME,
		}},
	}
	f, err := filtering.New(c, nil)
	require.NoError(t, err)

	f.SetEnabled(true)

	s, err := NewServer(DNSCreateParams{
		DHCPServer:  testDHCP,
		DNSFilter:   f,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(t, err)

	assert.NoError(t, s.Prepare(&ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeDefault,
			UpstreamDNS:       []string{"8.8.8.8:53"},
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}))

	ups := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
		return aghalg.Coalesce(
			aghtest.MatchedResponse(req, dns.TypeA, "example.org", "4.3.2.1"),
			new(dns.Msg).SetRcode(req, dns.RcodeNameError),
		), nil
	})
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{ups}
	startDeferStop(t, s)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)

	subTestFunc := func(t *testing.T) {
		req := createTestMessageWithType("test.com.", dns.TypeA)
		reply, eerr := dns.Exchange(req, addr.String())
		require.NoError(t, eerr)

		require.Len(t, reply.Answer, 1)

		a, ok := reply.Answer[0].(*dns.A)
		require.True(t, ok)

		assert.True(t, net.IP{1, 2, 3, 4}.Equal(a.A))

		req = createTestMessageWithType("test.com.", dns.TypeAAAA)
		reply, eerr = dns.Exchange(req, addr.String())
		require.NoError(t, eerr)

		assert.Empty(t, reply.Answer)

		req = createTestMessageWithType("alias.test.com.", dns.TypeA)
		reply, eerr = dns.Exchange(req, addr.String())
		require.NoError(t, eerr)

		require.Len(t, reply.Answer, 2)

		assert.Equal(t, "test.com.", reply.Answer[0].(*dns.CNAME).Target)
		assert.True(t, net.IP{1, 2, 3, 4}.Equal(reply.Answer[1].(*dns.A).A))

		req = createTestMessageWithType("my.alias.example.org.", dns.TypeA)
		reply, eerr = dns.Exchange(req, addr.String())
		require.NoError(t, eerr)

		// The original question is restored.
		require.Len(t, reply.Question, 1)

		assert.Equal(t, "my.alias.example.org.", reply.Question[0].Name)

		require.Len(t, reply.Answer, 2)

		assert.Equal(t, "example.org.", reply.Answer[0].(*dns.CNAME).Target)
		assert.Equal(t, dns.TypeA, reply.Answer[1].Header().Rrtype)
	}

	for _, protect := range []bool{true, false} {
		val := protect
		conf := s.getDNSConfig()
		conf.ProtectionEnabled = &val
		s.setConfig(conf)

		t.Run(fmt.Sprintf("protection_is_%t", val), subTestFunc)
	}
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey

	case *ecdsa.PrivateKey:
		return &k.PublicKey

	default:
		return nil
	}
}

var testDHCP = &dhcpd.MockInterface{
	OnStart:   func() (err error) { panic("not implemented") },
	OnStop:    func() (err error) { panic("not implemented") },
	OnEnabled: func() (ok bool) { return true },
	OnLeases: func(flags dhcpd.GetLeasesFlags) (leases []*dhcpd.Lease) {
		return []*dhcpd.Lease{{
			IP:       netip.MustParseAddr("192.168.12.34"),
			HWAddr:   net.HardwareAddr{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
			Hostname: "myhost",
		}}
	},
	OnSetOnLeaseChanged: func(olct dhcpd.OnLeaseChangedT) {},
	OnFindMACbyIP:       func(ip netip.Addr) (mac net.HardwareAddr) { panic("not implemented") },
	OnWriteDiskConfig:   func(c *dhcpd.ServerConfig) { panic("not implemented") },
}

func TestPTRResponseFromDHCPLeases(t *testing.T) {
	const localDomain = "lan"

	flt, err := filtering.New(&filtering.Config{}, nil)
	require.NoError(t, err)

	s, err := NewServer(DNSCreateParams{
		DNSFilter:   flt,
		DHCPServer:  testDHCP,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
		LocalDomain: localDomain,
	})
	require.NoError(t, err)

	s.conf.UDPListenAddrs = []*net.UDPAddr{{}}
	s.conf.TCPListenAddrs = []*net.TCPAddr{{}}
	s.conf.UpstreamDNS = []string{"127.0.0.1:53"}
	s.conf.FilteringConfig.ProtectionEnabled = true
	s.conf.FilteringConfig.BlockingMode = BlockingModeDefault
	s.conf.FilteringConfig.EDNSClientSubnet = &EDNSClientSubnet{Enabled: false}

	err = s.Prepare(&s.conf)
	require.NoError(t, err)

	err = s.Start()
	require.NoError(t, err)
	t.Cleanup(s.Close)

	addr := s.dnsProxy.Addr(proxy.ProtoUDP)
	req := createTestMessageWithType("34.12.168.192.in-addr.arpa.", dns.TypePTR)

	resp, err := dns.Exchange(req, addr.String())
	require.NoErrorf(t, err, "%s", addr)

	require.Len(t, resp.Answer, 1)

	ans := resp.Answer[0]
	assert.Equal(t, dns.TypePTR, ans.Header().Rrtype)
	assert.Equal(t, "34.12.168.192.in-addr.arpa.", ans.Header().Name)

	ptr := testutil.RequireTypeAssert[*dns.PTR](t, ans)

	assert.Equal(t, dns.Fqdn("myhost."+localDomain), ptr.Ptr)
}

func TestPTRResponseFromHosts(t *testing.T) {
	// Prepare test hosts file.

	const hostsFilename = "hosts"

	testFS := fstest.MapFS{
		hostsFilename: &fstest.MapFile{Data: []byte(`
		127.0.0.1   host # comment
		::1         localhost#comment
	`)},
	}

	var eventsCalledCounter uint32
	hc, err := aghnet.NewHostsContainer(0, testFS, &aghtest.FSWatcher{
		OnEvents: func() (e <-chan struct{}) {
			assert.Equal(t, uint32(1), atomic.AddUint32(&eventsCalledCounter, 1))

			return nil
		},
		OnAdd: func(name string) (err error) {
			assert.Equal(t, hostsFilename, name)

			return nil
		},
		OnClose: func() (err error) { panic("not implemented") },
	}, hostsFilename)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.Equal(t, uint32(1), atomic.LoadUint32(&eventsCalledCounter))
	})

	flt, err := filtering.New(&filtering.Config{
		EtcHosts: hc,
	}, nil)
	require.NoError(t, err)

	flt.SetEnabled(true)

	var s *Server
	s, err = NewServer(DNSCreateParams{
		DHCPServer:  testDHCP,
		DNSFilter:   flt,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(t, err)

	s.conf.UDPListenAddrs = []*net.UDPAddr{{}}
	s.conf.TCPListenAddrs = []*net.TCPAddr{{}}
	s.conf.UpstreamDNS = []string{"127.0.0.1:53"}
	s.conf.FilteringConfig.BlockingMode = BlockingModeDefault
	s.conf.FilteringConfig.EDNSClientSubnet = &EDNSClientSubnet{Enabled: false}

	err = s.Prepare(&s.conf)
	require.NoError(t, err)

	err = s.Start()
	require.NoError(t, err)
	t.Cleanup(s.Close)

	subTestFunc := func(t *testing.T) {
		addr := s.dnsProxy.Addr(proxy.ProtoUDP)
		req := createTestMessageWithType("1.0.0.127.in-addr.arpa.", dns.TypePTR)

		resp, eerr := dns.Exchange(req, addr.String())
		require.NoError(t, eerr)

		require.Len(t, resp.Answer, 1)

		assert.Equal(t, dns.TypePTR, resp.Answer[0].Header().Rrtype)
		assert.Equal(t, "1.0.0.127.in-addr.arpa.", resp.Answer[0].Header().Name)

		ptr, ok := resp.Answer[0].(*dns.PTR)
		require.True(t, ok)
		assert.Equal(t, "host.", ptr.Ptr)
	}

	for _, protect := range []bool{true, false} {
		val := protect
		conf := s.getDNSConfig()
		conf.ProtectionEnabled = &val
		s.setConfig(conf)

		t.Run(fmt.Sprintf("protection_is_%t", val), subTestFunc)
	}
}

func TestNewServer(t *testing.T) {
	// TODO(a.garipov): Consider moving away from the text-based error
	// checks and onto a more structured approach.
	testCases := []struct {
		name       string
		in         DNSCreateParams
		wantErrMsg string
	}{{
		name:       "success",
		in:         DNSCreateParams{},
		wantErrMsg: "",
	}, {
		name: "success_local_tld",
		in: DNSCreateParams{
			LocalDomain: "mynet",
		},
		wantErrMsg: "",
	}, {
		name: "success_local_domain",
		in: DNSCreateParams{
			LocalDomain: "my.local.net",
		},
		wantErrMsg: "",
	}, {
		name: "bad_local_domain",
		in: DNSCreateParams{
			LocalDomain: "!!!",
		},
		wantErrMsg: `local domain: bad domain name "!!!": ` +
			`bad top-level domain name label "!!!": ` +
			`bad top-level domain name label rune '!'`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServer(tc.in)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

// doubleTTL is a helper function that returns a clone of DNS PTR with appended
// copy of first answer record with doubled TTL.
func doubleTTL(msg *dns.Msg) (resp *dns.Msg) {
	if msg == nil {
		return nil
	}

	if len(msg.Answer) == 0 {
		return msg
	}

	rec := msg.Answer[0]
	ptr, ok := rec.(*dns.PTR)
	if !ok {
		return msg
	}

	clone := *ptr
	clone.Hdr.Ttl *= 2
	msg.Answer = append(msg.Answer, &clone)

	return msg
}

func TestServer_Exchange(t *testing.T) {
	const (
		onesHost        = "one.one.one.one"
		twosHost        = "two.two.two.two"
		localDomainHost = "local.domain"

		defaultTTL = time.Second * 60
	)

	var (
		onesIP  = netip.MustParseAddr("1.1.1.1")
		twosIP  = netip.MustParseAddr("2.2.2.2")
		localIP = netip.MustParseAddr("192.168.1.1")
	)

	onesRevExtIPv4, err := netutil.IPToReversedAddr(onesIP.AsSlice())
	require.NoError(t, err)

	twosRevExtIPv4, err := netutil.IPToReversedAddr(twosIP.AsSlice())
	require.NoError(t, err)

	extUpstream := &aghtest.UpstreamMock{
		OnAddress: func() (addr string) { return "external.upstream.example" },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			return aghalg.Coalesce(
				aghtest.MatchedResponse(req, dns.TypePTR, onesRevExtIPv4, onesHost),
				doubleTTL(aghtest.MatchedResponse(req, dns.TypePTR, twosRevExtIPv4, twosHost)),
				new(dns.Msg).SetRcode(req, dns.RcodeNameError),
			), nil
		},
	}

	revLocIPv4, err := netutil.IPToReversedAddr(localIP.AsSlice())
	require.NoError(t, err)

	locUpstream := &aghtest.UpstreamMock{
		OnAddress: func() (addr string) { return "local.upstream.example" },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			return aghalg.Coalesce(
				aghtest.MatchedResponse(req, dns.TypePTR, revLocIPv4, localDomainHost),
				new(dns.Msg).SetRcode(req, dns.RcodeNameError),
			), nil
		},
	}

	errUpstream := aghtest.NewErrorUpstream()
	nonPtrUpstream := aghtest.NewBlockUpstream("some-host", true)
	refusingUpstream := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
		return new(dns.Msg).SetRcode(req, dns.RcodeRefused), nil
	})
	zeroTTLUps := &aghtest.UpstreamMock{
		OnAddress: func() (addr string) { return "zero.ttl.example" },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			resp = new(dns.Msg).SetReply(req)
			hdr := dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			resp.Answer = []dns.RR{&dns.PTR{
				Hdr: hdr,
				Ptr: localDomainHost,
			}}

			return resp, nil
		},
	}

	srv := &Server{
		recDetector: newRecursionDetector(0, 1),
		internalProxy: &proxy.Proxy{
			Config: proxy.Config{
				UpstreamConfig: &proxy.UpstreamConfig{
					Upstreams: []upstream.Upstream{extUpstream},
				},
			},
		},
	}

	srv.conf.UsePrivateRDNS = true
	srv.privateNets = netutil.SubnetSetFunc(netutil.IsLocallyServed)

	testCases := []struct {
		req         netip.Addr
		wantErr     error
		locUpstream upstream.Upstream
		name        string
		want        string
		wantTTL     time.Duration
	}{{
		name:        "external_good",
		want:        onesHost,
		wantErr:     nil,
		locUpstream: nil,
		req:         onesIP,
		wantTTL:     defaultTTL,
	}, {
		name:        "local_good",
		want:        localDomainHost,
		wantErr:     nil,
		locUpstream: locUpstream,
		req:         localIP,
		wantTTL:     defaultTTL,
	}, {
		name:        "upstream_error",
		want:        "",
		wantErr:     aghtest.ErrUpstream,
		locUpstream: errUpstream,
		req:         localIP,
		wantTTL:     0,
	}, {
		name:        "empty_answer_error",
		want:        "",
		wantErr:     ErrRDNSNoData,
		locUpstream: locUpstream,
		req:         netip.MustParseAddr("192.168.1.2"),
		wantTTL:     0,
	}, {
		name:        "invalid_answer",
		want:        "",
		wantErr:     ErrRDNSNoData,
		locUpstream: nonPtrUpstream,
		req:         localIP,
		wantTTL:     0,
	}, {
		name:        "refused",
		want:        "",
		wantErr:     ErrRDNSFailed,
		locUpstream: refusingUpstream,
		req:         localIP,
		wantTTL:     0,
	}, {
		name:        "longest_ttl",
		want:        twosHost,
		wantErr:     nil,
		locUpstream: nil,
		req:         twosIP,
		wantTTL:     defaultTTL * 2,
	}, {
		name:        "zero_ttl",
		want:        localDomainHost,
		wantErr:     nil,
		locUpstream: zeroTTLUps,
		req:         localIP,
		wantTTL:     0,
	}}

	for _, tc := range testCases {
		pcfg := proxy.Config{
			UpstreamConfig: &proxy.UpstreamConfig{
				Upstreams: []upstream.Upstream{tc.locUpstream},
			},
		}
		srv.localResolvers = &proxy.Proxy{
			Config: pcfg,
		}

		t.Run(tc.name, func(t *testing.T) {
			host, ttl, eerr := srv.Exchange(tc.req)

			require.ErrorIs(t, eerr, tc.wantErr)
			assert.Equal(t, tc.want, host)
			assert.Equal(t, tc.wantTTL, ttl)
		})
	}

	t.Run("resolving_disabled", func(t *testing.T) {
		srv.conf.UsePrivateRDNS = false
		t.Cleanup(func() { srv.conf.UsePrivateRDNS = true })

		host, _, eerr := srv.Exchange(localIP)

		require.NoError(t, eerr)
		assert.Empty(t, host)
	})
}
