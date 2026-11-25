package openvpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

type hTestPKI struct {
	ca        []byte
	serverCrt []byte
	serverKey []byte
	clientCrt []byte
	clientKey []byte
}

func hNewTestPKI(t *testing.T, clientCommonName string) hTestPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, commonName string, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	pki := hTestPKI{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	pki.serverCrt, pki.serverKey = issue(2, "server", x509.ExtKeyUsageServerAuth)
	pki.clientCrt, pki.clientKey = issue(3, clientCommonName, x509.ExtKeyUsageClientAuth)
	return pki
}

type hTestQueue struct {
	write func(buffers []*buf.Buffer)
}

func (q *hTestQueue) WriteBuffers(buffers []*buf.Buffer) { q.write(buffers) }
func (q *hTestQueue) Close() error                       { return nil }

type hTestUser struct {
	username        string
	password        string
	withCertificate bool
}

func hStartTestServer(t *testing.T, pki hTestPKI, protocol string, users map[string]string, verifyClientCertificate string) (*Server, string) {
	t.Helper()
	var listenAddress string
	if protocol == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listenAddress = listener.Addr().String()
		listener.Close()
	} else {
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listenAddress = packetConn.LocalAddr().String()
		packetConn.Close()
	}
	options := ServerOptions{
		Context: context.Background(),
		Mode:    ModeTLS,
		Transport: ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      protocol,
		},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("fd00:8::/64")},
			Topology:     "subnet",
		},
		TLS: ServerTLSOptions{
			CertificateAuthority:    Material{Content: pki.ca},
			Certificate:             Material{Content: pki.serverCrt},
			Key:                     Material{Content: pki.serverKey},
			VerifyClientCertificate: verifyClientCertificate,
		},
		NewOutboundQueue: func(write func(buffers []*buf.Buffer)) OutboundQueue {
			return &hTestQueue{write: write}
		},
	}
	if users != nil {
		options.Authentication.Authenticator = func(_ context.Context, username string, password string) error {
			if expected, found := users[username]; !found || expected != password {
				return ErrAuthenticationFailed
			}
			return nil
		}
	}
	server, err := NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, listenAddress
}

func hStartTestClient(t *testing.T, pki hTestPKI, protocol string, listenAddress string, user hTestUser) (*Client, TunnelConfiguration) {
	t.Helper()
	host, portString, err := net.SplitHostPort(listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	options := ClientOptions{
		Context: context.Background(),
		Mode:    ModeTLS,
		Transport: ClientTransportOptions{
			Remotes:  []Remote{{Host: host, Port: uint16(port), Protocol: protocol}},
			Protocol: protocol,
		},
		TLS:  ClientTLSOptions{CertificateAuthority: Material{Content: pki.ca}},
		Pull: ClientPullOptions{Enabled: true},
	}
	if user.withCertificate {
		options.TLS.Certificate = Material{Content: pki.clientCrt}
		options.TLS.Key = Material{Content: pki.clientKey}
	}
	if user.username != "" {
		options.Authentication.Username = user.username
		options.Authentication.Password = user.password
	}
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		configuration := client.TunnelConfiguration()
		if client.Ready() && len(configuration.LocalIPv4) > 0 && len(configuration.LocalIPv6) > 0 {
			return client, configuration
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the client's tunnel addresses")
	return nil, TunnelConfiguration{}
}

func hTestIPv4Packet(source netip.Addr, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[8] = 64
	packet[9] = 17
	sourceBytes, destinationBytes := source.As4(), destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	copy(packet[20:], payload)
	return packet
}

// The source address of a packet read from the server names the peer that sent it.
func hAssertPacketOwner(t *testing.T, server *Server, client *Client, configuration TunnelConfiguration, expected PeerIdentity) {
	t.Helper()
	source := configuration.LocalIPv4[0].Addr()
	err := client.WriteDataPacket(hTestIPv4Packet(source, netip.MustParseAddr("10.8.0.1"), []byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := server.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(err)
	}
	packetSource, parsed := sourceFromIPPacket(packet.Payload)
	if !parsed || packetSource != source {
		t.Fatalf("packet source %s, want %s", packetSource, source)
	}
	identity, found := server.LookupPeer(packetSource)
	identity.PeerAddress = ""
	if !found || identity != expected {
		t.Fatalf("packet from %s owned by %+v (found %v), want %+v", packetSource, identity, found, expected)
	}
}

func TestH_LookupPeerIdentity(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		protocol     string
		users        map[string]string
		verifyClient string
		user         hTestUser
		want         PeerIdentity
	}{
		{
			name:     "user_and_certificate",
			protocol: "udp",
			users:    map[string]string{"alice": "secret"},
			user:     hTestUser{username: "alice", password: "secret", withCertificate: true},
			want:     PeerIdentity{Username: "alice", CommonName: "client-cert"},
		},
		{
			name:     "certificate_only",
			protocol: "tcp",
			user:     hTestUser{withCertificate: true},
			want:     PeerIdentity{CommonName: "client-cert"},
		},
		{
			name:         "user_only",
			protocol:     "udp",
			users:        map[string]string{"bob": "secret"},
			verifyClient: "none",
			user:         hTestUser{username: "bob", password: "secret"},
			want:         PeerIdentity{Username: "bob"},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			pki := hNewTestPKI(t, "client-cert")
			server, listenAddress := hStartTestServer(t, pki, testCase.protocol, testCase.users, testCase.verifyClient)
			client, configuration := hStartTestClient(t, pki, testCase.protocol, listenAddress, testCase.user)
			for _, address := range []netip.Addr{configuration.LocalIPv4[0].Addr(), configuration.LocalIPv6[0].Addr()} {
				identity, found := server.LookupPeer(address)
				if !found {
					t.Fatalf("no peer owns %s", address)
				}
				if identity.PeerAddress == "" {
					t.Fatalf("no peer address for %s", address)
				}
				identity.PeerAddress = ""
				if identity != testCase.want {
					t.Fatalf("peer of %s is %+v, want %+v", address, identity, testCase.want)
				}
			}
			mapped := netip.AddrFrom16(configuration.LocalIPv4[0].Addr().As16())
			if identity, found := server.LookupPeer(mapped); !found || identity.Name() != testCase.want.Name() {
				t.Fatalf("IPv4-mapped %s: %+v (found %v)", mapped, identity, found)
			}
			hAssertPacketOwner(t, server, client, configuration, testCase.want)
		})
	}
}

func TestH_LookupPeerSeparatesUsers(t *testing.T) {
	t.Parallel()
	pki := hNewTestPKI(t, "client-cert")
	users := map[string]string{"alice": "a", "bob": "b", "carol": "c"}
	server, listenAddress := hStartTestServer(t, pki, "udp", users, "none")
	var waitGroup sync.WaitGroup
	for username, password := range users {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			client, configuration := hStartTestClient(t, pki, "udp", listenAddress, hTestUser{username: username, password: password})
			identity, found := server.LookupPeer(configuration.LocalIPv4[0].Addr())
			if !found || identity.Username != username {
				t.Errorf("%s got the address of %+v (found %v)", username, identity, found)
			}
			_ = client
		}()
	}
	waitGroup.Wait()
}

func TestH_LookupPeerReleased(t *testing.T) {
	t.Parallel()
	pki := hNewTestPKI(t, "client-cert")
	server, listenAddress := hStartTestServer(t, pki, "tcp", map[string]string{"alice": "secret"}, "none")
	client, configuration := hStartTestClient(t, pki, "tcp", listenAddress, hTestUser{username: "alice", password: "secret"})
	address := configuration.LocalIPv4[0].Addr()
	if _, found := server.LookupPeer(address); !found {
		t.Fatalf("no peer owns %s", address)
	}
	if _, found := server.LookupPeer(netip.MustParseAddr("10.8.0.200")); found {
		t.Fatal("an address the pool did not assign has a peer")
	}
	if _, found := server.LookupPeer(netip.Addr{}); found {
		t.Fatal("the invalid address has a peer")
	}
	client.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, found := server.LookupPeer(address); !found {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s still has a peer after the client closed", address)
}

func TestH_LookupPeerStaticKey(t *testing.T) {
	var nilServer *Server
	if _, found := nilServer.LookupPeer(netip.MustParseAddr("10.8.0.2")); found {
		t.Fatal("a nil server has a peer")
	}
	registry := newPeerRouteRegistry()
	registry.Register(netip.MustParseAddr("10.8.0.2"), nil, &hTestQueue{})
	server := &Server{routes: registry}
	if _, found := server.LookupPeer(netip.MustParseAddr("10.8.0.2")); found {
		t.Fatal("a static key peer has an identity")
	}
}
