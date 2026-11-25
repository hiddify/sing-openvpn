package openvpn

import "net/netip"

// PeerIdentity is what a TLS peer of the server authenticated as. It does not change for the
// life of the session: a renegotiation that presents another user name or client certificate is
// refused (lockAuthenticatedUsername, verifyLockedCertificateIdentity).
type PeerIdentity struct {
	// Username is the auth-user-pass user name the server accepted, or "" when the server has no
	// user name authentication.
	Username string
	// CommonName is the subject common name of the client certificate, or "" when the peer sent
	// no certificate or its subject has no common name.
	CommonName string
	// PeerAddress is the transport address the session is bound to.
	PeerAddress string
}

// Name is the name to account the peer's traffic to: its user name, or else its certificate
// common name, as OpenVPN names a client.
func (i PeerIdentity) Name() string {
	if i.Username != "" {
		return i.Username
	}
	return i.CommonName
}

// LookupPeer returns the identity of the TLS peer that owns a tunnel address, which is an address
// the server assigned it from its pool. The server drops every data packet whose source address the
// sending peer does not own (see peerRouteRegistry.SourcesOwnedBy), so the source address of a
// packet read from the server names the peer that sent it. It returns false for an address no
// peer owns and in static key mode, which has no authenticated peer.
func (s *Server) LookupPeer(address netip.Addr) (PeerIdentity, bool) {
	if s == nil || s.routes == nil {
		return PeerIdentity{}, false
	}
	route := s.routes.Lookup(address.Unmap())
	if route.session == nil || route.identity == nil {
		return PeerIdentity{}, false
	}
	return *route.identity, true
}

// peerIdentity is taken once, when the session's addresses are registered: the user name and the
// certificate are locked by then, and the identity goes away with the route.
func (s *tlsServerSession) peerIdentity() *PeerIdentity {
	identity := &PeerIdentity{PeerAddress: s.peerAddress}
	if s.authenticatedUsernameSet {
		identity.Username = s.authenticatedUsername
	}
	if certificateIdentity := s.lockedCertificateIdentity.Load(); certificateIdentity != nil {
		identity.CommonName = certificateIdentity.commonName
	}
	return identity
}

// registerPeer is peerRouteRegistry.Register for a TLS session, keeping who owns the address.
func (r *peerRouteRegistry) registerPeer(address netip.Addr, session *tlsServerSession, identity *PeerIdentity) {
	if !address.IsValid() {
		return
	}
	r.access.Lock()
	defer r.access.Unlock()
	r.routes[address] = peerRoute{
		session:  session.tlsPeerSession,
		queue:    session.outboundQueue,
		identity: identity,
	}
}
