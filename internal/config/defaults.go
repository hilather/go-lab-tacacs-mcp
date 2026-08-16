package config

import "time"

func defaultDocument() Document {
	return Document{
		SchemaVersion: SchemaVersion,
		Server: Server{
			ShutdownGrace:      15 * time.Second,
			StartupFailureMode: "fail_closed",
			AdminOnly:          false,
			LogLevel:           "info",
		},
		Runtime: Runtime{
			Persistence:            "memory",
			AllowShadowing:         true,
			DeleteBaselineBehavior: "tombstone",
			ReloadOverlayBehavior:  "rebase",
			ResetRequiresScope:     "runtime:reset",
			MaxObjects: MaxObjects{
				Users:     10000,
				Groups:    1000,
				Clients:   2000,
				APITokens: 1000,
			},
		},
		Security: Security{
			AllowEnvironmentSecrets: false,
			StrictSecretFiles:       true,
			LegacySharedSecrets:     defaultSharedSecretPolicy(),
			RADIUSSharedSecrets:     defaultSharedSecretPolicy(),
		},
		Listeners: Listeners{
			LegacyTACACS: defaultTACACSListener("0.0.0.0:4949", 49, true),
			SecureTACACS: SecureTACACSListener{
				TACACSListener: defaultTACACSListener("0.0.0.0:4300", 300, true),
				TLS: SecureTLS{
					MinimumVersion:       "TLS1.3",
					ClientAuthentication: "require_and_verify_certificate",
					Revocation:           Revocation{Mode: "configured_crl"},
					SessionResumption: SessionResumption{
						Enabled:                 true,
						TicketLifetime:          TLSTicketLifetimeEnforced,
						RecheckClientRevocation: true,
					},
					RejectEarlyData: true,
				},
			},
			HTTP: HTTPListener{
				Enabled:             true,
				Bind:                "0.0.0.0:8080",
				ReadHeaderTimeout:   5 * time.Second,
				ReadTimeout:         30 * time.Second,
				WriteTimeout:        30 * time.Second,
				IdleTimeout:         60 * time.Second,
				MaxRequestBodyBytes: 2097152,
				TrustedProxyCIDRs:   []string{},
				TLS:                 HTTPTLS{Enabled: false},
			},
			RADIUSAccess:     defaultRADIUSAccess(),
			RADIUSAccounting: defaultRADIUSAccounting(),
			RADIUSRadSec:     defaultRADIUSRadSec(),
			RADIUSDynAuth:    defaultRADIUSDynAuth(),
		},
		API: API{
			Mode: "lab_static_bearer",
			UISession: UISession{
				Enabled:        true,
				Lifetime:       30 * time.Minute,
				IdleTimeout:    10 * time.Minute,
				CookieSameSite: "strict",
			},
			MCP: MCP{
				AllowedOrigins:     []string{},
				RequireOrigin:      false,
				AllowLegacyClients: false,
			},
			BootstrapTokens: []BootstrapToken{},
			RateLimits: RateLimits{
				Enabled:                          true,
				PerTokenRequestsPerSecond:        50,
				PerTokenBurst:                    100,
				UnauthenticatedRequestsPerSecond: 5,
				UnauthenticatedBurst:             10,
			},
		},
		Limits: Limits{
			MaxUsernameBytes:          253,
			MaxPortBytes:              253,
			MaxRemoteAddressBytes:     253,
			MaxAuthenticationRounds:   16,
			MaxAuthorizationArguments: 256,
			MaxArgumentBytes:          65535,
			MaxCommandBytes:           65535,
			MaxPolicyTraceSteps:       1000,
			MaxEventPayloadBytes:      65536,
		},
		Clients:             []Client{},
		Groups:              []Group{},
		Users:               []User{},
		FallbackRules:       RuleSet{},
		RADIUSPolicies:      []RADIUSPolicy{},
		RADIUSReplyProfiles: []RADIUSReplyProfile{},
		RADIUSDictionaries:  []RADIUSDictionary{},
		Events: Events{
			RingBufferCapacity:              10000,
			IncludeSuccessfulAuthentication: true,
			IncludeFailedAuthentication:     true,
			IncludeAuthorization:            true,
			IncludeAccounting:               true,
			RedactUserInput:                 true,
			Stdout: EventStdout{
				Enabled: true,
				Format:  "json",
			},
		},
		Observability: Observability{
			Metrics: Metrics{
				Enabled:       true,
				Bind:          "127.0.0.1:9090",
				Path:          "/metrics",
				ExposeOnAdmin: false,
			},
		},
	}
}

func defaultSharedSecretPolicy() SharedSecretPolicy {
	return SharedSecretPolicy{
		MinimumLengthCharacters: 16,
		MinimumCharacterClasses: 3,
		RejectKnownWeakValues:   true,
		WarnOnReuse:             true,
		DefaultRotationInterval: 90 * 24 * time.Hour,
		RotationWarningBefore:   14 * 24 * time.Hour,
	}
}

func defaultRADIUSAccess() RADIUSListener {
	return RADIUSListener{
		Enabled:                    false,
		Required:                   false,
		Bind:                       "0.0.0.0:1812",
		Transport:                  RADIUSTransportUDP,
		MaxPacketBytes:             RADIUSMaxPacketBytes,
		QueueCapacity:              2048,
		Workers:                    32,
		WorkerDeadline:             5 * time.Second,
		RetransmissionCacheEntries: 10000,
		RetransmissionCacheBytes:   4 << 20,
		RetransmissionTTL:          15 * time.Second,
		PerSourceRate:              100,
		PerSourceBurst:             200,
		MessageAuthenticator:       RADIUSMessageAuthenticatorRequired,
		LimitProxyState:            true,
		ChallengeTTL:               RADIUSChallengeTTLDefault,
		ChallengeEntries:           RADIUSChallengeEntriesDefault,
		ChallengeBytes:             RADIUSChallengeBytesDefault,
	}
}

func defaultRADIUSAccounting() RADIUSListener {
	return RADIUSListener{
		Enabled:                      false,
		Required:                     false,
		Bind:                         "0.0.0.0:1813",
		Transport:                    RADIUSTransportUDP,
		MaxPacketBytes:               RADIUSMaxPacketBytes,
		QueueCapacity:                2048,
		Workers:                      16,
		WorkerDeadline:               5 * time.Second,
		RetransmissionCacheEntries:   20000,
		RetransmissionCacheBytes:     8 << 20,
		RetransmissionTTL:            60 * time.Second,
		JournalEntries:               20000,
		JournalBytes:                 8 << 20,
		PerSourceRate:                100,
		PerSourceBurst:               200,
		AmbiguousAccountingPerMinute: 60,
		SessionIndexEntries:          DefaultSessionIndexEntries,
		SessionIndexBytes:            DefaultSessionIndexBytes,
		SessionTTL:                   DefaultSessionTTL,
		CoATimeout:                   DefaultCoATimeout,
	}
}

func defaultRADIUSRadSec() RADIUSRadSecListener {
	return RADIUSRadSecListener{
		Enabled:                    false,
		Required:                   false,
		Bind:                       "0.0.0.0:2083",
		Transport:                  EndpointTransportTLS,
		MaxPacketBytes:             RADIUSMaxPacketBytes,
		MaxConnections:             256,
		IdleTimeout:                60 * time.Second,
		HandshakeTimeout:           10 * time.Second,
		RetransmissionCacheEntries: 10000,
		RetransmissionCacheBytes:   4 << 20,
		RetransmissionTTL:          15 * time.Second,
		TLS: SecureTLS{
			MinimumVersion:       "TLS1.3",
			ClientAuthentication: "require_and_verify_certificate",
			Revocation:           Revocation{Mode: "configured_crl"},
			SessionResumption: SessionResumption{
				Enabled:                 true,
				TicketLifetime:          TLSTicketLifetimeEnforced,
				RecheckClientRevocation: true,
			},
			RejectEarlyData: true,
		},
	}
}

func defaultRADIUSDynAuth() RADIUSListener {
	return RADIUSListener{
		Enabled:                    false,
		Required:                   false,
		Bind:                       "0.0.0.0:3799",
		Transport:                  RADIUSTransportUDP,
		MaxPacketBytes:             RADIUSMaxPacketBytes,
		QueueCapacity:              256,
		Workers:                    8,
		WorkerDeadline:             5 * time.Second,
		RetransmissionCacheEntries: 10000,
		RetransmissionCacheBytes:   4 << 20,
		RetransmissionTTL:          15 * time.Second,
		PerSourceRate:              100,
		PerSourceBurst:             200,
		MessageAuthenticator:       RADIUSMessageAuthenticatorRequired,
		ChallengeTTL:               RADIUSChallengeTTLDefault,
		ChallengeEntries:           RADIUSChallengeEntriesDefault,
		ChallengeBytes:             RADIUSChallengeBytesDefault,
	}
}

func defaultTACACSListener(bind string, port int, enabled bool) TACACSListener {
	return TACACSListener{
		Enabled:                  enabled,
		Bind:                     bind,
		AdvertisedPort:           port,
		ReadTimeout:              15 * time.Second,
		WriteTimeout:             15 * time.Second,
		IdleTimeout:              60 * time.Second,
		HandshakeTimeout:         10 * time.Second,
		MaxConnections:           4096,
		MaxSessionsPerConnection: 1024,
		MaxPacketBodyBytes:       65536,
		SingleConnect: SingleConnect{
			Enabled:     true,
			MaxLifetime: 10 * time.Minute,
			IdleTimeout: 60 * time.Second,
		},
	}
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func intOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func int64Or(p *int64, def int64) int64 {
	if p == nil {
		return def
	}
	return *p
}

func floatOr(p *float64, def float64) float64 {
	if p == nil {
		return def
	}
	return *p
}

func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
