package main

// RADIUSScenario describes the optional IOL RADIUS / Cisco-AVPair interop path.
// Independent testdata/protocol/radius/cisco fixtures are the PASS evidence.
// This scenario never flips PRJ-CISCO-001 and never vendors IOL.
type RADIUSScenario struct {
	Status string
	Note   string
}

const (
	radiusSkipNote  = "cisco-lab RADIUS/Cisco-AVPair: SKIP without TACLAB_IOL_IMAGE; skip is not Cisco PASS, not RADIUS PASS, and not PRJ-CISCO-001 PASS"
	radiusReadyNote = "cisco-lab RADIUS/Cisco-AVPair: IOL image present; applying iol-radius.cfg.partial is optional. Live IOL is interop only and is not PRJ-CISCO-001 PASS"
)

// RADIUSCiscoAVPairScenario is skip-when-absent. A skip is never PASS.
func RADIUSCiscoAVPairScenario(d Decision) RADIUSScenario {
	if d.Status == StatusSkip {
		return RADIUSScenario{Status: StatusSkip, Note: radiusSkipNote}
	}
	return RADIUSScenario{Status: "optional", Note: radiusReadyNote}
}
