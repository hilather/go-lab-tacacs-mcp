package credentials

// SplitCHAPData parses RFC 8907 START data = PPP_id(1) || challenge(N) || response(16).
func SplitCHAPData(data []byte, minChallenge int) (id byte, challenge, response []byte, err error) {
	if minChallenge <= 0 {
		minChallenge = DefaultMinCHAPChallenge
	}
	if len(data) < 1+minChallenge+CHAPResponseLen {
		return 0, nil, nil, malformed()
	}
	n := len(data) - 1 - CHAPResponseLen
	ch := make([]byte, n)
	copy(ch, data[1:1+n])
	resp := make([]byte, CHAPResponseLen)
	copy(resp, data[1+n:])
	return data[0], ch, resp, nil
}

// SplitMSCHAPv1Data parses PPP_id(1) || challenge(8) || response(49).
func SplitMSCHAPv1Data(data []byte) (id byte, challenge, response []byte, err error) {
	return splitMSCHAP(data, MSCHAPv1ChallengeLen)
}

// SplitMSCHAPv2Data parses PPP_id(1) || challenge(16) || response(49).
func SplitMSCHAPv2Data(data []byte) (id byte, challenge, response []byte, err error) {
	return splitMSCHAP(data, MSCHAPv2ChallengeLen)
}

func splitMSCHAP(data []byte, chalLen int) (byte, []byte, []byte, error) {
	want := 1 + chalLen + MSCHAPResponseLen
	if len(data) != want {
		return 0, nil, nil, malformed()
	}
	ch := make([]byte, chalLen)
	copy(ch, data[1:1+chalLen])
	resp := make([]byte, MSCHAPResponseLen)
	copy(resp, data[1+chalLen:])
	return data[0], ch, resp, nil
}
