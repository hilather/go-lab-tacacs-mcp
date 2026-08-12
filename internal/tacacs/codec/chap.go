package codec

import "fmt"

// CHAPData is PPP id || challenge || 16-byte response (RFC 8907 §5.4.2.3).
type CHAPData struct {
	ID        byte
	Challenge []byte
	Response  []byte
}

// DecodeCHAPData splits START data. minChallenge defaults to 8 and is never below 5.
func DecodeCHAPData(data []byte, minChallenge int) (CHAPData, error) {
	if minChallenge <= 0 {
		minChallenge = DefaultCHAPMinChallenge
	}
	if minChallenge < MinCHAPChallenge {
		minChallenge = MinCHAPChallenge
	}
	// id(1) + challenge(N) + response(16)
	if len(data) < 1+minChallenge+CHAPResponseLen {
		return CHAPData{}, fmt.Errorf("%w: len=%d min_challenge=%d", ErrCHAPLength, len(data), minChallenge)
	}
	n := len(data) - 1 - CHAPResponseLen
	ch := make([]byte, n)
	copy(ch, data[1:1+n])
	resp := make([]byte, CHAPResponseLen)
	copy(resp, data[1+n:])
	return CHAPData{ID: data[0], Challenge: ch, Response: resp}, nil
}

// MSCHAPData is PPP id || challenge(8|16) || response(49).
type MSCHAPData struct {
	ID        byte
	Challenge []byte
	Response  []byte
}

// DecodeMSCHAPv1Data requires id(1) || challenge(8) || response(49).
func DecodeMSCHAPv1Data(data []byte) (MSCHAPData, error) {
	return decodeMSCHAP(data, MSCHAPv1ChallengeLen)
}

// DecodeMSCHAPv2Data requires id(1) || challenge(16) || response(49).
func DecodeMSCHAPv2Data(data []byte) (MSCHAPData, error) {
	return decodeMSCHAP(data, MSCHAPv2ChallengeLen)
}

func decodeMSCHAP(data []byte, challengeLen int) (MSCHAPData, error) {
	want := 1 + challengeLen + MSCHAPResponseLen
	if len(data) != want {
		return MSCHAPData{}, fmt.Errorf("%w: len=%d want=%d", ErrMSCHAPLength, len(data), want)
	}
	ch := make([]byte, challengeLen)
	copy(ch, data[1:1+challengeLen])
	resp := make([]byte, MSCHAPResponseLen)
	copy(resp, data[1+challengeLen:])
	return MSCHAPData{ID: data[0], Challenge: ch, Response: resp}, nil
}

// EncodeCHAPData concatenates id || challenge || 16-byte response.
func EncodeCHAPData(d CHAPData) ([]byte, error) {
	if len(d.Response) != CHAPResponseLen {
		return nil, fmt.Errorf("%w: response=%d", ErrCHAPLength, len(d.Response))
	}
	out := make([]byte, 0, 1+len(d.Challenge)+CHAPResponseLen)
	out = append(out, d.ID)
	out = append(out, d.Challenge...)
	out = append(out, d.Response...)
	return out, nil
}

// EncodeMSCHAPData concatenates id || challenge || 49-byte response.
func EncodeMSCHAPData(d MSCHAPData) ([]byte, error) {
	if len(d.Response) != MSCHAPResponseLen {
		return nil, fmt.Errorf("%w: response=%d", ErrMSCHAPLength, len(d.Response))
	}
	switch len(d.Challenge) {
	case MSCHAPv1ChallengeLen, MSCHAPv2ChallengeLen:
	default:
		return nil, fmt.Errorf("%w: challenge=%d", ErrMSCHAPLength, len(d.Challenge))
	}
	out := make([]byte, 0, 1+len(d.Challenge)+MSCHAPResponseLen)
	out = append(out, d.ID)
	out = append(out, d.Challenge...)
	out = append(out, d.Response...)
	return out, nil
}
