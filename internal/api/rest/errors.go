package rest

import (
	"encoding/json"
	"net/http"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDomain(w http.ResponseWriter, err error) {
	writeDomainID(w, err, "")
}

func writeDomainID(w http.ResponseWriter, err error, requestID string) {
	de, ok := domain.AsError(err)
	if !ok {
		de = domain.NewError(domain.CodeInternal, "internal error")
	}
	if de.Code == domain.CodeUnauthenticated && w.Header().Get("WWW-Authenticate") == "" {
		w.Header().Set("WWW-Authenticate", auth.BearerRealm)
	}
	writeProblemID(w, statusFor(de.Code), de, requestID)
}

func writeProblem(w http.ResponseWriter, status int, err domain.Error) {
	writeProblemID(w, status, err, "")
}

func writeProblemID(w http.ResponseWriter, status int, err domain.Error, requestID string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{
		"type":   "about:blank",
		"title":  string(err.Code),
		"status": status,
		"detail": err.Message,
		"code":   err.Code,
	}
	if err.Path != "" {
		body["path"] = err.Path
	}
	if requestID != "" {
		body["instance"] = requestID
	}
	_ = json.NewEncoder(w).Encode(body)
}

func statusFor(code domain.Code) int {
	switch code {
	case domain.CodeInvalidArgument:
		return http.StatusBadRequest
	case domain.CodeUnauthenticated:
		return http.StatusUnauthorized
	case domain.CodePermissionDenied:
		return http.StatusForbidden
	case domain.CodeNotFound:
		return http.StatusNotFound
	case domain.CodeAlreadyExists, domain.CodeConflict:
		return http.StatusConflict
	case domain.CodeRevisionMismatch:
		return http.StatusPreconditionFailed
	case domain.CodeRateLimited:
		return http.StatusTooManyRequests
	case domain.CodeUnavailable:
		return http.StatusServiceUnavailable
	case domain.CodeAuthMethodCredentialMissing, domain.CodeClientMatchAmbiguous,
		domain.CodeConfigYAMLInvalid, domain.CodeConfigUnknownField,
		domain.CodeGroupNotFound, domain.CodeObjectLimitExceeded, domain.CodeRegexInvalid,
		domain.CodeSecretFileUnreadable, domain.CodeSharedSecretPolicyViolation:
		return http.StatusBadRequest
	case domain.CodeRevisionConflict:
		return http.StatusPreconditionFailed
	default:
		return http.StatusInternalServerError
	}
}
