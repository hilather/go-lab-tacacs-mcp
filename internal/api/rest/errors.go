package rest

import (
	"encoding/json"
	"net/http"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDomain(w http.ResponseWriter, err error) {
	de, ok := domain.AsError(err)
	if !ok {
		de = domain.NewError(domain.CodeInternal, "internal error")
	}
	writeProblem(w, statusFor(de.Code), de)
}

func writeProblem(w http.ResponseWriter, status int, err domain.Error) {
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
	default:
		return http.StatusInternalServerError
	}
}
