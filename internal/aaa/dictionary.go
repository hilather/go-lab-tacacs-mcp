package aaa

import (
	"time"
	"unicode"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
)

// RFC 8907 §8.2 accounting-only argument names, in documented order.
var accountingOnly = []string{
	"task_id",
	"start_time",
	"stop_time",
	"elapsed_time",
	"timezone",
	"event",
	"reason",
	"bytes",
	"bytes_in",
	"bytes_out",
	"paks",
	"paks_in",
	"paks_out",
	"err_msg",
}

var accountingOnlySet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(accountingOnly))
	for _, n := range accountingOnly {
		m[n] = struct{}{}
	}
	return m
}()

// AccountingOnlyName reports whether name is an RFC accounting-only argument.
func AccountingOnlyName(name string) bool {
	_, ok := accountingOnlySet[name]
	return ok
}

// KnownAccountingArgs returns the accounting-only dictionary in documented order.
func KnownAccountingArgs() []string {
	out := make([]string, len(accountingOnly))
	copy(out, accountingOnly)
	return out
}

type parsedAcct struct {
	taskID    string
	args      []acctAV
	startTime *time.Time
	stopTime  *time.Time
}

type acctAV struct {
	pair domain.AVPair
}

func parseAccountingArgs(args domain.AVPairs) (parsedAcct, error) {
	var out parsedAcct
	if len(args) == 0 {
		return out, nil
	}
	out.args = make([]acctAV, 0, len(args))
	var tzName string
	for _, p := range args {
		if err := p.Validate(); err != nil {
			return parsedAcct{}, err
		}
		if err := validateAccountingValue(p); err != nil {
			return parsedAcct{}, err
		}
		if p.Name == "timezone" && tzName == "" {
			tzName = p.Value
		}
		if p.Name == "task_id" && out.taskID == "" {
			out.taskID = p.Value
		}
		out.args = append(out.args, acctAV{pair: p})
	}
	var loc *time.Location
	if tzName != "" {
		var err error
		loc, err = policy.LoadLocation(tzName)
		if err != nil {
			return parsedAcct{}, err
		}
	}
	for _, a := range out.args {
		switch a.pair.Name {
		case "start_time":
			t, err := policy.ParseEpochSeconds(a.pair.Value, loc)
			if err != nil {
				return parsedAcct{}, err
			}
			out.startTime = &t
		case "stop_time":
			t, err := policy.ParseEpochSeconds(a.pair.Value, loc)
			if err != nil {
				return parsedAcct{}, err
			}
			out.stopTime = &t
		}
	}
	return out, nil
}

func validateAccountingValue(p domain.AVPair) error {
	switch p.Name {
	case "task_id", "reason", "err_msg", "event":
		if err := requirePrintable(p.Name, p.Value); err != nil {
			return err
		}
	}
	return policy.ValidatePair(p)
}

func requirePrintable(name, value string) error {
	for _, r := range value {
		if r > unicode.MaxASCII || r < 0x20 || r == 0x7f {
			return domain.NewError(domain.CodeInvalidArgument, "argument must be printable US-ASCII").WithPath(name)
		}
	}
	return nil
}
