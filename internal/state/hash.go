package state

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

func hashBaseline(doc *config.Document) string {
	var b strings.Builder
	b.WriteString("v1\n")
	writeUsers(&b, doc.Users)
	writeGroups(&b, doc.Groups)
	writeClients(&b, doc.Clients)
	for _, tok := range doc.API.BootstrapTokens {
		b.WriteString("t\t")
		b.WriteString(tok.ID)
		b.WriteByte('\n')
	}
	return sha256Hex(b.String())
}

func hashOverlay(ov overlay) string {
	var b strings.Builder
	uids := make([]string, 0, len(ov.users))
	for id := range ov.users {
		uids = append(uids, id)
	}
	sort.Strings(uids)
	for _, id := range uids {
		e := ov.users[id]
		b.WriteString("u\t")
		b.WriteString(id)
		b.WriteByte('\t')
		if e.deleted {
			b.WriteString("D\n")
			continue
		}
		b.WriteString(string(e.meta.Source))
		b.WriteByte('\t')
		b.WriteString(e.user.DisplayName)
		b.WriteByte('\t')
		b.WriteString(secretRefKey(e.user.Credentials.Login.Verifier))
		b.WriteByte('\n')
	}
	gids := make([]string, 0, len(ov.groups))
	for id := range ov.groups {
		gids = append(gids, id)
	}
	sort.Strings(gids)
	for _, id := range gids {
		e := ov.groups[id]
		b.WriteString("g\t")
		b.WriteString(id)
		if e.deleted {
			b.WriteString("\tD\n")
			continue
		}
		b.WriteByte('\n')
	}
	cids := make([]string, 0, len(ov.clients))
	for id := range ov.clients {
		cids = append(cids, id)
	}
	sort.Strings(cids)
	for _, id := range cids {
		e := ov.clients[id]
		b.WriteString("c\t")
		b.WriteString(id)
		if e.deleted {
			b.WriteString("\tD\n")
			continue
		}
		b.WriteByte('\t')
		b.WriteString(secretRefKey(e.client.Legacy.SharedSecret))
		b.WriteByte('\n')
	}
	tids := make([]string, 0, len(ov.tokens))
	for id := range ov.tokens {
		tids = append(tids, id)
	}
	sort.Strings(tids)
	for _, id := range tids {
		e := ov.tokens[id]
		b.WriteString("t\t")
		b.WriteString(id)
		if e.deleted {
			b.WriteString("\tD\n")
			continue
		}
		b.WriteByte('\n')
	}
	if ov.fallback != nil {
		b.WriteString("fb\n")
	}
	return sha256Hex(b.String())
}

func writeUsers(b *strings.Builder, users []config.User) {
	for _, u := range users {
		b.WriteString("u\t")
		b.WriteString(u.ID)
		b.WriteByte('\t')
		b.WriteString(u.DisplayName)
		b.WriteByte('\t')
		b.WriteString(strconv.FormatBool(u.Enabled))
		b.WriteByte('\t')
		b.WriteString(secretRefKey(u.Credentials.Login.Verifier))
		b.WriteByte('\n')
	}
}

func writeGroups(b *strings.Builder, groups []config.Group) {
	for _, g := range groups {
		b.WriteString("g\t")
		b.WriteString(g.ID)
		b.WriteByte('\n')
	}
}

func writeClients(b *strings.Builder, clients []config.Client) {
	for _, c := range clients {
		b.WriteString("c\t")
		b.WriteString(c.ID)
		b.WriteByte('\t')
		b.WriteString(secretRefKey(c.Legacy.SharedSecret))
		b.WriteByte('\n')
	}
}

func secretRefKey(r config.SecretRef) string {
	if r.File != "" {
		return "f:" + r.File
	}
	if r.Environment != "" {
		return "e:" + r.Environment
	}
	return "-"
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
