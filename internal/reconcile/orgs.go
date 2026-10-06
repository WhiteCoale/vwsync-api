package reconcile

import (
	"fmt"
	"strings"

	"vwsync-api/internal/model"
)

// OrgAmbiguousError bedeutet, dass ein Name auf mehrere Organisationen passt, die sich nur in der
// Groß- und Kleinschreibung unterscheiden.
type OrgAmbiguousError struct {
	Key string
	IDs []string
}

func (e *OrgAmbiguousError) Error() string {
	return fmt.Sprintf("organization name %q matches several organizations (%s); use the id", e.Key, strings.Join(e.IDs, ", "))
}

// FindOrg sucht eine Org über ID oder Namen. Die ID muss exakt passen. Ein Name passt ohne Beachtung
// der Groß- und Kleinschreibung, "team alpha" findet also "Team Alpha". Passen so mehrere Orgs,
// gewinnt die exakte Schreibweise. Sonst ist die Suche mehrdeutig, und der Aufrufer muss die ID nehmen.
func FindOrg(orgs []model.Organization, key string) (model.Organization, error) {
	for _, o := range orgs {
		if o.ID == key {
			return o, nil
		}
	}
	var folded, exact []model.Organization
	for _, o := range orgs {
		if strings.EqualFold(o.Name, key) {
			folded = append(folded, o)
			if o.Name == key {
				exact = append(exact, o)
			}
		}
	}
	switch {
	case len(folded) == 1:
		return folded[0], nil
	case len(exact) == 1:
		return exact[0], nil
	case len(folded) == 0:
		return model.Organization{}, &OrgNotFoundError{Key: key}
	}
	ids := make([]string, len(folded))
	for i, o := range folded {
		ids[i] = o.ID
	}
	return model.Organization{}, &OrgAmbiguousError{Key: key, IDs: ids}
}
