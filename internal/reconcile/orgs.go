package reconcile

import (
	"fmt"
	"strings"

	"vwsync-api/internal/model"
)

// OrgAmbiguousError means a name matches several organizations that differ only in letter case.
type OrgAmbiguousError struct {
	Key string
	IDs []string
}

func (e *OrgAmbiguousError) Error() string {
	return fmt.Sprintf("organization name %q matches several organizations (%s); use the id", e.Key, strings.Join(e.IDs, ", "))
}

// FindOrg resolves an org by id or name. The id must match exactly. A name matches without regard to
// letter case, so "team alpha" finds "Team Alpha". If several orgs match that way, an exact spelling
// wins, otherwise the lookup is ambiguous and the caller has to use the id.
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
