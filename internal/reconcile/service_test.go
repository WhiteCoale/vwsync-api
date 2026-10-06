package reconcile

import (
	"context"
	"errors"
	"testing"

	"vwsync-api/internal/model"
)

type createDir struct {
	Directory // nicht implementierte Methoden lösen einen Panic aus, das belegt, dass CreateOrg sie nicht aufruft
	orgs      []model.Organization
	created   []string
}

func (d *createDir) AdminOrganizations(context.Context) ([]model.Organization, error) {
	return d.orgs, nil
}
func (d *createDir) SelfEmail(context.Context) (string, error) { return "me@x.io", nil }
func (d *createDir) CreateOrganization(_ context.Context, name, billing string) (model.Organization, error) {
	d.created = append(d.created, name+"|"+billing)
	return model.Organization{ID: "id1", Name: name}, nil
}

func TestCreateOrg(t *testing.T) {
	d := &createDir{orgs: []model.Organization{{ID: "o1", Name: "Existing"}}}
	s := NewService(d)
	ctx := context.Background()

	var exists *OrgExistsError
	if _, err := s.CreateOrg(ctx, "EXISTING", "", true); !errors.As(err, &exists) {
		t.Fatalf("duplicate (case-insensitive) accepted: %v", err)
	}
	org, err := s.CreateOrg(ctx, "New", "", false)
	if err != nil || org.ID != "" || len(d.created) != 0 {
		t.Fatalf("dry run created something: %+v %v", d.created, err)
	}
	org, err = s.CreateOrg(ctx, "New", "", true)
	if err != nil || org.ID != "id1" || d.created[0] != "New|me@x.io" {
		t.Fatalf("%+v %v %v", org, err, d.created)
	}
	if _, err := s.CreateOrg(ctx, "Other", "fin@x.io", true); err != nil || d.created[1] != "Other|fin@x.io" {
		t.Fatalf("%v %v", err, d.created)
	}
}
