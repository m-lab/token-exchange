package store

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/datastore"
)

type mockDatastoreClient struct {
	keys    []*datastore.Key
	apiKeys []APIKey
	err     error
}

func (m *mockDatastoreClient) GetAll(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
	if m.err != nil {
		return nil, m.err
	}
	if apiKeys, ok := dst.(*[]APIKey); ok {
		*apiKeys = m.apiKeys
		return m.keys, nil
	}
	return nil, errors.New("unsupported destination type")
}

func TestDatastoreClient_VerifyAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		keys      []*datastore.Key
		apiKeys   []APIKey
		err       error
		inputKey  string
		wantOrgID string
		wantErr   string
	}{
		{
			name:      "success",
			keys:      []*datastore.Key{datastore.IDKey(APIKeyKind, 1, datastore.NameKey(OrgKind, "org123", nil))},
			apiKeys:   []APIKey{{Key: "the-key"}},
			inputKey:  "the-key",
			wantOrgID: "org123",
		},
		{
			name:     "invalid key",
			keys:     []*datastore.Key{},
			apiKeys:  []APIKey{},
			inputKey: "bad-key",
			wantErr:  "invalid API key",
		},
		{
			name:    "datastore error",
			err:     errors.New("datastore error"),
			wantErr: "failed to query API key: datastore error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDatastoreClient{
				keys:    tt.keys,
				apiKeys: tt.apiKeys,
				err:     tt.err,
			}
			ds := NewDatastoreClientWithAPI(mock, "testns")
			orgID, err := ds.VerifyAPIKey(context.Background(), tt.inputKey)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if orgID != tt.wantOrgID {
					t.Errorf("expected orgID %q, got %q", tt.wantOrgID, orgID)
				}
			}
		})
	}
}
