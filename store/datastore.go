// datastore.go - documentation and common datastore types.

// Package store defines datastore types and methods for token-exchange.
//
// This package is public because https://github.com/m-lab/autojoin orgadm tool
// uses the definitions inside this package to interact with datastore.
package store

import (
	"context"
	"errors"

	"cloud.google.com/go/datastore"
)

var (
	// ErrInvalidKey is returned when the API key is not found in Datastore
	ErrInvalidKey = errors.New("invalid API key")
)

// DatastoreClient is an interface for interacting with Datastore.
type DatastoreClient interface {
	Put(ctx context.Context, key *datastore.Key, src any) (*datastore.Key, error)
	Get(ctx context.Context, key *datastore.Key, dst any) error
	GetAll(ctx context.Context, q *datastore.Query, dst any) ([]*datastore.Key, error)
}
