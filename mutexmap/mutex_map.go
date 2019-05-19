package mutexmap

import (
	"sync"
)

// DataStore is the container for a map
// Taken from https://hackernoon.com/dancing-with-go-s-mutexes-92407ae927bf
// Assumes that a map has concurrent writes but serial reads
type DataStore struct {
	sync.Mutex // ← this mutex protects the cache below
	Cache      map[string]struct{}
}

// NewDS is the DataStore constructor
func NewDS() *DataStore {
	return &DataStore{
		Cache: make(map[string]struct{}),
	}
}

func (ds *DataStore) set(key string, values struct{}) {
	ds.Cache[key] = values
}

// Set a set of strings for a key
func (ds *DataStore) Set(key string, values struct{}) {
	ds.Lock()
	defer ds.Unlock()
	ds.set(key, values)
}
