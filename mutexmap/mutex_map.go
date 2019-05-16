package mutexmap

import (
	"sync"
)

// Taken from https://hackernoon.com/dancing-with-go-s-mutexes-92407ae927bf
// Assumes that a map has concurrent writes but serial reads

// DataStore is the container for a map
type DataStore struct {
	sync.Mutex // ← this mutex protects the cache below
	Cache      map[string][]string
}

// NewDS is the DataStore constructor
func NewDS() *DataStore {
	return &DataStore{
		Cache: make(map[string][]string),
	}
}

func (ds *DataStore) set(key string, value []string) {
	ds.Cache[key] = value
}

// Set a set of strings for a key
func (ds *DataStore) Set(key string, value []string) {
	ds.Lock()
	defer ds.Unlock()
	ds.set(key, value)
}
