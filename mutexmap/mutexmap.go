// Package mutexmap has all of the data structures this program uses
package mutexmap

import (
	"reflect"
	"sync"
)

// PcapInfo stores info about an individual pcap
type PcapInfo struct {
	Filename    string
	Sources     []string
	Description string
	Capinfos    map[string]interface{}
	Protocols   []string
	Ports       map[string][]int
	ErrorStr    string
}

// DataStore is the container for a map
// Taken from https://hackernoon.com/dancing-with-go-s-mutexes-92407ae927bf
// Assumes that a map has concurrent writes but serial reads
type DataStore struct {
	sync.Mutex // ← this mutex protects the cache below
	Cache      map[string]PcapInfo
}

// NewDS is the DataStore constructor
func NewDS() *DataStore {
	return &DataStore{
		Cache: make(map[string]PcapInfo),
	}
}

// Set a set of strings for a key
func (ds *DataStore) Set(hash string, pi *PcapInfo) {
	ds.Lock()
	defer ds.Unlock()
	// If the file has already been analyzed (by hash), add the link so that hubcap does not redownload/reanalyze this file
	_, hashInCache := ds.Cache[hash]
	if hashInCache {
		if reflect.DeepEqual(ds.Cache[hash].Sources, pi.Sources) {
			return // If two PcapInfos are completely equal, adding to cache is a waste
		}
		ds.addSources(hash, pi.Sources)
	} else {
		ds.Cache[hash] = *pi
	}
}

// DeleteFilename removes redundant capinfos filename
func (ds *DataStore) DeleteFilename(hash string, pi *PcapInfo) {
	ds.Lock()
	defer ds.Unlock()
	delete(ds.Cache[hash].Capinfos, "FileName")
}

// Add links to datastore object
func (ds *DataStore) addSources(hash string, addend []string) {
	temp := PcapInfo{
		Filename:    ds.Cache[hash].Filename,
		Sources:     append(ds.Cache[hash].Sources, addend...),
		Description: ds.Cache[hash].Description,
		Capinfos:    ds.Cache[hash].Capinfos,
		Protocols:   ds.Cache[hash].Protocols,
		Ports:       ds.Cache[hash].Ports,
		ErrorStr:    ds.Cache[hash].ErrorStr,
	}
	ds.Cache[hash] = temp
}
