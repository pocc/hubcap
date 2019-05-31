package dl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/mholt/archiver"
	"github.com/pocc/hubcap/pcap"
)

// UnarchivePcaps will unarchive pcaps from archive f to a folder of the same name before removing f
func UnarchivePcaps(archived string) ([]string, error) {
	fmt.Printf("\033[92mINFO\033[0m Unarchiving %s\n", archived)
	folderName := string(StripArchiveExt(archived))
	if folderName == archived {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Unarchive called for nonarchive %s", archived)
	}
	if err := os.MkdirAll(folderName, 0744); err != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Cannot create folder %s to extract files to. Got error: %s", folderName, err)
	}
	archiveErr := archiver.Unarchive(archived, folderName)
	if archiveErr != nil {
		return nil, fmt.Errorf("\033[93mWARN\033[0m Problem with archive %s.\nError: %s", archived, archiveErr)
	}
	delErr := os.Remove(archived)
	if delErr != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem deleting archive `%s` "+
			"(Do you have permissions?).\nERROR: %s", archived, delErr)
	}
	files, err := WalkArchive(folderName)
	if err != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Could not read archive directory %s", folderName)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("\033[93mWARN\033[0m Archive %s had no pcaps", archived)
	}
	return files, nil
}

// WalkArchive walks an extracted archive
func WalkArchive(startpath string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.Walk(startpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		pcapErr := pcap.IsPcap(path)
		// If a file inside the archive isn't a pcap, skip it silently
		if pcapErr == nil {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		fmt.Println("Problem walking archive recursively", err)
	}
	return files, err
}

// StripArchiveExt removes archive extensions `.tar.gz` and `.bz2` or returns filename otherwise
func StripArchiveExt(fPath string) string {
	archiveRe := regexp.MustCompile(`(.*?)\.(?:n?tar\.gz|bz2|lzma|ntar|rar|tbz2|tgz|tar|xz|zip)$`)
	archiveMatches := archiveRe.FindStringSubmatch(fPath)
	if len(archiveMatches) == 2 {
		return archiveMatches[1]
	}
	return fPath
}
