package dl

import (
	"fmt"
	"github.com/mholt/archiver"
	"os"
	"regexp"
)

// UnarchivePcaps will unarchive pcaps from archive f to a folder of the same name before removing f
func UnarchivePcaps(f string) ([]string, error) {
	fmt.Printf("\033[92mINFO\033[0m Unarchiving %s\n", f)
	folderName := StripArchiveExt(f)
	osErr := os.Mkdir(folderName, 0644)
	fmt.Printf("\033[92mINFO\033[0m Creating folder %s\n", folderName)
	if osErr != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem creating folder `%s` for archive contents.\nError: %s", folderName, osErr)
	}
	archiveErr := archiver.Unarchive(f, folderName)
	if archiveErr != nil {
		return nil, fmt.Errorf("\033[93mWARN\033[0m Unrecognized archive %s.\nError:%s", f, archiveErr)
	}
	delErr := os.Remove(f)
	if delErr != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem deleting archive `%s` (Do you have permissions?).\nERROR: %s", f, delErr)
	}
	return []string{""}, nil
}

// StripArchiveExt removes archive extensions `.tar.gz` and `.bz2` or returns filename otherwise
func StripArchiveExt(fPath string) string {
	archiveRe := regexp.MustCompile(`(.*?)(?:\.p?cap)?\.(?:n?tar\.gz|bz2|zip|xz|lzma|rar|tbz2|tgz|ntar|tar)$`)
	archiveMatches := archiveRe.FindStringSubmatch(fPath)
	if len(archiveMatches) == 2 {
		return archiveMatches[1]
	}
	return fPath
}
