package dl

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/mholt/archiver"
)

// UnarchivePcaps will unarchive pcaps from archive f to a folder of the same name before removing f
func UnarchivePcaps(f string) ([]string, error) {
	fmt.Printf("\033[92mINFO\033[0m Unarchiving %s\n", f)
	folderName := StripArchiveExt(f)
	if folderName == f {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Unarchive called for nonarchive %s", f)
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem getting current working directory")
	}
	fullFolderName := dir + "/" + folderName
	archiveErr := archiver.Unarchive(f, fullFolderName)
	if archiveErr != nil {
		return nil, fmt.Errorf("\033[93mWARN\033[0m Unrecognized archive %s.\nError: %s", f, archiveErr)
	}
	delErr := os.Remove(f)
	if delErr != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem deleting archive `%s` (Do you have permissions?).\nERROR: %s", f, delErr)
	}
	files, err := ioutil.ReadDir(fullFolderName)
	if err != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Could not read archive directory %s", fullFolderName)
	}
	newFiles := make([]string, len(files))
	for i, file := range files {
		newFiles[i] = file.Name()
	}
	return newFiles, nil
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
