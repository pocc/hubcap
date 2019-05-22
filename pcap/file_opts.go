// Package pcap file operations
package pcap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IsPcap returns whether Wireshark recognizes the file as a capture
func IsPcap(filepath string) error {
	cmd := exec.Command("captype", filepath)
	stdout := new(bytes.Buffer)
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil {
		log.Fatal("captype failed: ", err, " when parsing filepath ", filepath)
	}
	// capinfos output like `/path/to/file.pcap: pcap\n`
	stdout.ReadBytes(' ')
	fileType := string(stdout.Bytes())
	fileType = fileType[:len(fileType)-1] // get rid of trailing newline
	if fileType == "unknown" {
		return fmt.Errorf("\033[93mWARN\033[0m captype: %s is not a recognized capture", filepath)
	}
	return nil
}

// UnCompress untars/unzips files to the same directory
func UnCompress(cFile string) error {
	var err error
	fd, err := os.Open(cFile)
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	switch {
	case strings.HasSuffix(cFile, "tar.gz") || strings.HasSuffix(cFile, ".tgz"):
		_, err = unTgzip(fd)
	case strings.HasSuffix(cFile, ".bz2"):
		err = unBzip2(fd)
	case strings.HasSuffix(cFile, ".zip"):
		err = unZip(fd)
	default:
		return fmt.Errorf("Expected compressed file ending with regex `.(n?tar.gz|tgz|bz2|zip)`, got %s", cFile)
	}
	return err
}

// unTgzip returns a list of files that it extracted and an error.
// If there is an error halfway through, file list will be incomplete
func unTgzip(fileDesc io.Reader) ([]string, error) {
	// Courtesy https://medium.com/@skdomino/taring-untaring-files-in-go-6b07cf56bc07
	fileList := make([]string, 0)
	gzReader, err := gzip.NewReader(fileDesc)
	if err != nil {
		log.Fatal(err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, tarErr := tarReader.Next()

		switch {
		case tarErr == io.EOF:
			return fileList, nil
		case tarErr != nil:
			return fileList, fmt.Errorf("Problem reading next tar file: %s", tarErr)
		case header.Typeflag == tar.TypeDir: // = directory
			os.Mkdir(header.Name, 0755)
		case header.Typeflag == tar.TypeReg: // = regular file
			// If there are directories below file, create them
			fdDir := filepath.Dir(header.Name)
			if _, err := os.Stat(fdDir); os.IsNotExist(err) {
				os.Mkdir(fdDir, 0755)
			}
			fd, err := os.OpenFile(header.Name, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fileList, fmt.Errorf("Error opening file:%s", err)
			}

			if _, err := io.Copy(fd, tarReader); err != nil {
				return fileList, fmt.Errorf("Error writing file:%s", err)
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			fd.Close()
			fileList = append(fileList, header.Name)
		default:
			return fileList, fmt.Errorf("File descriptor %c is of type %s, not file/dir",
				header.Typeflag,
				header.Name,
			)
		}
	}
}

func unBzip2(fileDesc io.Reader) error {
	return nil
}

func unZip(fileDesc io.Reader) error {
	return nil
}
