// Package pcap file operations
package pcap

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
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

// UnCompress untars/unzips files to target directory
// Returns a map of uncompressed filename(s) to SHA256 checksum, err
func UnCompress(cFile string, destDir string) (map[string][]byte, error) {
	var err error
	var fileList map[string][]byte
	fd, err := os.Open(cFile)
	if err != nil {
		return fileList, fmt.Errorf("Could not open file `%s`", cFile)
	}
	defer fd.Close()

	switch {
	case strings.HasSuffix(cFile, "tar.gz") || strings.HasSuffix(cFile, ".tgz"):
		fileList, err = unTgzip(fd, destDir)
	case strings.HasSuffix(cFile, ".bz2"):
		dirlessFile := filepath.Base(cFile)
		targetFile := destDir + dirlessFile[:len(dirlessFile)-4]
		fileList, err = unBzip2(fd, targetFile)
	case strings.HasSuffix(cFile, ".zip"):
		fileList, err = unZip(cFile, destDir)
	default:
		return fileList, fmt.Errorf("Expected compressed file ending with regex `.(n?tar.gz|tgz|bz2|zip)`, got %s", cFile)
	}
	return fileList, err
}

// unTgzip returns a list of files that it extracted and an error.
// If there is an error halfway through, file list will be incomplete
func unTgzip(fileDesc io.Reader, destDir string) (map[string][]byte, error) {
	// Modified from https://medium.com/@skdomino/taring-untaring-files-in-go-6b07cf56bc07
	fileList := make(map[string][]byte)
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
			dir := destDir + "/" + header.Name
			os.Mkdir(dir, 0755)
		case header.Typeflag == tar.TypeReg: // = regular file
			// If there are directories below file, create them
			fdpath := destDir + "/" + header.Name
			fdDir := filepath.Dir(fdpath)
			if _, err := os.Stat(fdDir); os.IsNotExist(err) {
				os.Mkdir(fdDir, 0755)
			}
			fd, err := os.OpenFile(fdpath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fileList, fmt.Errorf("Error opening file:%s", err)
			}
			// Duplicate file stream so that it can be both written and hashed
			var buf bytes.Buffer
			tee := io.TeeReader(tarReader, &buf)
			if _, err := io.Copy(fd, tee); err != nil {
				return fileList, fmt.Errorf("Error writing file: %s", err)
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			fd.Close()

			pcapHash := sha256.New()
			if _, err := io.Copy(pcapHash, &buf); err != nil {
				return fileList, fmt.Errorf("Error copying to hash: %s", err)
			}
			fileSHA256 := pcapHash.Sum(nil)
			fileList[header.Name] = fileSHA256[:]
		default:
			return fileList, fmt.Errorf("File descriptor %c is of type %s, not file/dir",
				header.Typeflag,
				destDir+"/"+header.Name,
			)
		}
	}
}

// unBzip2 uncompresses a single bz2 file.
func unBzip2(fileDesc io.Reader, destFile string) (map[string][]byte, error) {
	var result = make(map[string][]byte)
	bzReader := bzip2.NewReader(fileDesc)
	fd, err := os.Create(destFile)
	if err != nil {
		return nil, fmt.Errorf("Could not create file %s.\nError: %s", destFile, err)
	}
	var buf bytes.Buffer
	tee := io.TeeReader(bzReader, &buf)
	if _, err := io.Copy(fd, tee); err != io.EOF {
		return result, fmt.Errorf("Error writing file: %s", err)
	}
	fd.Close()

	pcapHash := sha256.New()
	if _, err := io.Copy(pcapHash, &buf); err != nil {
		return result, fmt.Errorf("Error copying to hash: %s", err)
	}
	fileSHA256 := pcapHash.Sum(nil)
	result[fd.Name()] = fileSHA256[:]

	return result, nil
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func unZip(src string, destDir string) (map[string][]byte, error) {
	// Modified from https://golangcode.com/unzip-files-in-go/
	var result = make(map[string][]byte)

	zipFiles, err := zip.OpenReader(src)
	if err != nil {
		return result, err
	}
	defer zipFiles.Close()

	for _, zipFile := range zipFiles.File {

		// Store filename/path for returning and using later on
		zfpath := filepath.Join(destDir, zipFile.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(zfpath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return result, fmt.Errorf("%s: illegal file path", zfpath)
		}

		if zipFile.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(zfpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(zfpath), os.ModePerm); err != nil {
			return result, err
		}

		outFile, err := os.OpenFile(zfpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			return result, err
		}

		zipReader, err := zipFile.Open()
		if err != nil {
			return result, err
		}

		if err != nil {
			return result, err
		}

		var buf bytes.Buffer
		tee := io.TeeReader(zipReader, &buf)
		if _, err := io.Copy(outFile, tee); err != io.EOF {
			return result, fmt.Errorf("Error writing file: %s", err)
		}
		outFile.Close()

		pcapHash := sha256.New()
		if _, err := io.Copy(pcapHash, &buf); err != nil {
			return result, fmt.Errorf("Error copying to hash: %s", err)
		}
		fileSHA256 := pcapHash.Sum(nil)
		result[zfpath] = fileSHA256[:]
	}
	return result, nil
}
