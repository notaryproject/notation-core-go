package cache

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const tempFileName = "notation-*"

// fileSystemCache builds on top of OS file system to leverage the file system
// concurrency control and atomicity
type fileSystemCache struct {
	dir string
}

// NewFileSystemCache creates a new file system store
func NewFileSystemCache(dir string) Cache {
	return &fileSystemCache{
		dir: dir,
	}
}

// Get retrieves the CRL from the store
func (f *fileSystemCache) Get(fileName string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(f.dir, fileName))
}

// Set stores the CRL in the store
func (f *fileSystemCache) Set(filename string) (WriteCanceler, error) {
	return newFileSystemWriter(filepath.Join(f.dir, filename))
}

// List returns the list of CRLs in the store
func (f *fileSystemCache) List() ([]string, error) {
	files, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, err
	}

	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}

	return fileNames, nil
}

// Delete removes the CRL from the store
func (f *fileSystemCache) Delete(fileName string) error {
	return os.Remove(filepath.Join(f.dir, fileName))
}

// fileSystemWriter is a WriteCanceler implementation that writes to
// a file system file and renames it to the final path when Close is called
type fileSystemWriter struct {
	io.WriteCloser
	tempFilePath string
	filePath     string
	canceled     bool
}

func newFileSystemWriter(filePath string) (WriteCanceler, error) {
	tempFile, err := os.CreateTemp("", tempFileName)
	if err != nil {
		return nil, err
	}

	filePath, err = filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	return &fileSystemWriter{
		WriteCloser:  tempFile,
		tempFilePath: tempFile.Name(),
		filePath:     filePath,
	}, nil
}

func (c *fileSystemWriter) Write(p []byte) (int, error) {
	return c.WriteCloser.Write(p)
}

func (c *fileSystemWriter) Cancel() {
	c.canceled = true
}

func (c *fileSystemWriter) Close() error {
	if err := c.WriteCloser.Close(); err != nil {
		return err
	}

	if !c.canceled {
		// make directory
		if err := os.MkdirAll(filepath.Dir(c.filePath), 0755); err != nil {
			return err
		}

		fmt.Println("Renaming", c.tempFilePath, "to", c.filePath)
		return os.Rename(c.tempFilePath, c.filePath)
	}
	return nil
}
