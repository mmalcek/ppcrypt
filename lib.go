package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func readStdin() ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("getStdin: %s", err.Error())
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("stdin: Error-noPipe")
	}

	msg, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("readStdin: %s", err.Error())
	}
	// TODO: test on linux with \n only
	msg = bytes.TrimRight(msg, "\r\n")

	return msg, nil
}
