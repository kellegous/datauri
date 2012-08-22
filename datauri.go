package main

import (
  "bytes"
  "encoding/base64"
  "flag"
  "fmt"
  "io"
  "net/http"
  "net/url"
  "os"
  "path/filepath"
)

var mimeMap = map[string]string{
  ".png": "image/png",
  ".jpg": "image/jpg",
  ".gif": "image/gif",
  ".bmp": "image/bmp",
  "":     "application/octet-stream",
}

func sniffContent(r io.Reader) (string, io.Reader, error) {
  // read the first 512 bytes
  b := make([]byte, 512)
  n, err := io.ReadFull(r, b)
  if err == io.ErrUnexpectedEOF {
    b = b[:n]
  } else if err != nil {
    return "", nil, err
  }

  return http.DetectContentType(b),
    io.MultiReader(bytes.NewBuffer(b), r),
    nil
}

func sniff(filename string, r io.Reader) (string, io.Reader, error) {
  t, r, err := sniffContent(r)
  if err != nil {
    return "", nil, err
  }

  if t != "application/octet-stream" {
    return t, r, nil
  }

  return mimeMap[filepath.Ext(filename)], r, nil
}

func open(name string) (io.ReadCloser, error) {
  if u, err := url.Parse(name); err != nil || u.Scheme == "" {
    return os.Open(name)
  }

  r, err := http.Get(name)
  if err != nil {
    return nil, err
  }

  return r.Body, nil
}

func main() {
  flag.Parse()
  args := flag.Args()
  if len(args) == 0 {
    fmt.Fprintf(os.Stderr, "usage:\n")
    os.Exit(1)
  }

  r, err := open(args[0])
  if err != nil {
    panic(err)
  }
  defer r.Close()

  t, nr, err := sniff(args[0], r)
  if err != nil {
    panic(err)
  }

  fmt.Printf("data:%s;base64,", t)
  if _, err := io.Copy(base64.NewEncoder(base64.StdEncoding, os.Stdout), nr); err != nil {
    panic(err)
  }
}
