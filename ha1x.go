package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	"os"
)

func calculateMD5(inputString string) string {
	data := []byte(inputString)
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}

func main() {
	singleMode := flag.Bool("s", false, "Enable single mode")
	flag.Parse()

	sInput := ""
	if *singleMode {
		if len(flag.Args()) != 1 {
			fmt.Printf("Hash: %d\n", len(os.Args))
			fmt.Println("Usage: ha1x <input-string>")
			os.Exit(1)
		}
		sInput = flag.Arg(0)
	} else {
		if len(flag.Args()) != 3 {
			fmt.Println("Usage: ha1x <username> <realm> <password>")
			os.Exit(1)
		}
		sInput = flag.Arg(0) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
	}

	sHash := calculateMD5(sInput)
	fmt.Printf("Hash: %s\n", sHash)
}
