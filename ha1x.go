package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ha1Version = "1.0.0"

func calculateMD5(inputString string) string {
	data := []byte(inputString)
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}

func calculateSHA1(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func calculateSHA256(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func calculateSHA384(input string) string {
	h := sha512.New384()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func calculateSHA512(input string) string {
	h := sha512.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func printCLIOptions() {
	type CLIOptionDef struct {
		Ops      []string
		Usage    string
		DefValue string
		VType    string
	}
	var items []CLIOptionDef
	flag.VisitAll(func(f *flag.Flag) {
		var found bool = false
		for idx, it := range items {
			if it.Usage == f.Usage {
				found = true
				it.Ops = append(it.Ops, f.Name)
				items[idx] = it
			}
		}
		if !found {
			items = append(items, CLIOptionDef{
				Ops:      []string{f.Name},
				Usage:    f.Usage,
				DefValue: f.DefValue,
				VType:    fmt.Sprintf("%T", f.Value),
			})
		}
	})
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Ops[0]) < strings.ToLower(items[j].Ops[0]) })
	for _, val := range items {
		vtype := val.VType[6 : len(val.VType)-5]
		if vtype[len(vtype)-2:] == "64" {
			vtype = vtype[:len(vtype)-2]
		}
		for _, opt := range val.Ops {
			if vtype == "bool" {
				fmt.Printf("  -%s\n", opt)
			} else {
				fmt.Printf("  -%s %s\n", opt, vtype)
			}
		}
		if vtype != "bool" && len(val.DefValue) > 0 {
			fmt.Printf("      %s [default: %s]\n", val.Usage, val.DefValue)
		} else {
			fmt.Printf("      %s\n", val.Usage)
		}
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), ha1Version)
		printCLIOptions()
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}
	algName := flag.String("a", "md5", "Hashing algorithm")
	singleMode := flag.Bool("s", false, "Enable single mode")
	ha1bMode := flag.Bool("b", false, "Compute HA1B variant")
	domainVal := flag.String("d", "", "Domain value")
	writeMode := flag.Bool("w", false, "Write only the hash")
	versionMode := flag.Bool("version", false, "Print the version")
	flag.Parse()

	if *versionMode {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), ha1Version)
		os.Exit(1)
	}

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
		if *ha1bMode {
			if domainVal != nil && len(*domainVal) > 0 {
				sInput = flag.Arg(0) + "@" + *domainVal + ":" + flag.Arg(1) + ":" + flag.Arg(2)
			} else {
				sInput = flag.Arg(0) + "@" + flag.Arg(1) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
			}
		} else {
			sInput = flag.Arg(0) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
		}
	}

	sHash := ""
	switch *algName {
	case "sha1":
		sHash = calculateSHA1(sInput)
	case "sha256":
		sHash = calculateSHA256(sInput)
	case "sha384":
		sHash = calculateSHA384(sInput)
	case "sha512":
		sHash = calculateSHA512(sInput)
	default:
		sHash = calculateMD5(sInput)
	}
	if *writeMode {
		fmt.Printf("%s", sHash)
	} else {
		fmt.Printf("Hash: %s\n", sHash)
	}
}
