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

type CLIOptions struct {
	algName      *string
	singleMode   *bool
	ha1bMode     *bool
	ha2Mode      *bool
	responseMode *bool
	domainVal    *string
	writeMode    *bool
	versionMode  *bool
	bodyVal      *string
	ncVal        *string
	cnonceVal    *string
	qopVal       *string
}

var cliops = CLIOptions{}

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

func calculateHash(sAlg string, sInput string) string {
	sHash := ""
	switch strings.ToLower(strings.Replace(sAlg, "-", "", 1)) {
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
	return sHash
}

func printHash(sHash string) {
	if *cliops.writeMode {
		fmt.Printf("Hash: %s\n", sHash)
	} else {
		fmt.Printf("%s", sHash)
	}
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
		fmt.Printf("Usage of %s (v%s)\n", filepath.Base(os.Args[0]), ha1Version)
		fmt.Printf("Prototypes:\n")
		fmt.Printf("    %s [opts] <username> <realm> <password>\n", filepath.Base(os.Args[0]))
		fmt.Printf("    %s -2 [opts] <method> <uri>\n", filepath.Base(os.Args[0]))
		fmt.Printf("    %s -r [opts] <username> <realm> <method> <uri> <nonce> <password>\n", filepath.Base(os.Args[0]))
		fmt.Printf("    %s -s [opts] <text>\n", filepath.Base(os.Args[0]))
		fmt.Printf("Options:\n")
		printCLIOptions()
		fmt.Printf("\n")
		os.Exit(1)
	}
	cliops.ha2Mode = flag.Bool("2", false, "Compute HA2 variant")
	cliops.ha1bMode = flag.Bool("3", false, "Compute HA1B variant")
	cliops.algName = flag.String("a", "md5", "Hashing algorithm")
	cliops.bodyVal = flag.String("b", "", "Body value")
	cliops.cnonceVal = flag.String("c", "", "CNonce value")
	cliops.domainVal = flag.String("d", "", "Domain value")
	cliops.ncVal = flag.String("n", "", "Nonce count value")
	cliops.responseMode = flag.Bool("r", false, "Compute the digest response")
	cliops.qopVal = flag.String("q", "", "QoP value")
	cliops.singleMode = flag.Bool("s", false, "Enable single mode")
	cliops.writeMode = flag.Bool("w", false, "Write verbose output")
	cliops.versionMode = flag.Bool("version", false, "Print the version")
	flag.Parse()

	if *cliops.versionMode {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), ha1Version)
		os.Exit(1)
	}

	if *cliops.singleMode {
		if len(flag.Args()) != 1 {
			fmt.Printf("Hash: %d\n", len(os.Args))
			fmt.Println("Usage: ha1x -s <input-string>")
			os.Exit(1)
		}
		printHash(calculateHash(*cliops.algName, flag.Arg(0)))
		os.Exit(0)
	}

	if *cliops.ha2Mode {
		if len(flag.Args()) != 2 {
			fmt.Printf("Hash: %d\n", len(os.Args))
			fmt.Println("Usage: ha1x -2 <method> <uri>")
			os.Exit(1)
		}
		printHash(calculateHash(*cliops.algName, flag.Arg(0)+":"+flag.Arg(1)))
		os.Exit(0)
	}

	if *cliops.responseMode {
		if len(flag.Args()) != 6 {
			fmt.Printf("Hash: %d\n", len(os.Args))
			fmt.Println("Usage: ha1x -r <username> <realm> <method> <uri> <nonce> <password>")
			os.Exit(1)
		}
		sHA1 := calculateHash(*cliops.algName, flag.Arg(0)+":"+flag.Arg(1)+":"+flag.Arg(5))
		sHA2 := calculateHash(*cliops.algName, flag.Arg(2)+":"+flag.Arg(3))
		if *cliops.qopVal == "auth" {
			// HASH(HA1:nonce:HA2)
			printHash(calculateHash(*cliops.algName, sHA1+":"+flag.Arg(4)+":"+sHA2))
		} else {
			// HASH(HA1:nonce:nonceCount:cnonce:qop:HA2)
			printHash(calculateHash(*cliops.algName, sHA1+":"+flag.Arg(4)+":"+
				*cliops.ncVal+":"+*cliops.cnonceVal+":"+*cliops.qopVal+":"+sHA2))
		}
		os.Exit(0)
	}

	sInput := ""
	if len(flag.Args()) != 3 {
		fmt.Println("Usage: ha1x [opts] <username> <realm> <password>")
		os.Exit(1)
	}
	if *cliops.ha1bMode {
		if cliops.domainVal != nil && len(*cliops.domainVal) > 0 {
			sInput = flag.Arg(0) + "@" + *cliops.domainVal + ":" + flag.Arg(1) + ":" + flag.Arg(2)
		} else {
			sInput = flag.Arg(0) + "@" + flag.Arg(1) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
		}
	} else {
		sInput = flag.Arg(0) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
	}

	sHash := calculateHash(*cliops.algName, sInput)
	printHash(sHash)
}
