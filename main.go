// Package main searches for a [WireGuard] [curve25519] keypair
// with a base64-encoded public key that has a specified prefix.
//
// [WireGuard]: https://www.wireguard.com/
// [curve25519]: https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AlexanderYastrebov/vanity25519"
)

type SearchResult struct {
	PublicKey []byte
	Offset    *big.Int
	Found     bool
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "add" {
		cmdAdd(os.Args[2:])
		return
	}

	start := time.Now()
	config := struct {
		prefix     string
		timeout    time.Duration
		public     string
		output     string
		ignoreCase bool
		keysAmount uint64
	}{}

	flag.StringVar(&config.prefix, "prefix", "AY/", "prefix of base64-encoded public key")
	flag.DurationVar(&config.timeout, "timeout", 0, "stop after specified timeout")
	flag.StringVar(&config.public, "public", "", "start from specified public key")
	flag.StringVar(&config.output, "output", "", "use \"offset\" to print offset only")
	flag.BoolVar(&config.ignoreCase, "ignore-case", false, "enable case-insensitive search")
	flag.Uint64Var(&config.keysAmount, "keys", 1, "amount of keys that will be returned. 0 means infinite")
	flag.Parse()

	var startKey *ecdh.PrivateKey
	var startPublicKey []byte
	var err error

	if config.public != "" {
		startPublicKey, err = base64.StdEncoding.DecodeString(config.public)
		if err != nil {
			panic(err)
		}
	} else {
		startKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		startPublicKey = startKey.PublicKey().Bytes()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if config.timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, config.timeout)
		defer cancel()
	}

	var test func([]byte) bool
	if config.ignoreCase {
		prefixUpper := []byte(strings.ToUpper(config.prefix))
		test = func(pub []byte) bool {
			buf := make([]byte, base64.StdEncoding.EncodedLen(len(pub)))
			base64.StdEncoding.Encode(buf, pub)
			for i := 0; i < len(prefixUpper) && i < len(buf); i++ {
				a := buf[i]
				if a >= 'a' && a <= 'z' {
					a -= 'a' - 'A'
				}
				if a != prefixUpper[i] {
					return false
				}
			}
			return len(buf) >= len(prefixUpper)
		}
	} else {
		test = vanity25519.HasPrefixBits(decodeBase64PrefixBits(config.prefix))
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	var totalAttempts atomic.Uint64
	results := searchParallel(ctx, runtime.GOMAXPROCS(0), startPublicKey, test, &totalAttempts, config.keysAmount)
	ok := printParallel(results, startKey, config.prefix, start, &totalAttempts)

	if !ok {
		os.Exit(1)
	}
}

func cmdAdd(args []string) {
	config := struct {
		offset *big.Int
	}{}
	var ok bool

	fs := flag.NewFlagSet("add", flag.ExitOnError)
	fs.Func("offset", "add specified offset to the private key", func(s string) error {
		if config.offset, ok = new(big.Int).SetString(s, 10); !ok {
			return fmt.Errorf("invalid offset")
		}
		return nil
	})
	fs.Parse(args)

	if config.offset == nil {
		panic("offset required")
	}

	in := make([]byte, 44)
	if _, err := io.ReadFull(os.Stdin, in); err != nil {
		panic(err)
	}
	startPrivateKey, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		panic(err)
	}

	vanityPrivateKey, err := vanity25519.Add(startPrivateKey, config.offset)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(vanityPrivateKey))
}

func searchParallel(ctx context.Context, workers int, startPublicKey []byte, test func([]byte) bool, totalAttempts *atomic.Uint64, keysAmount uint64) <-chan SearchResult {
	results := make(chan SearchResult, workers)

	go func() {
		defer close(results)

		var foundCount atomic.Uint64
		var wg sync.WaitGroup

		gtx, cancel := context.WithCancel(ctx)
		defer cancel()

		for range workers {
			wg.Go(func() {
				vanity25519.Search(gtx, startPublicKey, randBigInt(), 4096, test, func(publicKey []byte, offset *big.Int) {
					r := SearchResult{
						PublicKey: append([]byte(nil), publicKey...),
						Offset:    new(big.Int).Set(offset),
						Found:     true,
					}
					select {
					case results <- r:
					case <-gtx.Done():
						return
					}

					if foundCount.Add(1) >= uint64(keysAmount) && keysAmount != 0 {
						cancel()
					}
				})
			})
		}
		wg.Wait()
	}()
	return results
}

func printParallel(results <-chan SearchResult, startKey *ecdh.PrivateKey, prefix string, start time.Time, totalAttempts *atomic.Uint64) bool {
	var anyFound bool
	fmt.Printf("%-44s %-44s %-10s %-10s %s\n", "private", "public", "attempts", "duration", "attempts/s")

	for r := range results {
		anyFound = true
		public := base64.StdEncoding.EncodeToString(r.PublicKey)
		private := "-"
		if startKey != nil {
			if vanityPrivateKey, err := vanity25519.Add(startKey.Bytes(), r.Offset); err == nil {
				private = base64.StdEncoding.EncodeToString(vanityPrivateKey)
			}
		}
		attempts := totalAttempts.Load()

		elapsed := time.Since(start)
		fmt.Printf("%-44s %-44s %-10d %-10s %.0f\n",
			private,
			public,
			attempts,
			elapsed.Round(time.Second),
			float64(attempts)/elapsed.Seconds(),
		)
	}

	fmt.Printf("\nCompleted in %s\n", time.Since(start).Round(time.Second))
	return anyFound
}

// decodeBase64PrefixBits returns decoded prefix and number of decoded bits.
func decodeBase64PrefixBits(prefix string) ([]byte, int) {
	decodedBits := 6 * len(prefix)
	quantums := (len(prefix) + 3) / 4
	prefix += strings.Repeat("A", quantums*4-len(prefix))
	buf := make([]byte, quantums*3)
	_, err := base64.StdEncoding.Decode(buf, []byte(prefix))
	if err != nil {
		panic(err)
	}
	return buf, decodedBits
}

func randBigInt() *big.Int {
	var buf [8]byte
	rand.Read(buf[:])
	return new(big.Int).SetBytes(buf[:])
}
