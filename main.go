package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/cretz/bine/tor"
	"github.com/ipsn/go-libtor"
)

var parallelism = flag.Int("p", 1, "Parallelism")
var length = flag.Int("l", 32, "Length")
var target = flag.String("target", "", "The URL to retrieve (required)")
var ua = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0", "Tor user agent by default")

func main() {
	flag.Parse()
	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	tc := NewTorClient()
	defer tc.Close()
	resp, err := tc.Fetch(*target, "")
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Non-200 status code: %d\n", resp.StatusCode)
	}

	defer resp.Body.Close()

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}

type ArgonParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
	difficulty  int
	prefix      string
	salt        string
}

func (p ArgonParams) Check(n int) bool {
	password := fmt.Sprintf("%s%d", p.prefix, n)
	hash := argon2.IDKey([]byte(password), []byte(p.salt), p.iterations, p.memory, p.parallelism, p.keyLength)
	for i, v := range hash[:(p.difficulty+1)/2] {
		if 2*i == p.difficulty {
			return true
		}
		if v != 0 {
			if 2*i+1 == p.difficulty && v>>4 == 0 {
				return true
			}
			break
		}
	}
	return false
}

type TorClient struct {
	c      http.Client
	torCtx *tor.Tor
}

func (tc *TorClient) Get(target, referer string) (*http.Response, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}

	req.Header.Set("User-Agent", *ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	return tc.c.Do(req)
}

func (tc *TorClient) PostForm(target string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Referer", target)

	req.Header.Set("User-Agent", *ua)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	return tc.c.Do(req)
}

func (tc *TorClient) Close() {
	tc.torCtx.Close()
}

func NewTorClient() *TorClient {
	ctx := context.Background()
	torCtx, err := tor.Start(
		ctx,
		&tor.StartConf{ProcessCreator: libtor.Creator},
	)
	if err != nil {
		log.Fatalf("Failed to create Tor Context = %v\n", err)
	}
	dialer, err := torCtx.Dialer(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to create dialer for Tor Context - %v\n", err)
	}
	jar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
			DialContext:     dialer.DialContext,
		},
		Jar: jar,
	}
	return &TorClient{
		c:      httpClient,
		torCtx: torCtx,
	}
}

func (tc *TorClient) Fetch(target, referer string) (*http.Response, error) {
	resp, err := tc.Get(target, referer)
	if err != nil {
		return nil, err
	}

	// Check whether we were allowed direct access.
	if resp.StatusCode != http.StatusForbidden {
		// If so (eg due to passing captcha earlier), then return
		// the http.Response for caller to do what it will.
		return resp, nil
	}

	// Otherwise, do the captcha dance.
	defer resp.Body.Close()

	var p ArgonParams
	var pow string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		l := scanner.Text()
		if !strings.HasPrefix(l, "\t<body data") {
			continue
		}
		parts := strings.Split(l[len("\t<body "):len(l)-1], " ")

		for _, part := range parts {
			split := strings.SplitN(part, "=", 2)
			key := split[0]
			// Trim the quotes on either side of the value.
			value := split[1][1 : len(split[1])-1]
			switch key {
			case "data-pow":
				// data-pow="234a8b1a036dd6aee9c2745b31ffb1b8#2b8e80f38873205a65c14f9055b6ad0567b7690d8cd0fc73ac55882f32457045#fa725558ce6c1a9343265dd2abaddde7acfdd8af56c6e7269b3fddc4b6c29884"
				pow = value
				params := strings.Split(pow, "#")
				p.salt = params[0]
				p.prefix = params[1]
			case "data-time":
				// data-time="1"
				iters, err := strconv.Atoi(value)
				if err != nil {
					log.Fatal(err)
				}
				p.iterations = uint32(iters)
			case "data-diff":
				// data-diff="24"
				bits, err := strconv.Atoi(value)
				if err != nil {
					log.Fatal(err)
				}
				p.difficulty = bits / 8
			case "data-kb":
				// data-kb="512"
				mem, err := strconv.Atoi(value)
				if err != nil {
					log.Fatal(err)
				}
				p.memory = uint32(mem)
			default:
				log.Fatalf("Unexpected key: %s", key)
			}
		}
		p.parallelism = uint8(*parallelism)
		p.keyLength = uint32(*length)
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Run the POW, single-threaded in case another circuit is running.
	var result int
	for n := 0; ; n++ {
		if p.Check(n) {
			result = n
			break
		}
	}

	// Post the result back to the checker. This will yield a redirect to
	// our true target.
	values := url.Values{}
	values.Set("pow_response", fmt.Sprintf("%s#%d", pow, result))
	values.Set("submit", "submit")
	return tc.PostForm(resp.Request.URL.String(), values)
}
