package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/akkuman/httprobe/iprange"
)

type Result struct {
	URL      string
	Title    string
	PortOpen bool
	// Whether to continue trying HTTP protocol
	TryHTTP bool
}

type probeArgs []string

func (p *probeArgs) Set(val string) error {
	*p = append(*p, val)
	return nil
}

func (p probeArgs) String() string {
	return strings.Join(p, ",")
}

var (
	// concurrency flag
	concurrency int
	// probe flags
	probes probeArgs
	// skip default probes flag
	skipDefault bool
	// timeout flag
	sTimeout int
	// prefer https
	preferHTTPS bool
	// HTTP method to use
	method string
	ips    string
)

func init() {
	flag.IntVar(&concurrency, "c", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")
	flag.Var(&probes, "p", "add additional probe (proto:port)")
	flag.BoolVar(&skipDefault, "s", false, "skip the default probes (http:80 and https:443)")
	flag.IntVar(&sTimeout, "t", 10, "timeout (seconds)")
	flag.BoolVar(&preferHTTPS, "prefer-https", false, "only try plain HTTP if HTTPS fails")
	flag.StringVar(&method, "method", "GET", "HTTP method to use")
	flag.StringVar(&ips, "ips", "", "the ip range of target")
	flag.Parse()
}

func main() {
	// make an actual time.Duration out of the timeout
	timeout := time.Duration(sTimeout) * time.Second

	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}

	// domain/port pairs are initially sent on the httpsURLs channel.
	// If they are listening and the --prefer-https flag is set then
	// no HTTP check is performed; otherwise they're put onto the httpURLs
	// channel for an HTTP check.
	httpsURLs := make(chan string)
	httpURLs := make(chan string)
	output := make(chan Result)

	// HTTPS workers
	var httpsWG sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		httpsWG.Add(1)

		go func() {
			for url := range httpsURLs {

				// always try HTTPS first
				withProto := "https://" + url
				result := isListening(client, withProto, method)
				if result != nil {
					output <- *result

					// skip trying HTTP if --prefer-https is set
					if preferHTTPS {
						continue
					}

					// proceed to the next step only when HTTP is available
					if !(result.PortOpen && result.TryHTTP) {
						continue
					}
				}

				httpURLs <- url
			}

			httpsWG.Done()
		}()
	}

	// HTTP workers
	var httpWG sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		httpWG.Add(1)

		go func() {
			for url := range httpURLs {
				withProto := "http://" + url
				result := isListening(client, withProto, method)
				if result != nil {
					output <- *result
					continue
				}
			}

			httpWG.Done()
		}()
	}

	// Close the httpURLs channel when the HTTPS workers are done
	go func() {
		httpsWG.Wait()
		close(httpURLs)
	}()

	// Output worker
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for o := range output {
			fmt.Fprintf(os.Stdout, "%-30s | [%s]\n", o.URL, o.Title)
		}
		outputWG.Done()
	}()

	// Close the output channel when the HTTP workers are done
	go func() {
		httpWG.Wait()
		close(output)
	}()

	// accept domains on stdin
	if ips != "" {
		ipList, err := iprange.GetAllIP(ips)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse ips: %s\n", err)
		}
		for _, ip := range ipList {
			run(ip.To4().String(), httpURLs, httpsURLs)
		}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			run(sc.Text(), httpURLs, httpsURLs)
		}
		// check there were no errors reading stdin (unlikely)
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	// once we've sent all the URLs off we can close the
	// input/httpsURLs channel. The workers will finish what they're
	// doing and then call 'Done' on the WaitGroup
	close(httpsURLs)

	// Wait until the output waitgroup is done
	outputWG.Wait()
}

func run(target string, httpURLs, httpsURLs chan string) {
	domain := strings.ToLower(target)

	// submit standard port checks
	if !skipDefault {
		httpsURLs <- domain
	}

	// Adding port templates
	xlarge := []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
	large := []string{"81", "591", "2082", "2087", "2095", "2096", "3000", "8000", "8001", "8008", "8080", "8083", "8443", "8834", "8888"}

	// submit any additional proto:port probes
	for _, p := range probes {
		switch p {
		case "xlarge":
			for _, port := range xlarge {
				httpsURLs <- fmt.Sprintf("%s:%s", domain, port)
			}
		case "large":
			for _, port := range large {
				httpsURLs <- fmt.Sprintf("%s:%s", domain, port)
			}
		default:
			pair := strings.SplitN(p, ":", 2)
			if len(pair) != 2 {
				continue
			}

			// This is a little bit funny as "https" will imply an
			// http check as well unless the --prefer-https flag is
			// set. On balance I don't think that's *such* a bad thing
			// but it is maybe a little unexpected.
			if strings.ToLower(pair[0]) == "https" {
				httpsURLs <- fmt.Sprintf("%s:%s", domain, pair[1])
			} else {
				httpURLs <- fmt.Sprintf("%s:%s", domain, pair[1])
			}
		}
	}
}

func isListening(client *http.Client, requrl, method string) *Result {
	var title string
	req, err := http.NewRequest(method, requrl, nil)
	if err != nil {
		return nil
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil {
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return nil
		}
		title = doc.Find("title").Text()
		resp.Body.Close()
	}

	result := Result{
		URL:   requrl,
		Title: title,
	}

	if err != nil {
		if strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS client") {
			result.TryHTTP = true
		}
		if ue, ok := err.(*url.Error); ok {
			if ne, ok1 := ue.Err.(*net.OpError); ok1 {
				if ne.Op == "dial" {
					result.PortOpen = false
				}
			}
		}
		return nil
	}

	return &result
}
