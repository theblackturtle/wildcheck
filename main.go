package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	amassresolvers "github.com/OWASP/Amass/v3/resolvers"
	"golang.org/x/net/publicsuffix"
)

const AUTHOR = `@thebl4ckturtle - https://github.com/theblackturtle/`

var DefaultResolvers = []string{
	"1.1.1.1:53",     // Cloudflare
	"8.8.8.8:53",     // Google
	"64.6.64.6:53",   // Verisign
	"77.88.8.8:53",   // Yandex.DNS
	"74.82.42.42:53", // Hurricane Electric
	"1.0.0.1:53",     // Cloudflare Secondary
	"8.8.4.4:53",     // Google Secondary
	"77.88.8.1:53",   // Yandex.DNS Secondary
}

func main() {
	var (
		input        string
		threads      int
		publicDNS    bool
		resolverList string
	)
	flag.StringVar(&input, "i", "-", "Subdomains list. Default is stdin")
	flag.IntVar(&threads, "t", 10, "Threads to use")
	flag.BoolVar(&publicDNS, "p", false, "Get resolvers from Public-DNS")
	flag.StringVar(&resolverList, "r", "", "Your resolvers list")
	flag.Parse()

	var sc *bufio.Scanner
	if input == ""{
		fmt.Fprintln(os.Stderr, "Check your input again")
		os.Exit(1)
	}
	if input == "-" {
		sc = bufio.NewScanner(os.Stdin)
	} else {
		subsFile, err := os.Open(input)
		if err != nil {
			fmt.Println("Please check your input file.")
			os.Exit(1)
		}
		defer subsFile.Close()
		sc = bufio.NewScanner(subsFile)
	}

	var resolvers []string
	if publicDNS {
		resolvers = append(resolvers, getPublicDNS()...)
	}

	if resolverList != "" {
		f, err := os.Open(resolverList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open resolver file: %s\n", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if err := sc.Err(); err == nil && line != "" {
				lineArgs := strings.SplitN(line, ":", 2)
				switch len(lineArgs) {
				case 2:
					resolvers = append(resolvers, line)
				case 1:
					resolvers = append(resolvers, line+":53")
				}
			}
		}
	}

	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}

	resolverPool := amassresolvers.SetupResolverPool(resolvers, false, nil)
	if resolverPool == nil {
		fmt.Println("Failed to init pool")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Total working resolvers: %d\n", len(resolverPool.Resolvers))

	var wg sync.WaitGroup
	jobChan := make(chan *requests.DNSRequest, threads)
	ctx := context.Background()
	defer ctx.Done()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range jobChan {
				if !resolverPool.MatchesWildcard(ctx, req) {
					fmt.Printf("[non-wildcard] - %s\n", req.Name)
				} else {
					fmt.Printf("[wildcard] - %s\n", req.Name)
				}
			}
		}()
	}

	var domainList []string
	for sc.Scan() {
		var mainDomain string
		line := strings.TrimSpace(sc.Text())
		subDomain := strings.ToLower(dns.RemoveAsteriskLabel(line))
		subDomain = strings.Trim(subDomain, ".")

		for _, d := range domainList {
			if strings.HasSuffix(subDomain, d) || d == subDomain {
				mainDomain = d
				break
			}
		}

		// Extract main domain from sub domain
		if mainDomain == "" {
			mainDomain, err := publicsuffix.EffectiveTLDPlusOne(subDomain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get main domain from %s subdomain\n", subDomain)
				continue
			}
			domainList = append(domainList, mainDomain)
		}
		for _, sub := range getSubs(mainDomain, subDomain) {
			jobChan <- &requests.DNSRequest{
				Name:   sub,
				Domain: mainDomain,
			}
		}

	}
	close(jobChan)
	wg.Wait()
}

func getSubs(mainDomain string, subdomain string) []string {
	var subsList []string
	subRe := dns.SubdomainRegex(mainDomain)
	subsList = append(subsList, subRe.FindAllString(subdomain, -1)...)
	return subsList
}

func getPublicDNS() []string {
	var resolversList []string
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	cc := "us"
	if result := getCountryCode(client); result != "" {
		cc = result
	}
	url := "https://public-dns.info/nameserver/" + cc + ".txt"

	resp, err := client.Get(url)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to get public DNS list\n")
		return []string{}
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to get public DNS list\n")
		return []string{}
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if err := sc.Err(); err == nil && line != "" {
			resolversList = append(resolversList, line)
		}
	}
	return resolversList
}

func getCountryCode(client *http.Client) string {
	req, err := http.NewRequest("GET", "https://ipapi.co/json", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var ipinfo struct {
		CountryCode string `json:"country"`
	}

	json.Unmarshal(body, &ipinfo)
	return strings.ToLower(ipinfo.CountryCode)
}
