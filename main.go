package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/caffix/resolve"
)

var DefaultBaselineResolvers = []string{
    "8.8.8.8",        // Google
    "1.1.1.1",        // Cloudflare
    "9.9.9.9",        // Quad9
    "208.67.222.222", // Cisco OpenDNS
    "209.244.0.3",    // Level3
    "64.6.64.6",      // Verisign
    "84.200.69.80",   // DNS.WATCH
    "8.26.56.26",     // Comodo Secure DNS
    "109.69.8.51",    // puntCAT
    "74.82.42.42",    // Hurricane Electric
    "77.88.8.8",      // Yandex.DNS
}

const DefaultQueriesPerPublicResolver = 15
const DefaultQueriesPerBaselineResolver = 50

var PublicResolvers []string

func init() {
    addrs := getPublicDNS()

loop:
    for _, addr := range addrs {
        for _, baseline := range DefaultBaselineResolvers {
            if addr == baseline {
                continue loop
            }
        }

        PublicResolvers = append(PublicResolvers, addr)
    }
}

func main() {
    var (
        input        string
        mainDomain   string
        maxDNSPerSec int
        threads      int
    )
    flag.StringVar(&input, "i", "-", "Subdomains list. Default is stdin")
    flag.StringVar(&mainDomain, "d", "", "Main domain")
    flag.IntVar(&threads, "t", 10, "Threads")
    flag.IntVar(&maxDNSPerSec, "rate", 20000, "Max DNS Limit per second")
    flag.Parse()

    if mainDomain == "" {
        fmt.Fprintln(os.Stderr, "Main domain is require")
        os.Exit(1)
    }

    var sc *bufio.Scanner
    if input == "" {
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

    pool := publicResolverSetup(maxDNSPerSec)
    if pool == nil {
        fmt.Fprintln(os.Stderr, "The system was unable to build the pool of resolvers")
        os.Exit(1)
    }

    var wg sync.WaitGroup
    jobChan := make(chan string, threads)

    for i := 0; i < threads; i++ {
        go func() {
            for sub := range jobChan {
                msg := resolve.QueryMsg(sub, 1)
                if pool.WildcardType(context.Background(), msg, mainDomain) == resolve.WildcardTypeNone {
                    fmt.Println(sub)
                }
            }
        }()
    }
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if strings.HasPrefix(line, "http") {
            u, err := url.Parse(line)
            if err != nil {
                continue
            }
            line = u.Hostname()
        }
        // subDomain := strings.ToLower(dns.RemoveAsteriskLabel(line))
        line = strings.Trim(line, ".")

        jobChan <- line
    }

    close(jobChan)
    wg.Wait()
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

func publicResolverSetup(maxDNSQueries int) resolve.Resolver {
    max := int(float64(GetFileLimit()) * 0.7)

    num := len(PublicResolvers)
    if num > max {
        num = max
    }

    if maxDNSQueries == 0 {
        maxDNSQueries = num * DefaultQueriesPerPublicResolver
    } else if maxDNSQueries < num {
        maxDNSQueries = num
    }

    var trusted []resolve.Resolver
    for _, addr := range DefaultBaselineResolvers {
        if r := resolve.NewBaseResolver(addr, DefaultQueriesPerBaselineResolver, nil); r != nil {
            trusted = append(trusted, r)
        }
    }

    baseline := resolve.NewResolverPool(trusted, time.Second, nil, 1, nil)
    r := setupResolvers(PublicResolvers, max, DefaultQueriesPerPublicResolver, nil)

    return resolve.NewResolverPool(r, 2*time.Second, baseline, 2, nil)
}

func setupResolvers(addrs []string, max, rate int, log *log.Logger) []resolve.Resolver {
    if len(addrs) <= 0 {
        return nil
    }

    finished := make(chan resolve.Resolver, 10)
    for _, addr := range addrs {
        if _, _, err := net.SplitHostPort(addr); err != nil {
            // Add the default port number to the IP address
            addr = net.JoinHostPort(addr, "53")
        }
        go func(ip string, ch chan resolve.Resolver) {
            if err := resolve.ClientSubnetCheck(ip); err == nil {
                if n := resolve.NewBaseResolver(ip, rate, log); n != nil {
                    ch <- n
                }
            }
            ch <- nil
        }(addr, finished)
    }

    l := len(addrs)
    var count int
    var resolvers []resolve.Resolver
    for i := 0; i < l; i++ {
        if r := <-finished; r != nil {
            if count < max {
                resolvers = append(resolvers, r)
                count++
                continue
            }
            r.Stop()
        }
    }

    if len(resolvers) == 0 {
        return nil
    }
    return resolvers
}

// GetFileLimit attempts to raise the ulimit to the maximum hard limit and returns that value.
func GetFileLimit() int {
    limit := 50000

    var lim syscall.Rlimit
    if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
        lim.Cur = lim.Max
        limit = int(lim.Cur)

        if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
            return limit
        }
    }

    if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
        if cur := int(lim.Cur); cur < limit {
            limit = cur
        }
    }

    return limit
}
