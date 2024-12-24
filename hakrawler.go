package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// Result stores the output fields for each found URL.
type Result struct {
	Source string
	URL    string
	Where  string
}

// Headers from the command line flag, stored in a map for easy usage by Colly.
var headers map[string]string

// Thread-safe map for uniqueness checks.
var sm sync.Map

func main() {
	inside := flag.Bool("i", false, "Only crawl inside path")
	threads := flag.Int("t", 8, "Number of threads to utilize.")
	depth := flag.Int("d", 2, "Depth to crawl.")
	maxSize := flag.Int("size", -1, "Page size limit, in KB.")
	insecure := flag.Bool("insecure", false, "Disable TLS verification.")
	subsInScope := flag.Bool("subs", false, "Include subdomains for crawling.")
	showJSON := flag.Bool("json", false, "Output results as JSON.")
	showSource := flag.Bool("s", false, "Show the source of URL (e.g. href, form, script).")
	showWhere := flag.Bool("w", false, "Show from which link the URL was found.")
	rawHeaders := flag.String("h", "", "Custom headers separated by double semicolons. e.g. -h \"Cookie: foo=bar;;Referer: http://example.com/\" ")
	uniqueOnly := flag.Bool("u", false, "Show only unique URLs.")
	proxy := flag.String("proxy", "", "Proxy URL. e.g. -proxy http://127.0.0.1:8080")
	timeout := flag.Int("timeout", -1, "Max time to crawl each URL from stdin, in seconds. -1 means no timeout.")
	disableRedirects := flag.Bool("dr", false, "Disable following HTTP redirects.")

	flag.Parse()

	// Validate the number of threads
	if *threads < 1 {
		fmt.Fprintln(os.Stderr, "Invalid number of threads, resetting to default (8).")
		*threads = 8
	}

	// Parse and validate custom headers (if any).
	if err := parseHeaders(*rawHeaders); err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing headers:", err)
		os.Exit(1)
	}

	// Prepare proxy config if provided.
	if *proxy != "" {
		if err := os.Setenv("PROXY", *proxy); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to set PROXY environment variable:", err)
			os.Exit(1)
		}
	}

	proxyURL, err := url.Parse(os.Getenv("PROXY"))
	if err != nil && *proxy != "" {
		fmt.Fprintln(os.Stderr, "Invalid proxy URL:", err)
		os.Exit(1)
	}

	// Check for STDIN input to avoid waiting on an empty pipe.
	stat, err := os.Stdin.Stat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading Stdin:", err)
		os.Exit(1)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No URLs detected on stdin. Hint: cat urls.txt | hakrawler")
		os.Exit(1)
	}

	// Prepare channel for results.
	results := make(chan string, *threads)

	// Goroutine to read from stdin and process each URL.
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urlToVisit := sc.Text()
			if urlToVisit == "" {
				continue
			}

			hostname, err := extractHostname(urlToVisit)
			if err != nil {
				log.Println("[Error] Invalid URL:", err, "| Input was:", urlToVisit)
				continue
			}

			// Allowed domains (initially includes the main hostname).
			allowedDomains := []string{hostname}

			// If "Host" header is set, append it to allowed domains.
			if headers != nil {
				if hostVal, ok := headers["Host"]; ok && hostVal != "" {
					allowedDomains = append(allowedDomains, hostVal)
				}
			}

			// Create a Colly collector with the user-specified options.
			c := createCollector(
				allowedDomains,
				*depth,
				*maxSize,
				*insecure,
				proxyURL,
				*threads,
				*subsInScope,
				*disableRedirects,
			)

			// Setup callback logic for HTML elements.
			setupCallbacks(
				c,
				urlToVisit,
				results,
				*inside,
				*showSource,
				*showWhere,
				*showJSON,
			)

			// Crawl with (or without) timeout.
			if *timeout == -1 {
				// No timeout.
				c.Visit(urlToVisit)
				c.Wait()
			} else {
				// With timeout.
				done := make(chan struct{}, 1)
				go func() {
					defer close(done)
					c.Visit(urlToVisit)
					c.Wait()
				}()
				select {
				case <-done:
					// Completed before timeout.
				case <-time.After(time.Duration(*timeout) * time.Second):
					log.Println("[timeout]", urlToVisit)
				}
			}
		}

		// Check for scanner errors.
		if err := sc.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "[Error] Reading standard input:", err)
		}

		// Close the results channel to signal the output loop to end.
		close(results)
	}()

	// Collect and print results from the channel.
	printResults(results, *uniqueOnly)
}

// createCollector builds and returns a configured Colly Collector.
func createCollector(
	allowedDomains []string,
	depth int,
	maxSizeKB int,
	insecure bool,
	proxyURL *url.URL,
	threads int,
	subsInScope bool,
	disableRedirects bool,
) *colly.Collector {
	c := colly.NewCollector(
		colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
		colly.Headers(headers),
		colly.AllowedDomains(allowedDomains...),
		colly.MaxDepth(depth),
		colly.Async(true),
	)

	// If user has set a size limit.
	if maxSizeKB != -1 {
		c.MaxBodySize = maxSizeKB * 1024
	}

	// If user wants subdomains in scope, override AllowedDomains with a regex filter instead.
	if subsInScope && len(allowedDomains) > 0 {
		hostname := allowedDomains[0]
		c.AllowedDomains = nil
		// Use a regex that allows subdomains or the original domain name itself.
		regexPattern := ".*(\\.|\\/\\/)" + strings.ReplaceAll(hostname, ".", "\\.") + "((#|\\/|\\?).*)?"
		c.URLFilters = []*regexp.Regexp{regexp.MustCompile(regexPattern)}
	}

	// Optionally disable redirects.
	if disableRedirects {
		c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		})
	}

	// Parallelism limit.
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: threads,
	})

	// Transport settings (proxy + TLS).
	c.WithTransport(&http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	})

	// Additional custom headers on each request.
	if headers != nil {
		c.OnRequest(func(r *colly.Request) {
			for headerKey, headerValue := range headers {
				r.Headers.Set(headerKey, headerValue)
			}
		})
	}

	return c
}

// setupCallbacks configures the OnHTML callbacks, request visits, etc.
func setupCallbacks(
	c *colly.Collector,
	baseURL string,
	results chan string,
	inside bool,
	showSource bool,
	showWhere bool,
	showJSON bool,
) {
	// Follow 'href' links, optionally limited to inside path.
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		absoluteLink := e.Request.AbsoluteURL(link)
		// If inside path only or if link is in base domain.
		if strings.Contains(absoluteLink, baseURL) || !inside {
			printResult(link, "href", showSource, showWhere, showJSON, results, e)
			_ = e.Request.Visit(link)
		}
	})

	// Find <script src="..."> links.
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		printResult(e.Attr("src"), "script", showSource, showWhere, showJSON, results, e)
	})

	// Find <form action="..."> links.
	c.OnHTML("form[action]", func(e *colly.HTMLElement) {
		printResult(e.Attr("action"), "form", showSource, showWhere, showJSON, results, e)
	})
}

// printResults handles the reading of results from a channel and output formatting.
func printResults(results <-chan string, uniqueOnly bool) {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	var urlsFound bool

	if uniqueOnly {
		for res := range results {
			if isUnique(res) {
				fmt.Fprintln(w, res)
				urlsFound = true
			}
		}
	} else {
		for res := range results {
			fmt.Fprintln(w, res)
			urlsFound = true
		}
	}

	// If no URLs were found, show a helpful message.
	if !urlsFound {
		fmt.Fprintln(os.Stderr, "No URLs were found. This might happen if the domain redirects to a subdomain not in scope. " +
			"Try using the -subs option to include subdomains, or specify the final redirected URL.")
	}
}

// parseHeaders validates and stores raw headers (flag input) into a map.
func parseHeaders(rawHeaders string) error {
	if rawHeaders == "" {
		return nil
	}

	if !strings.Contains(rawHeaders, ":") {
		return errors.New("headers flag not formatted properly (no colon found to separate header and value)")
	}

	headers = make(map[string]string)

	headerPairs := strings.Split(rawHeaders, ";;")
	for _, header := range headerPairs {
		var parts []string
		// Attempt splitting on ": " first, then just ":" if that fails.
		if strings.Contains(header, ": ") {
			parts = strings.SplitN(header, ": ", 2)
		} else if strings.Contains(header, ":") {
			parts = strings.SplitN(header, ":", 2)
		} else {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			return fmt.Errorf("invalid header detected: '%s'", header)
		}
		headers[key] = value
	}
	return nil
}

// extractHostname extracts the hostname from a URL, ensuring it's a valid absolute URL.
func extractHostname(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}
	if !u.IsAbs() {
		return "", fmt.Errorf("URL is not absolute: %s", urlString)
	}
	return u.Hostname(), nil
}

// printResult constructs output lines and sends them to the results channel.
func printResult(
	link string,
	sourceName string,
	showSource bool,
	showWhere bool,
	showJSON bool,
	results chan string,
	e *colly.HTMLElement,
) {
	absLink := e.Request.AbsoluteURL(link)
	if absLink == "" {
		return
	}

	whereURL := e.Request.URL.String()
	result := absLink

	// If JSON output.
	if showJSON {
		where := ""
		if showWhere {
			where = whereURL
		}
		bytes, _ := json.Marshal(Result{
			Source: sourceName,
			URL:    absLink,
			Where:  where,
		})
		result = string(bytes)
	} else {
		// Add source label.
		if showSource {
			result = "[" + sourceName + "] " + result
		}
		// Add where it was found if requested (and not JSON).
		if showWhere {
			result = "[" + whereURL + "] " + result
		}
	}

	// Recover from any panic if channel is closed (e.g. due to timeout).
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()
	results <- result
}

// isUnique checks if the provided URL has been seen before.
func isUnique(urlStr string) bool {
	_, found := sm.Load(urlStr)
	if found {
		return false
	}
	sm.Store(urlStr, true)
	return true
}
