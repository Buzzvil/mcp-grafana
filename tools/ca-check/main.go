// ca-check verifies public TLS endpoints without Grafana credentials or API calls.
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/grafana/mcp-grafana"
)

func main() {
	caFile := flag.String("ca-file", "", "optional CA bundle; empty uses the image's system roots")
	flag.Parse()
	transport, err := mcpgrafana.BuildTransport(&mcpgrafana.GrafanaConfig{
		TLSConfig: &mcpgrafana.TLSConfig{CAFile: *caFile},
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	fmt.Printf("Go=%s CA=%q (empty means system roots)\n", runtime.Version(), *caFile)
	failed := false
	check := func(host string, reject bool) {
		resp, err := client.Head("https://" + host + "/")
		if resp != nil {
			_ = resp.Body.Close()
		}
		if reject {
			// DNS, timeouts, expiry and hostname failures are not distrust evidence.
			var untrusted x509.UnknownAuthorityError
			var invalid x509.CertificateInvalidError
			if errors.As(err, &untrusted) || (errors.As(err, &invalid) && invalid.Reason == x509.NoValidChains) {
				fmt.Printf("REJECT %s: %v\n", host, err)
				return
			}
		} else if err == nil && resp.StatusCode < 400 {
			fmt.Printf("OK %s: HTTP %d\n", host, resp.StatusCode)
			return
		}
		fmt.Fprintf(os.Stderr, "FAIL %s reject=%t: response=%v error=%v\n", host, reject, resp, err)
		failed = true
	}
	for _, ca := range []string{"dv-g3b", "dv-g3c", "ev-g3b", "ev-g3c", "ov-g3b", "ov-g3c"} {
		check(ca+"-emudhra.we-have-a-problem.com", true)
		check(ca+"-aaa-emudhra.we-have-a-problem.com", true)
	}
	check("dv-g3b-noct-emudhra.we-have-a-problem.com", true)
	check("dv-g3b-aaa-noct-emudhra.we-have-a-problem.com", true)
	for _, host := range []string{"grafana.com", "proxy.golang.org", "pypi.org"} {
		check(host, false)
	}
	if failed {
		os.Exit(1)
	}
}
