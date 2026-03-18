package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

type Forwarder struct {
	upstream    string
	homelabZone string
	domainRemap map[string]string
	udpClient   dns.Client
	tcpClient   dns.Client
}

const localTLD = "local"

func main() {
	dnsListen := flag.String("listen", ":53", "DNS listen address")
	tsHostname := flag.String("ts-hostname", "tsdns", "Tailscale hostname")
	tsStateDir := flag.String("ts-state-dir", "", "Tailscale state directory")
	homelabZone := flag.String("homelab-zone", "homelab", "Homelab zone used for remapping (for example: homelab)")
	advertiseRoute := flag.String("advertise-route", "", "CIDR route prefix to advertise to tailnet (for example: 10.42.0.0/24)")
	flag.Parse()
	ctx := context.Background()
	zone := strings.Trim(strings.ToLower(*homelabZone), ".")
	if zone == "" {
		log.Fatalf("invalid -homelab-zone %q", *homelabZone)
	}

	ts := &tsnet.Server{
		Hostname: *tsHostname,
		Dir:      *tsStateDir,
	}
	defer func() {
		_ = ts.Close()
	}()

	if _, err := ts.Up(ctx); err != nil {
		log.Fatalf("tailscale bring-up failed: %v", err)
	}

	if *advertiseRoute != "" {
		prefix, err := netip.ParsePrefix(*advertiseRoute)
		if err != nil {
			log.Fatalf("invalid -advertise-route %q: %v", *advertiseRoute, err)
		}
		lc, err := ts.LocalClient()
		if err != nil {
			log.Fatalf("tailscale local client failed: %v", err)
		}
		_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				AdvertiseRoutes: []netip.Prefix{prefix},
			},
			AdvertiseRoutesSet: true,
		})
		if err != nil {
			log.Fatalf("failed to advertise route %s: %v", prefix, err)
		}
		log.Printf("advertised route prefix to tailnet: %s", prefix)
	}

	upstream, err := defaultSystemResolver()
	if err != nil {
		log.Fatalf("failed to read system resolver: %v", err)
	}

	forwarder := &Forwarder{
		upstream:    upstream,
		homelabZone: zone,
		// Placeholder for future domain remapping rules.
		domainRemap: map[string]string{},
		udpClient:   dns.Client{Net: "udp"},
		tcpClient:   dns.Client{Net: "tcp"},
	}

	dns.HandleFunc(".", forwarder.handleRequest)

	udpServer := &dns.Server{Addr: *dnsListen, Net: "udp"}
	tcpServer := &dns.Server{Addr: *dnsListen, Net: "tcp"}

	errCh := make(chan error, 2)
	go func() {
		errCh <- udpServer.ListenAndServe()
	}()
	go func() {
		errCh <- tcpServer.ListenAndServe()
	}()

	log.Printf("dns forwarder listening on %s (udp/tcp), upstream %s", *dnsListen, upstream)
	if serveErr := <-errCh; serveErr != nil {
		log.Fatalf("dns server failed: %v", serveErr)
	}

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
}

func defaultSystemResolver() (string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	if len(cfg.Servers) == 0 {
		return "", fmt.Errorf("no system DNS servers in /etc/resolv.conf")
	}
	port := cfg.Port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(cfg.Servers[0], port), nil
}

func (f *Forwarder) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	req := r.Copy()
	f.applyDomainRemap(req)

	resp, _, err := f.udpClient.Exchange(req, f.upstream)
	if err == nil && resp != nil && resp.Truncated {
		resp, _, err = f.tcpClient.Exchange(req, f.upstream)
	}

	if err != nil || resp == nil {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}

	resp.Id = r.Id
	_ = w.WriteMsg(resp)
}

func (f *Forwarder) applyDomainRemap(req *dns.Msg) {
	for i := range req.Question {
		name := dns.Fqdn(req.Question[i].Name)
		if mapped, ok := f.domainRemap[name]; ok {
			req.Question[i].Name = dns.Fqdn(mapped)
			continue
		}
		if mapped, ok := remapHomelabName(name, f.homelabZone); ok {
			req.Question[i].Name = mapped
		}
	}
}

func remapHomelabName(name, homelabZone string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if len(labels) != 4 {
		return "", false
	}
	service := labels[0]
	project := labels[1]
	zone := labels[2]
	tld := labels[3]
	if zone != homelabZone || tld != localTLD {
		return "", false
	}
	if service == "" || project == "" {
		return "", false
	}
	mapped := fmt.Sprintf("%s-%s-1.", project, service)
	return mapped, true
}
