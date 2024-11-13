package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"code.crute.us/mcrute/golib/secrets"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/publicsuffix"
)

const (
	namespace = "unifinet"
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the Unifi Network Application instance queried successfully?",
		nil, nil,
	)
	adopted = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "adopted"),
		"Is the device adopted?",
		[]string{"site", "name", "mac"}, nil,
	)
	defaulted = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "defaulted"),
		"Is the device in default state?",
		[]string{"site", "name", "mac"}, nil,
	)
	disabled = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "disabled"),
		"Is the device disabled?",
		[]string{"site", "name", "mac"}, nil,
	)
	isolated = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "isolated"),
		"Is the device isolated?",
		[]string{"site", "name", "mac"}, nil,
	)
	unsupported = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unsupported"),
		"Is the device EOL, incompatible, or otherwise unsupported?",
		[]string{"site", "name", "mac"}, nil,
	)
	upgradeable = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "upgradeable"),
		"Does the device have a pending firmware upgrade?",
		[]string{"site", "name", "mac"}, nil,
	)
	lastSeen = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "last_seen"),
		"Unix timestamp of when the device was last seen by the controller.",
		[]string{"site", "name", "mac"}, nil,
	)
	lastSeenSecs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "last_seen_secs"),
		"Number of seconds from when the device was last seen by the controller.",
		[]string{"site", "name", "mac"}, nil,
	)
	uptime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "uptime"),
		"Number of seconds the device has been running.",
		[]string{"site", "name", "mac"}, nil,
	)
	cpuPercent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cpu_percent"),
		"Percentage of the CPU that is currently used.",
		[]string{"site", "name", "mac"}, nil,
	)
	memTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "mem_total"),
		"Total megabytes of memory on the device.",
		[]string{"site", "name", "mac"}, nil,
	)
	memUsed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "mem_used"),
		"Total megabytes of memory currently in use on the device.",
		[]string{"site", "name", "mac"}, nil,
	)
	loadAvg1 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "load_avg_one"),
		"One minute load average for the device.",
		[]string{"site", "name", "mac"}, nil,
	)
	loadAvg5 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "load_avg_five"),
		"Five minute load average for the device.",
		[]string{"site", "name", "mac"}, nil,
	)
	loadAvg15 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "load_avg_fifteen"),
		"Fifteen minute load average for the device.",
		[]string{"site", "name", "mac"}, nil,
	)
)

type unifiDevice struct {
	Adopted       bool   `json:"adopted"`
	Default       bool   `json:"default"`
	Disabled      bool   `json:"disabled"`
	Isolated      bool   `json:"isolated"`
	EOL           bool   `json:"model_in_eol"`
	Incompatible  bool   `json:"model_incompatible"`
	Restarting    bool   `json:"restarting"`
	Unsupported   bool   `json:"unsupported"`
	Upgradeable   bool   `json:"upgradable"`
	Name          string `json:"name"`
	IP            net.IP
	MAC           net.HardwareAddr
	LastSeen      time.Time
	Uptime        time.Duration
	CPUPercent    float64
	MemoryPercent float64
	LoadAvg1      float64
	LoadAvg5      float64
	LoadAvg15     float64
	MemTotal      int
	MemUsed       int
}

func (u *unifiDevice) UnmarshalJSON(d []byte) error {
	type Alias unifiDevice

	dev := struct {
		IP       string `json:"ip"`
		MAC      string `json:"mac"`
		LastSeen int64  `json:"last_seen"`
		Uptime   int64  `json:"uptime"`
		Stats1   struct {
			CPU    float64 `json:"cpu"`
			Memory float64 `json:"mem"`
		} `json:"system-stats"`
		Stats2 struct {
			LoadAvg1  float64 `json:"loadavg_1"`
			LoadAvg5  float64 `json:"loadavg_5"`
			LoadAvg15 float64 `json:"loadavg_15"`
			MemTotal  int     `json:"mem_total"`
			MemUsed   int     `json:"mem_used"`
		} `json:"sys_stats"`
		*Alias
	}{Alias: (*Alias)(u)}

	if err := json.Unmarshal(d, &dev); err != nil {
		return err
	}

	mac, err := net.ParseMAC(dev.MAC)
	if err != nil {
		return err
	}

	u.MAC = mac
	u.Uptime = time.Duration(dev.Uptime * 1_000_000_000)
	u.LastSeen = time.Unix(dev.LastSeen, 0)
	u.IP = net.ParseIP(dev.IP)
	u.CPUPercent = dev.Stats1.CPU
	u.MemoryPercent = dev.Stats1.Memory
	u.LoadAvg1 = dev.Stats2.LoadAvg1
	u.LoadAvg5 = dev.Stats2.LoadAvg5
	u.LoadAvg15 = dev.Stats2.LoadAvg15
	u.MemTotal = dev.Stats2.MemTotal
	u.MemUsed = dev.Stats2.MemUsed

	return nil
}

type unifiDeviceInfo struct {
	Devices []unifiDevice `json:"network_devices"`
}

type unifiInfo struct {
	Sites []struct {
		Name        string `json:"name"`
		Description string `json:"desc"`
		DeviceCount int    `json:"device_count"`
	} `json:"sites"`
}

type UnifiCollector struct {
	url    *url.URL
	auth   []byte
	client *http.Client
}

func NewUnifiCollector(hostname, username, password string) (c *UnifiCollector, err error) {
	c = &UnifiCollector{}

	c.url, err = url.Parse(hostname)
	if err != nil {
		return nil, err
	}

	cj, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	c.client = &http.Client{
		Jar: cj,
	}

	c.auth, err = json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *UnifiCollector) fetchStats() (map[string]unifiDeviceInfo, error) {
	u := *c.url

	u.Path = "/api/login"
	res, err := c.client.Post(u.String(), "application/json", bytes.NewReader(c.auth))
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, err
	}

	u.Path = "/v2/api/info"
	res, err = c.client.Get(u.String())
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, err
	}

	var info unifiInfo
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return nil, err
	}
	res.Body.Close()

	siteStats := map[string]unifiDeviceInfo{}

	for _, site := range info.Sites {
		if site.Name == "default" {
			continue
		}

		u.Path = fmt.Sprintf("/v2/api/site/%s/device", site.Name)
		u.RawQuery = "separateUnmanaged=true&includeTrafficUsage=true"

		res, err = c.client.Get(u.String())
		if err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusOK {
			return nil, err
		}

		var stats unifiDeviceInfo
		if err := json.NewDecoder(res.Body).Decode(&stats); err != nil {
			return nil, err
		}
		res.Body.Close()

		siteStats[site.Description] = stats
	}

	return siteStats, nil
}

func (c *UnifiCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- adopted
	ch <- defaulted
	ch <- disabled
	ch <- isolated
	ch <- unsupported
	ch <- upgradeable
	ch <- lastSeen
	ch <- lastSeenSecs
	ch <- uptime
	ch <- cpuPercent
	ch <- memTotal
	ch <- memUsed
	ch <- loadAvg1
	ch <- loadAvg5
	ch <- loadAvg15
}

func (c *UnifiCollector) Collect(ch chan<- prometheus.Metric) {
	stats, err := c.fetchStats()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, 0)
		return
	} else {
		ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, 1)
	}

	for site, stats := range stats {
		for _, device := range stats.Devices {
			ch <- prometheus.MustNewConstMetric(
				adopted, prometheus.GaugeValue, boolsToFloat(device.Adopted),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				defaulted, prometheus.GaugeValue, boolsToFloat(device.Default),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				disabled, prometheus.GaugeValue, boolsToFloat(device.Disabled),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				isolated, prometheus.GaugeValue, boolsToFloat(device.Isolated),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				unsupported, prometheus.GaugeValue,
				boolsToFloat(device.EOL, device.Incompatible, device.Unsupported),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				upgradeable, prometheus.GaugeValue, boolsToFloat(device.Upgradeable),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				lastSeen, prometheus.GaugeValue, float64(device.LastSeen.Unix()),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				lastSeenSecs, prometheus.GaugeValue,
				float64(time.Since(device.LastSeen).Seconds()),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				uptime, prometheus.GaugeValue, float64(device.Uptime.Seconds()),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				cpuPercent, prometheus.GaugeValue, device.CPUPercent,
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				memTotal, prometheus.GaugeValue, float64(device.MemTotal),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				memUsed, prometheus.GaugeValue, float64(device.MemUsed),
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				loadAvg1, prometheus.GaugeValue, device.LoadAvg1,
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				loadAvg5, prometheus.GaugeValue, device.LoadAvg5,
				site, device.Name, device.MAC.String(),
			)
			ch <- prometheus.MustNewConstMetric(
				loadAvg15, prometheus.GaugeValue, device.LoadAvg15,
				site, device.Name, device.MAC.String(),
			)
		}
	}
}

// boolsToFloat returns 1 if and only if all passed boolean values are
// true, otherwise zero
func boolsToFloat(b ...bool) float64 {
	for _, i := range b {
		if !i {
			return 0
		}
	}
	return 1
}

func getUsernamePassword(ctx context.Context, path string) (string, string, error) {
	// Allow making Vault optional by providing the username and password
	// in the environment
	username := os.Getenv("UNIFI_USERNAME")
	password := os.Getenv("UNIFI_PASSWORD")
	if username != "" && password != "" {
		return username, password, nil
	}

	// Otherwise fall back to querying Vault
	client, err := secrets.NewVaultClient(nil)
	if err != nil {
		return "", "", err
	}

	if err := client.Authenticate(ctx); err != nil {
		return "", "", err
	}

	var cred secrets.Credential
	if _, err := client.Secret(ctx, path, &cred); err != nil {
		return "", "", err
	}

	return cred.Username, cred.Password, nil
}

func main() {
	hostname := flag.String("hostname", "", "Unifi network application hostname")
	bind := flag.String("bind", ":9120", "Bind address for http server")
	vaultPath := flag.String("vault-path", "", "Vault path for Unifi network application login")
	flag.Parse()

	if *hostname == "" {
		log.Fatalf("--hostname must be specified")
	}

	username, password, err := getUsernamePassword(context.Background(), *vaultPath)
	if err != nil {
		log.Fatalf("error fetching Vault credentials: %s", err)
	}

	collector, err := NewUnifiCollector(*hostname, username, password)
	if err != nil {
		log.Fatalf("error building collector: %s", err)
	}

	prometheus.MustRegister(collector)
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<h1>Unifi Device Exporter</h1><pre><a href="/metrics">/metrics</a></pre>`)
	})

	log.Printf("HTTP server listening on %s", *bind)
	if err := http.ListenAndServe(*bind, nil); err != nil {
		log.Fatalf("error running web server: %s", err)
	}
}
