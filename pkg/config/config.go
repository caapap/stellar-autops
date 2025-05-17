package config

import "stellar-autops/pkg/notify"

type Config struct {
	PrometheusURL   string       `yaml:"prometheus_url"`
	PrometheusK8s   string       `yaml:"prometheus-k8s"`
	MetricTypes     []MetricType `yaml:"metric_types"`
	ProjectName     string       `yaml:"project_name"`
	CronSchedule    string       `yaml:"cron_schedule"`
	Harbor          HarborConfig `yaml:"harbor"`
	ReportCleanup   struct {
		Enabled      bool   `yaml:"enabled"`
		MaxAge       int    `yaml:"max_age"`
		CronSchedule string `yaml:"cron_schedule"`
	} `yaml:"report_cleanup"`
	Notifications struct {
		Dingtalk notify.DingtalkConfig `yaml:"dingtalk"`
		Email    notify.EmailConfig    `yaml:"email"`
	} `yaml:"notifications"`
	Port string `yaml:"port"`
}

// HarborConfig Harbor仓库配置
type HarborConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Insecure bool   `yaml:"insecure"`
}

type MetricType struct {
	Type    string         `yaml:"type"`
	Metrics []MetricConfig `yaml:"metrics"`
}

type MetricConfig struct {
	Name          string            `yaml:"name"`
	Description   string            `yaml:"description"`
	Query         string            `yaml:"query"`
	Threshold     float64           `yaml:"threshold"`
	Unit          string            `yaml:"unit"`
	Labels        map[string]string `yaml:"labels"`
	ThresholdType string            `yaml:"threshold_type"`
	PrometheusURL string            `yaml:"prometheus_url"`
}

// GetK8sPrometheusURL 获取K8s Prometheus URL
func (c *Config) GetK8sPrometheusURL() string {
	if c.PrometheusK8s == "" {
		return ""
	}
	
	// 检查是否包含协议和端口
	if len(c.PrometheusK8s) > 0 && c.PrometheusK8s[0:4] == "http" {
		return c.PrometheusK8s
	}
	
	// 默认使用HTTP协议和13324端口，这是默认的K8s Prometheus端口
	return "http://" + c.PrometheusK8s + ":13324/"
}
