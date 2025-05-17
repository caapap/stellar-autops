package main

import (
	"log"
	"os"
	
	"stellar-autops/pkg/config"
	"stellar-autops/pkg/metrics"
	"stellar-autops/pkg/prometheus"
	"stellar-autops/pkg/report"
	
	"gopkg.in/yaml.v2"
)

func main() {
	// 加载配置
	configPath := "config/config.yaml"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}

	// 创建Prometheus客户端
	client, err := prometheus.NewClient(cfg.PrometheusURL)
	if err != nil {
		log.Fatalf("创建Prometheus客户端失败: %v", err)
	}

	// 创建收集器
	collector := metrics.NewCollector(client.API, &cfg)

	// 收集指标
	log.Println("开始收集指标...")
	reportData, err := collector.CollectMetrics()
	if err != nil {
		log.Fatalf("收集指标失败: %v", err)
	}
	
	// 生成报告
	log.Println("开始生成报告...")
	reportPath, err := report.GenerateReport(*reportData)
	if err != nil {
		log.Fatalf("生成报告失败: %v", err)
	}
	
	log.Printf("报告生成成功: %s", reportPath)
} 