package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
	"crypto/tls"
	"io/ioutil"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"stellar-autops/pkg/config"
	"stellar-autops/pkg/report"
	"stellar-autops/pkg/prometheus"
)

// Collector 处理指标收集
type Collector struct {
	Client      PrometheusAPI
	config      *config.Config
	clientCache map[string]PrometheusAPI // 用于缓存不同URL的客户端
}

type PrometheusAPI interface {
	Query(ctx context.Context, query string, ts time.Time, opts ...v1.Option) (model.Value, v1.Warnings, error)
	QueryRange(ctx context.Context, query string, r v1.Range, opts ...v1.Option) (model.Value, v1.Warnings, error)
}

// NewCollector 创建新的收集器
func NewCollector(client PrometheusAPI, config *config.Config) *Collector {
	return &Collector{
		Client:      client,
		config:      config,
		clientCache: make(map[string]PrometheusAPI), // 初始化客户端缓存
	}
}

// getClientForMetric 根据指标配置获取合适的Prometheus客户端
func (c *Collector) getClientForMetric(metric config.MetricConfig) (PrometheusAPI, error) {
	// 如果指标没有指定Prometheus URL，使用默认客户端
	if metric.PrometheusURL == "" {
		return c.Client, nil
	}

	// 如果已经有此URL的客户端缓存，直接使用
	if client, ok := c.clientCache[metric.PrometheusURL]; ok {
		return client, nil
	}

	// 否则，创建新的客户端
	promClient, err := prometheus.NewClient(metric.PrometheusURL)
	if err != nil {
		return nil, fmt.Errorf("为指标 %s 创建Prometheus客户端失败: %w", metric.Name, err)
	}

	// 缓存客户端
	c.clientCache[metric.PrometheusURL] = promClient.API
	return promClient.API, nil
}

// CollectNodeHealth 收集节点健康状态
func (c *Collector) CollectNodeHealth() (*report.NodeHealth, error) {
	ctx := context.Background()
	k8sPrometheusURL := c.config.GetK8sPrometheusURL()
	
	// 获取适用于K8s的Prometheus客户端
	var k8sClient PrometheusAPI
	var err error
	
	if k8sPrometheusURL != "" {
		// 使用K8s特定的Prometheus
		promClient, err := prometheus.NewClient(k8sPrometheusURL)
		if err != nil {
			return nil, fmt.Errorf("创建K8s Prometheus客户端失败: %w", err)
		}
		k8sClient = promClient.API
	} else {
		// 使用默认客户端
		k8sClient = c.Client
	}
	
	// 查询就绪节点数
	readyResult, _, err := k8sClient.Query(ctx, "sum(kube_node_status_condition{condition='Ready'})", time.Now())
	if err != nil {
		return nil, fmt.Errorf("查询就绪节点数失败: %w", err)
	}
	
	// 查询未就绪节点数
	notReadyResult, _, err := k8sClient.Query(ctx, "sum(kube_node_status_condition{condition='Ready',status!='true'})", time.Now())
	if err != nil {
		return nil, fmt.Errorf("查询未就绪节点数失败: %w", err)
	}
	
	// 查询集群CPU使用率
	cpuResult, _, err := k8sClient.Query(ctx, "avg(1 - rate(node_cpu_seconds_total{mode='idle'}[2m])) by (node)", time.Now())
	if err != nil {
		log.Printf("警告: 查询集群CPU使用率失败: %v", err)
	}
	
	// 查询集群内存使用率
	memResult, _, err := k8sClient.Query(ctx, "max(100 * (1 - ((avg_over_time(node_memory_MemFree_bytes[10m]) + avg_over_time(node_memory_Cached_bytes[10m]) + avg_over_time(node_memory_Buffers_bytes[10m])) / avg_over_time(node_memory_MemTotal_bytes[10m])))) by (node)", time.Now())
	if err != nil {
		log.Printf("警告: 查询集群内存使用率失败: %v", err)
	}
	
	nodeHealth := &report.NodeHealth{}
	
	// 解析结果
	if readyVector, ok := readyResult.(model.Vector); ok && len(readyVector) > 0 {
		nodeHealth.Ready = int(readyVector[0].Value)
	}
	
	if notReadyVector, ok := notReadyResult.(model.Vector); ok && len(notReadyVector) > 0 {
		nodeHealth.NotReady = int(notReadyVector[0].Value)
	}
	
	// 计算CPU使用率平均值
	if cpuVector, ok := cpuResult.(model.Vector); ok && len(cpuVector) > 0 {
		var totalCPU float64
		for _, sample := range cpuVector {
			totalCPU += float64(sample.Value)
		}
		// 将值转换为百分比
		nodeHealth.ClusterCPUUsage = totalCPU / float64(len(cpuVector)) * 100
	}
	
	// 计算内存使用率最大值
	if memVector, ok := memResult.(model.Vector); ok && len(memVector) > 0 {
		maxMem := 0.0
		for _, sample := range memVector {
			if float64(sample.Value) > maxMem {
				maxMem = float64(sample.Value)
			}
		}
		nodeHealth.ClusterMemoryUsage = maxMem
	}
	
	// 总节点数 = 就绪节点数 + 未就绪节点数
	nodeHealth.Total = nodeHealth.Ready + nodeHealth.NotReady
	
	return nodeHealth, nil
}

// CollectHarborHealth 收集Harbor健康状态
func (c *Collector) CollectHarborHealth() (*report.HarborHealth, error) {
	// 检查Harbor是否启用
	if !c.config.Harbor.Enabled {
		return nil, nil
	}
	
	// 创建HTTP客户端，支持忽略SSL证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.config.Harbor.Insecure},
	}
	client := &http.Client{Transport: tr}
	
	// 构建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v2.0/health", c.config.Harbor.URL), nil)
	if err != nil {
		return nil, fmt.Errorf("创建Harbor健康检查请求失败: %w", err)
	}
	
	// 添加认证
	req.SetBasicAuth(c.config.Harbor.Username, c.config.Harbor.Password)
	
	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问Harbor健康检查API失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取Harbor健康检查响应失败: %w", err)
	}
	
	// 解析JSON
	var healthData report.HarborHealth
	if err := json.Unmarshal(body, &healthData); err != nil {
		return nil, fmt.Errorf("解析Harbor健康检查响应失败: %w", err)
	}
	
	return &healthData, nil
}

// CollectPodStatus 收集Pod运行状态（硬编码实现，替代配置文件中的定义）
func (c *Collector) CollectPodStatus(ctx context.Context, data *report.ReportData) error {
	// 获取K8s专用的Prometheus客户端
	k8sPrometheusURL := c.config.GetK8sPrometheusURL() // 从配置中获取K8s Prometheus URL
	
	var k8sClient PrometheusAPI
	var err error
	
	// 创建或获取K8s Prometheus客户端
	if k8sPrometheusURL == "" {
		// 如果配置中没有K8s Prometheus URL，使用默认的Prometheus客户端
		k8sClient = c.Client
	} else if client, ok := c.clientCache[k8sPrometheusURL]; ok {
		// 使用缓存的客户端
		k8sClient = client
	} else {
		// 创建新的客户端
		promClient, err := prometheus.NewClient(k8sPrometheusURL)
		if err != nil {
			return fmt.Errorf("创建K8s Prometheus客户端失败: %w", err)
		}
		k8sClient = promClient.API
		c.clientCache[k8sPrometheusURL] = k8sClient
	}
	
	// 执行Pod状态查询
	// 使用与配置文件中相同的查询语句
	query := "sum by (namespace, pod, phase) (kube_pod_status_phase == 1)"
	result, _, err := k8sClient.Query(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("查询Pod运行状态失败: %w", err)
	}
	
	// 确保基础资源使用情况组存在
	metricType := "基础资源使用情况"
	if _, exists := data.MetricGroups[metricType]; !exists {
		data.MetricGroups[metricType] = &report.MetricGroup{
			Type:          metricType,
			MetricsByName: make(map[string][]report.MetricData),
		}
	}
	
	// 指标名称和描述
	metricName := "Pod运行状态"
	description := "集群Pod运行状态统计"
	
	// 处理查询结果
	if vector, ok := result.(model.Vector); ok {
		metrics := make([]report.MetricData, 0, len(vector))
		
		for _, sample := range vector {
			log.Printf("指标 [%s] 原始数据: %+v, 值: %+v", metricName, sample.Metric, sample.Value)
			
			// 提取标签值
			namespace := string(sample.Metric["namespace"])
			pod := string(sample.Metric["pod"])
			phase := string(sample.Metric["phase"])
			
			// 构建标签列表
			labels := []report.LabelData{
				{
					Name:  "namespace",
					Alias: "命名空间",
					Value: namespace,
				},
				{
					Name:  "pod",
					Alias: "Pod名称",
					Value: pod,
				},
				{
					Name:  "phase",
					Alias: "运行状态",
					Value: phase,
				},
			}
			
			// 创建指标数据
			metricData := report.MetricData{
				Name:        metricName,
				Description: description,
				Value:       float64(sample.Value),
				Threshold:   1, // 配置文件中的值
				Unit:        "", // 配置文件中的值
				Status:      getStatus(float64(sample.Value), 1, "equal"),
				StatusText:  report.GetStatusText(getStatus(float64(sample.Value), 1, "equal")),
				Timestamp:   time.Now(),
				Labels:      labels,
			}
			
			metrics = append(metrics, metricData)
		}
		
		// 将指标数据添加到报告中
		data.MetricGroups[metricType].MetricsByName[metricName] = metrics
	}
	
	return nil
}

// CollectBasicResourceMetrics 收集基础资源类指标（硬编码实现）
func (c *Collector) CollectBasicResourceMetrics(ctx context.Context, data *report.ReportData) error {
	promClient := c.Client
	metricType := "基础资源使用情况"
	if _, exists := data.MetricGroups[metricType]; !exists {
		data.MetricGroups[metricType] = &report.MetricGroup{
			Type:          metricType,
			MetricsByName: make(map[string][]report.MetricData),
		}
	}
	group := data.MetricGroups[metricType]

	// 1. CPU使用率
	cpuQuery := "avg by(ident) (cpu_usage_active)"
	cpuResult, _, err := promClient.Query(ctx, cpuQuery, time.Now())
	if err == nil {
		metrics := make([]report.MetricData, 0)
		if vector, ok := cpuResult.(model.Vector); ok {
			for _, sample := range vector {
				ident := string(sample.Metric["ident"])
				labels := []report.LabelData{{Name: "ident", Alias: "节点名称", Value: ident}}
				metricData := report.MetricData{
					Name:        "CPU使用率",
					Description: "节点CPU使用率统计",
					Value:       float64(sample.Value),
					Threshold:   80,
					Unit:        "%",
					Status:      getStatus(float64(sample.Value), 80, "greater"),
					StatusText:  report.GetStatusText(getStatus(float64(sample.Value), 80, "greater")),
					Timestamp:   time.Now(),
					Labels:      labels,
				}
				metrics = append(metrics, metricData)
			}
		}
		group.MetricsByName["CPU使用率"] = metrics
	}

	// 2. 内存使用率
	memQuery := "avg by(ident) (mem_used_percent)"
	memResult, _, err := promClient.Query(ctx, memQuery, time.Now())
	if err == nil {
		metrics := make([]report.MetricData, 0)
		if vector, ok := memResult.(model.Vector); ok {
			for _, sample := range vector {
				ident := string(sample.Metric["ident"])
				labels := []report.LabelData{{Name: "ident", Alias: "节点名称", Value: ident}}
				metricData := report.MetricData{
					Name:        "内存使用率",
					Description: "节点内存使用率统计",
					Value:       float64(sample.Value),
					Threshold:   85,
					Unit:        "%",
					Status:      getStatus(float64(sample.Value), 85, "greater"),
					StatusText:  report.GetStatusText(getStatus(float64(sample.Value), 85, "greater")),
					Timestamp:   time.Now(),
					Labels:      labels,
				}
				metrics = append(metrics, metricData)
			}
		}
		group.MetricsByName["内存使用率"] = metrics
	}

	// 3. 系统运行时间
	uptimeQuery := "system_uptime"
	uptimeResult, _, err := promClient.Query(ctx, uptimeQuery, time.Now())
	if err == nil {
		metrics := make([]report.MetricData, 0)
		if vector, ok := uptimeResult.(model.Vector); ok {
			for _, sample := range vector {
				ident := string(sample.Metric["ident"])
				labels := []report.LabelData{{Name: "ident", Alias: "节点名称", Value: ident}}
				metricData := report.MetricData{
					Name:        "系统运行时间",
					Description: "节点系统运行时间",
					Value:       float64(sample.Value),
					Threshold:   0,
					Unit:        "秒",
					Status:      getStatus(float64(sample.Value), 0, "greater"),
					StatusText:  report.GetStatusText(getStatus(float64(sample.Value), 0, "greater")),
					Timestamp:   time.Now(),
					Labels:      labels,
				}
				metrics = append(metrics, metricData)
			}
		}
		group.MetricsByName["系统运行时间"] = metrics
	}

	// 4. 根分区磁盘使用率
	diskQuery := "avg by(ident, path, device) (disk_used_percent{path=~'/'})"
	diskResult, _, err := promClient.Query(ctx, diskQuery, time.Now())
	if err == nil {
		metrics := make([]report.MetricData, 0)
		if vector, ok := diskResult.(model.Vector); ok {
			for _, sample := range vector {
				ident := string(sample.Metric["ident"])
				path := string(sample.Metric["path"])
				device := string(sample.Metric["device"])
				labels := []report.LabelData{
					{Name: "ident", Alias: "节点名称", Value: ident},
					{Name: "path", Alias: "挂载点", Value: path},
					{Name: "device", Alias: "磁盘", Value: device},
				}
				metricData := report.MetricData{
					Name:        "根分区磁盘使用率",
					Description: "根分区磁盘使用率统计",
					Value:       float64(sample.Value),
					Threshold:   80,
					Unit:        "%",
					Status:      getStatus(float64(sample.Value), 80, "greater"),
					StatusText:  report.GetStatusText(getStatus(float64(sample.Value), 80, "greater")),
					Timestamp:   time.Now(),
					Labels:      labels,
				}
				metrics = append(metrics, metricData)
			}
		}
		group.MetricsByName["根分区磁盘使用率"] = metrics
	}

	return nil
}

// CollectMetrics 收集指标数据
func (c *Collector) CollectMetrics() (*report.ReportData, error) {
	ctx := context.Background()

	data := &report.ReportData{
		Timestamp:    time.Now(),
		MetricGroups: make(map[string]*report.MetricGroup),
		ChartData:    make(map[string]template.JS),
		Project:      c.config.ProjectName,
	}
	
	// 收集节点健康状态
	nodeHealth, err := c.CollectNodeHealth()
	if err != nil {
		log.Printf("警告: 收集节点健康状态失败: %v", err)
	} else {
		data.NodeHealth = nodeHealth
	}
	
	// 收集Harbor健康状态
	harborHealth, err := c.CollectHarborHealth()
	if err != nil {
		log.Printf("警告: 收集Harbor健康状态失败: %v", err)
	} else {
		data.HarborHealth = harborHealth
	}

	// 硬编码收集基础资源类指标
	if err := c.CollectBasicResourceMetrics(ctx, data); err != nil {
		log.Printf("警告: 收集基础资源类指标失败: %v", err)
	}

	// 硬编码收集Pod运行状态
	if err := c.CollectPodStatus(ctx, data); err != nil {
		log.Printf("警告: 收集Pod运行状态失败: %v", err)
	}

	// 收集自定义指标项组
	customType := "自定义指标项组"
	data.MetricGroups[customType] = &report.MetricGroup{
		Type:          customType,
		MetricsByName: make(map[string][]report.MetricData),
	}
	customGroup := data.MetricGroups[customType]

	// 遍历配置中的指标，收集未被硬编码的指标（如/iflytek分区磁盘使用率及用户自定义项）
	hardcodedNames := map[string]bool{
		"CPU使用率": true,
		"内存使用率": true,
		"系统运行时间": true,
		"根分区磁盘使用率": true,
		"Pod运行状态": true,
	}
	for _, metricType := range c.config.MetricTypes {
		for _, metric := range metricType.Metrics {
			if hardcodedNames[metric.Name] {
				continue
			}
			// 获取或创建此指标的Prometheus客户端
			client, err := c.getClientForMetric(metric)
			if err != nil {
				log.Printf("警告: 获取自定义指标 %s 的Prometheus客户端失败: %v", metric.Name, err)
				continue
			}
			result, _, err := client.Query(ctx, metric.Query, time.Now())
			if err != nil {
				log.Printf("警告: 查询自定义指标 %s 失败: %v", metric.Name, err)
				continue
			}
			switch v := result.(type) {
			case model.Vector:
				metrics := make([]report.MetricData, 0, len(v))
				for _, sample := range v {
					availableLabels := make(map[string]string)
					for labelName, labelValue := range sample.Metric {
						availableLabels[string(labelName)] = string(labelValue)
					}
					labels := make([]report.LabelData, 0, len(metric.Labels))
					for configLabel, configAlias := range metric.Labels {
						labelValue := "-"
						if rawValue, exists := availableLabels[configLabel]; exists && rawValue != "" {
							labelValue = rawValue
						}
						labels = append(labels, report.LabelData{
							Name:  configLabel,
							Alias: configAlias,
							Value: labelValue,
						})
					}
					metricData := report.MetricData{
						Name:        metric.Name,
						Description: metric.Description,
						Value:       float64(sample.Value),
						Threshold:   metric.Threshold,
						Unit:        metric.Unit,
						Status:      getStatus(float64(sample.Value), metric.Threshold, metric.ThresholdType),
						StatusText:  report.GetStatusText(getStatus(float64(sample.Value), metric.Threshold, metric.ThresholdType)),
						Timestamp:   time.Now(),
						Labels:      labels,
					}
					metrics = append(metrics, metricData)
				}
				customGroup.MetricsByName[metric.Name] = metrics
			}
		}
	}
	return data, nil
}

// validateMetricData 验证指标数据的完整性
func validateMetricData(data report.MetricData, configLabels map[string]string) error {
	if len(data.Labels) != len(configLabels) {
		return fmt.Errorf("标签数量不匹配: 期望 %d, 实际 %d",
			len(configLabels), len(data.Labels))
	}

	labelMap := make(map[string]bool)
	for _, label := range data.Labels {
		if _, exists := configLabels[label.Name]; !exists {
			return fmt.Errorf("发现未配置的标签: %s", label.Name)
		}
		if label.Value == "" || label.Value == "-" {
			return fmt.Errorf("标签 %s 值为空", label.Name)
		}
		labelMap[label.Name] = true
	}

	return nil
}

// getStatus 获取状态
func getStatus(value, threshold float64, thresholdType string) string {
	if thresholdType == "" {
		thresholdType = "greater"
	}
	switch thresholdType {
	case "greater":
		if value > threshold {
			return "critical"
		} else if value >= threshold*0.8 {
			return "warning"
		}
	case "greater_equal":
		if value >= threshold {
			return "critical"
		} else if value >= threshold*0.8 {
			return "warning"
		}
	case "less":
		if value < threshold {
			return "normal"
		} else if value <= threshold*1.2 {
			return "warning"
		}
	case "less_equal":
		if value <= threshold {
			return "normal"
		} else if value <= threshold*1.2 {
			return "warning"
		}
	case "equal":
		if value == threshold {
			return "normal"
		} else if value > threshold {
			return "critical"
		}
		return "critical"
	}
	return "normal"
}

// validateLabels 验证标签数据的完整性
func validateLabels(labels []report.LabelData) bool {
	for _, label := range labels {
		if label.Value == "" || label.Value == "-" {
			return false
		}
	}
	return true
}

