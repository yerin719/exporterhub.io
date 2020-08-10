# [Exporterhub.io](https://exporterhub.io/)
> ### A Smart Uses of Curated List about all things Prometheus Exporter. 
> #### (powered by [nexclipper](https://nexclipper.io))

## Contents

- [What is ExporterHub.io](https://github.com/NexClipper/exporterhub.io#what-is-exporterhubio)
- [Roadmap](https://github.com/NexClipper/exporterhub.io#roadmap)
- [Official Exporters](https://github.com/NexClipper/exporterhub.io#official-exporters)
- [Exporters](https://github.com/NexClipper/exporterhub.io#exporters)
- [Integration Lists](https://github.com/NexClipper/exporterhub.io#integration-lists)
- [Contribute](https://github.com/NexClipper/exporterhub.io#contribute)
- [References](https://github.com/NexClipper/exporterhub.io#references)
- [License](https://github.com/NexClipper/exporterhub.io#license)

## What is [ExporterHub.io](https://exporterhub.io/)

### Exporterhub provides not only curated lists, but also various contents such as installing exporters, configuring alert rules, and configuring dashboards.

Each exporter's detail page contains the following.

- Official Github (Origin Repository)
- Resource (Install, Exported Metrics)
- Alert-rule (Recommended)
- Dashboard (Grafana)

ExporterHub.io is the front-end for the Community Prometheus Exporter Repository.   
If you have Specific exporter to contribute to ExporterHub.io, feel free to send issues or pull requests.   
Please read the pull request requirements before creating one to ensure all required files are present.

## Roadmap

* [x] Installation Guide, Metric Collection Flags, Recommend Alert-rule
* [ ] Card-Styled Github Pages
* [ ] Search Official Exporters
* [ ] Personalization
* [ ] NexClipper Cloud Integration

![exporterhub](./media/exporterhub.png)

## Official Exporters

[Consul Exporter](https://github.com/NexClipper/exporterhub.io/blob/master/lists/consul/index.md) - Export Consul service health to Prometheus.  
[Memcached Exporter](https://github.com/NexClipper/exporterhub.io/blob/master/lists/memcached/index.md) - Exports metrics from memcached servers for consumption by Prometheus.   
[MySQL Server Exporter](https://github.com/NexClipper/exporterhub.io/blob/master/lists/mysql/index.md) - Exporter for MySQL server metrics   
[Node Exporter](https://github.com/NexClipper/exporterhub.io/blob/master/lists/node/index.md) - Exporter for machine metrics   
[HAProxy Exporter](https://github.com/prometheus/haproxy_exporter) - About
Simple server that scrapes HAProxy stats and exports them via HTTP   
[CloudWatch Exporter](https://github.com/prometheus/cloudwatch_exporter) - Metrics exporter for Amazon AWS CloudWatch   
[Collectd Exporter](https://github.com/prometheus/collectd_exporter) - A server that accepts collectd stats via HTTP POST and exports them via HTTP   
[Graphite Exporter](https://github.com/prometheus/graphite_exporter) - Server that accepts metrics via the Graphite protocol and exports them   
[InfluxDB Exporter](https://github.com/prometheus/influxdb_exporter) - A server that accepts InfluxDB metrics via the HTTP API and exports them via HTTP  
[JMX Exporter](https://github.com/prometheus/jmx_exporter) - A process for exposing JMX Beans via HTTP for Prometheus consumption   
[SNMP Exporter](https://github.com/prometheus/snmp_exporter) - SNMP Exporter for Prometheus   
[Statsd Exporter](https://github.com/prometheus/statsd_exporter) - StatsD to Prometheus metrics exporter   
[Blackbox Exporter](https://github.com/prometheus/blackbox_exporter) - Blackbox prober exporter   


## Exporters

https://github.com/prometheus-community/windows_exporter   
https://github.com/prometheus-community/stackdriver_exporter   
https://github.com/oliver006/redis_exporter   
https://github.com/wrouesnel/postgres_exporter   
https://github.com/NVIDIA/gpu-monitoring-tools   
https://github.com/kbudde/rabbitmq_exporter   
https://github.com/digitalocean/ceph_exporter   
https://github.com/nginxinc/nginx-prometheus-exporter   
https://github.com/fstab/grok_exporter   
https://github.com/RobustPerception/azure_metrics_exporter   
https://github.com/google/cadvisor   
https://github.com/cloudflare/ebpf_exporter   
https://github.com/prometheus-community/json_exporter   
https://github.com/kubernetes/kube-state-metrics   
https://github.com/openstack-exporter/openstack-exporter   
https://github.com/ncabatoff/process-exporter   
https://github.com/Kong/kong-plugin-prometheus   

## Integration Lists

https://docs.ansible.com/ansible-tower/latest/html/administration/metrics.html   
https://github.com/purpleidea/mgmt/blob/master/docs/prometheus.md   
https://github.com/containous/traefik   
https://github.com/clj-commons/iapetos   
https://github.com/armon/go-metrics   
https://micrometer.io/docs/registry/prometheus   
https://github.com/prometheus/client_python   


## Contribute
Contributions are welcome!   
Feel free to send issues or pull requests.

## References
- [Official Exporters AND Integrations](https://prometheus.io/docs/instrumenting/exporters/)
- [Awesome Prometheus alerts](https://awesome-prometheus-alerts.grep.to/)
- [SLOs with Prometheus](https://promtools.dev/)
- [Awesome Prometheus](https://github.com/roaldnefs/awesome-prometheus)
- [Promcat](https://promcat.io/)


## License
Exporterhub.io is licensed under the MIT License. See [LICENSE](https://github.com/NexClipper/exporterhub.io/blob/master/LICENSE) for the full license text.