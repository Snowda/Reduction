# Reduction

> Opinionated Rust Reverse Proxy

## Features

### Load Balancing:

* Distributes incoming web traffic across multiple backend servers to prevent overloads and ensure high availability.

### SSL/TLS Termination

* Offloads the heavy computational work of encrypting and decrypting HTTPS traffic from your backend servers.

### Caching

* Stores frequently requested static and dynamic content at the proxy level, significantly decreasing load times and origin server strain.

### Compression

* Compressed with Zstd. Deal with it.

### Security & Obfuscation

* Conceals the topology and IP addresses of your internal servers. It also acts as a frontline defense against DDoS attacks by blocking suspicious IPs or limiting connection rates.

### Centralized Authentication

* Intercepts client requests and validates authentication tokens or credentials before allowing traffic to reach the actual application servers.

### Routing & Virtual Hosting

* Analyzes incoming requests (using exact paths or domain names) and correctly routes them to the right microservice, application, or internal port.

### Networks

* TCP
* UDP
* HTTPS
* QUIC
* No SSH support

* gRPC over rustls

* Hot configuration reload
* TLS support
* CORS support

### Configuration

* Configuration is done in TOML

### Metrics

* OTel support
* Prometheus support

### Serialization

* Payload serialization using Bitcode
