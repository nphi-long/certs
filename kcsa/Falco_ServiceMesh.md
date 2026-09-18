# KCSA Study Notes — Platform Security: Observability (Falco) & Service Mesh (Istio)

Tổng hợp 8 bài trong section Platform Security: Observability Overview, Falco Overview and Installation, Using Falco to Detect Threats, Monolithics vs Microservices, Service Mesh, Service Mesh Istio, Security in Istio, Istio Security Architecture.

---

## PHẦN A: OBSERVABILITY & FALCO

## 1. Observability Overview

### Vì sao Early Detection quan trọng
Ngay cả khi đã hardening control plane, workload isolation, sandboxing, mTLS, và NetworkPolicy chặt chẽ, attacker vẫn có thể tìm được đường vào. Observability giúp phát hiện compromise SỚM, giảm blast radius, và phục hồi nhanh chóng.

5 kỹ thuật bảo mật đã học trong course (nền tảng trước Observability):
```
Securing Cluster | Sandboxing Techniques | Restricting Network Access |
Minimizing Microservices Vulnerability | mTLS Encryption
```

### Analogy — Cảnh báo thẻ tín dụng
Giống ngân hàng gửi cảnh báo tức thời khi có giao dịch thẻ bất thường (Instant Notifications, Revert Transactions, Transaction Limits), khi 1 container bị compromise:
- Instant alert cho biết KHI NÀO và Ở ĐÂU breach xảy ra
- Automated workflow có thể cô lập hoặc thay thế Pod bị ảnh hưởng
- Policy limit (resource quota, network policy) giới hạn tác động

### Falco là gì
Falco là dự án runtime security mã nguồn mở của **Sysdig**. Falco hook vào Linux kernel để bắt syscall từ container và áp dụng rule để phát hiện:
- **Unexpected shell access** bên trong container
- **Reading sensitive files** như `/etc/shadow`
- **Deleting or truncating logs** để xoá dấu vết

> Falco cần quyền privileged để giám sát syscall — phải deploy với đúng securityContext và RBAC.

### Bảng Indicator of Compromise (IoC)

| Suspicious Activity | Description |
|---|---|
| Unexpected shell trong container | `kubectl exec -ti <pod> -- bash` mở interactive shell |
| Truy cập password hash | `cat /etc/shadow` |
| Xoá/truncate audit log | `> /opt/logs/audit.log` |

Ví dụ session Falco sẽ flag:
```bash
kubectl exec -ti nginx-master -- bash
cat /etc/shadow
> /opt/logs/audit.log
```

> Cảnh báo quan trọng: Suppressing Falco alert cho rule quan trọng có thể khiến bạn MÙ trước threat thật. Nên tinh chỉnh (tune) rule cẩn thận thay vì tắt hẳn.

---

## 2. Falco Overview and Installation

### Cách Falco bắt kernel event — 2 phương pháp

| Capture Method | Mô tả | Ưu/Nhược |
|---|---|---|
| Kernel Module | Chèn module vào Linux kernel để intercept syscall | Hiệu năng cao NHƯNG intrusive, bị hạn chế trên managed cluster |
| eBPF | Dùng Extended Berkeley Packet Filter để gắn probe vào kernel function | An toàn hơn, không xâm lấn NHƯNG overhead cao hơn 1 chút |

Sau khi bắt event, chúng đi qua Sysdig libraries và Falco policy engine để đánh giá theo rule. Alert được forward tới syslog, stdout, Slack, email...

### 2 cách deploy Falco

| Method | Use Case | Ưu điểm |
|---|---|---|
| Native Linux Installation | Full root access vào Linux node | Tách biệt khỏi Kubernetes control plane (vẫn hoạt động dù control plane bị compromise) |
| Kubernetes DaemonSet qua Helm | Managed cluster hoặc môi trường hạn chế | Dễ upgrade, quản lý tập trung qua Helm |

**Cài trên Linux Node:**
```bash
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" \
  | tee /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y
apt-get install -y linux-headers-$(uname -r) falco
systemctl enable --now falco
```
> Cần đúng package `linux-headers-$(uname -r)` — headers không khớp có thể khiến Falco kernel module build lỗi.

**Deploy qua Helm (DaemonSet):**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco
```
Verify:
```bash
kubectl get pods -l app=falco
# falco-7grdt  1/1  Running  0  2m21s
# falco-tmq28  1/1  Running  0  2m21s
```

---

## 3. Using Falco to Detect Threats

### Verify Falco đang chạy
```bash
sudo systemctl status falco
```
Output mẫu: `Active: active (running)`, chạy binary `/usr/bin/falco -c /etc/falco/falco.yaml`.

Nếu deploy dạng DaemonSet: `kubectl get pods -n falco-driver-loader`.

### Test với nginx — Trigger alert thật
```bash
kubectl run nginx --image=nginx
kubectl get pods -o wide          # xem node nào chạy Pod

# SSH vào node đó, stream log Falco
ssh user@<node-ip>
sudo journalctl -fu falco

# Terminal khác: trigger alert
kubectl exec -ti nginx -- bash
cat /etc/shadow
```
Falco sẽ log alert NGAY LẬP TỨC cho cả sự kiện mở shell VÀ truy cập file nhạy cảm.

### Anatomy của 1 Falco Rule — 5 field bắt buộc
```yaml
- rule:      # Tên rule DUY NHẤT
  desc:      # Mô tả dễ hiểu
  condition: # Biểu thức boolean check field của event
  output:    # Template message của alert
  priority:  # Mức độ (DEBUG, INFO, WARNING, CRITICAL)
```

Ví dụ rule built-in phát hiện shell trong container:
```yaml
- rule: OpenShellInContainer
  desc: Alert when a shell (e.g., bash) is spawned inside a container
  condition: container.id != host and proc.name = bash
  output: Shell opened in container (user=%user.name container=%container.id)
  priority: WARNING
```

### Custom Rule tự viết
```yaml
- rule: DetectShellInsideContainer
  desc: Alert if a shell such as bash is opened inside any container
  condition: container.id != host and proc.name = bash
  output: Bash shell opened (user=%user.name container=%container.id)
  priority: WARNING
```

### Bảng Sysdig Filter Reference — CẦN THUỘC

| Filter | Mô tả |
|---|---|
| `container.id` | ID container duy nhất |
| `proc.name` | Tên process |
| `user.name` | Username khởi tạo event |
| `container.image.repository` | Tên image |
| `fd.name` | Đường dẫn file descriptor (VD: `/etc/shadow`) |
| `evt.type` | Tên system call (VD: `execve`, `open`) |

### Mở rộng bằng List — Theo dõi NHIỀU loại shell
```yaml
- list: linux_shells
  items: [bash, zsh, ksh, sh, csh]

- rule: DetectShellInsideContainer
  desc: Alert if any common shell is opened inside a container
  condition: container.id != host and proc.name in (linux_shells)
  output: Shell opened (user=%user.name container=%container.id proc=%proc.name)
  priority: WARNING
```

### Đơn giản hoá bằng Macro
`container` là macro built-in, viết tắt cho `container.id != host`:
```yaml
- rule: DetectShellInsideContainer
  desc: Alert if any common shell is opened inside a container
  condition: container and proc.name in (linux_shells)
  output: Shell opened (user=%user.name container=%container.id proc=%proc.name)
  priority: WARNING

- list: linux_shells
  items: [bash, zsh, ksh, sh, csh]
```

---

## PHẦN B: SERVICE MESH & ISTIO

## 4. Monolithics vs Microservices

### Bối cảnh lịch sử — Agile Manifesto (2001)
```
Individuals & Interactions  over  processes and tools
Working Software            over  comprehensive documentation
Customer Collaboration      over  contract negotiation
Responding to Change        over  following a plan
```
Agile thúc đẩy feedback loop nhanh hơn, gắn kết khách hàng, release lặp lại (iterative).

### Monolith — Vấn đề
Monolith gộp TOÀN BỘ tính năng (presentation, business logic, data access) vào 1 unit deployable duy nhất — chung 1 codebase, 1 process, thường 1 database. BẤT KỲ update nào, dù nhỏ, đều cần redeploy TOÀN BỘ hệ thống.

Ví dụ "Book Info Monolith" (Java): Details, Reviews, Ratings, Product Page — TẤT CẢ trong 1 jar, gọi nhau và share database.

Nhược điểm chính:
- Mọi thay đổi cần full redeploy
- Scale TẤT CẢ module cùng lúc, dù chỉ 1 module cần
- Thêm ngôn ngữ/module mới = phải viết lại toàn bộ
- 1 lỗi có thể làm SẬP CẢ hệ thống
- Dần trở thành "Big Ball of Mud"

### Chuyển sang Microservices
Book Info tách thành: Product Page (Python), Details (Ruby), Reviews (Java, có A/B version), Ratings (Node.js). User vẫn thấy 1 trang thống nhất, nhưng mỗi component scale/upgrade ĐỘC LẬP.

### Lợi ích Microservices

| Benefit | Mô tả |
|---|---|
| Scalability | Chỉ scale service đang chịu tải |
| Faster Releases | Deploy thay đổi nhỏ độc lập |
| Technology Agnosticism | Dùng ngôn ngữ/framework tốt nhất cho từng service |
| Resilience | Cô lập lỗi, giới hạn blast radius |
| Team Autonomy | Team sở hữu service từ đầu đến cuối |

### Thách thức MỚI phát sinh — Đây chính là lý do CẦN Service Mesh

| Challenge | Impact |
|---|---|
| Service Discovery | Service tìm và giao tiếp nhau NHƯ THẾ NÀO |
| Security | Mã hoá + xác thực inter-service VÀ client-to-service |
| Observability | Tương quan log/metric/trace XUYÊN SUỐT nhiều service phân tán |
| Operational Overhead | Quản lý nhiều framework, ngôn ngữ, deployment pattern |

> Không có 1 platform NHẤT QUÁN cho networking/security/telemetry, microservices có thể trở nên KHÓ QUẢN LÝ như monolith. DevOps giúp bắc cầu dev-ops, nhưng thường CẦN thêm 1 lớp riêng — Service Mesh — để xử lý những phức tạp này ở QUY MÔ LỚN.

---

## 5. Service Mesh

### Định nghĩa
Service mesh là 1 lớp hạ tầng CHUYÊN DỤNG xử lý giao tiếp service-to-service trong kiến trúc microservices. Bằng cách đẩy logic networking ra lớp NÀY, developer tập trung vào business logic mà KHÔNG cần sửa code ứng dụng để có resilience/security/observability.

### Kiến trúc — Data Plane + Control Plane
```
Thay vì nhúng networking logic vào TỪNG microservice
      ↓
Service mesh inject SIDECAR PROXY vào MỖI service instance
      ↓
Các proxy này TẠO THÀNH Data Plane (quản lý toàn bộ traffic east-west)
      ↓
Control Plane cấu hình + điều phối TẬP TRUNG cho các proxy
  (dynamic routing, security policy, telemetry collection)
```

Lợi ích chính:
- **Dynamic Traffic Routing**: canary release, blue/green, circuit breaking, retry
- **Mutual TLS (mTLS)**: tự động mã hoá + xác thực service call
- **Observability**: metric, log, distributed tracing end-to-end
- **Service Discovery**: tự động đăng ký + tra cứu service instance

> Service mesh là platform-agnostic — Istio, Linkerd, Consul Connect là các implementation phổ biến.

### Bảng Core Responsibilities

| Capability | Mô tả | Ví dụ Tool/Config |
|---|---|---|
| Service Discovery | Duy trì registry instance khoẻ mạnh để tra cứu động | Envoy, Consul Catalog |
| Health Checking | Loại bỏ instance không phản hồi | HTTP/gRPC probe |
| Load Balancing | Phân phối traffic (round-robin, least connections, locality) | Envoy LB algorithm |
| Security (mTLS) | Mã hoá + xác thực TOÀN BỘ inter-service traffic | Istio PeerAuthentication, Linkerd identity service |
| Traffic Management | Retry, timeout, fault injection, traffic splitting | Istio VirtualService, Linkerd ServiceProfile |
| Observability | Thu thập metric/log/trace end-to-end | Prometheus, Jaeger, Grafana |

---

## 6. Service Mesh Istio

### Istio là gì
Istio là service mesh mã nguồn mở HÀNG ĐẦU, miễn phí — bảo mật, kết nối, và quan sát microservices. Tích hợp liền mạch với Kubernetes VÀ workload chạy trên VM. Cung cấp:
- Fine-grained traffic control và routing
- Mutual TLS tự động cho service identity + encryption
- Thu thập telemetry và distributed tracing
- Policy enforcement và rate limiting

### Kiến trúc 2 mặt phẳng

| Plane | Mô tả |
|---|---|
| Control Plane | Quản lý config, policy, certificate qua 1 BINARY thống nhất — **Istiod** |
| Data Plane | Gồm các **Envoy** sidecar proxy — enforce policy, route traffic, thu thập telemetry |

### Istiod — Control Plane
Ban đầu được xây từ 3 component riêng biệt (**Pilot, Citadel, Galley**), giờ HỢP NHẤT thành 1 binary duy nhất: **Istiod**. Xử lý:
- Service discovery + traffic configuration
- Cấp phát + xoay vòng certificate (mTLS)
- Validate + phân phối configuration

> Istiod đơn giản hoá quản lý bằng cách gộp nhiều component thành 1. Upgrade/bảo mật Istiod ảnh hưởng TOÀN BỘ chức năng control-plane.

### Envoy — Data Plane
MỖI workload (VD: 1 Pod Kubernetes) chạy 1 **Envoy** sidecar proxy CẠNH container ứng dụng. Envoy xử lý:
- Traffic routing, retry, failover
- Giao tiếp an toàn với TLS tự động
- Metric và log cho telemetry/monitoring

```bash
# Inject Envoy sidecar vào 1 namespace
kubectl label namespace default istio-injection=enabled
```

### Istio Agent
Chạy như sidecar CẠNH Envoy. Bootstrap proxy, cung cấp config + certificate, đảm bảo Envoy luôn cập nhật:
- Lấy x.509 certificate cho mTLS
- Stream dynamic configuration tới Envoy qua SDS/CDS
- Giám sát health của proxy và tự restart nếu lỗi

> Đảm bảo Istio Agent có đúng ServiceAccount + RBAC permission — cấu hình sai có thể chặn certificate delivery và làm hỏng service-to-service TLS.

### Bảng tổng hợp 3 Component

| Component | Plane | Trách nhiệm |
|---|---|---|
| Istiod | Control Plane | Phân phối config, enforce policy, quản lý certificate |
| Envoy | Data Plane | Quản lý traffic, thu thập telemetry, enforce security |
| Istio Agent | Data Plane | Bootstrap proxy, phân phối config & certificate |

---

## 7. Service Mesh Security in Istio

### 3 yêu cầu cốt lõi để bảo mật microservices
1. **Encryption** service-to-service traffic để chống Man-in-the-Middle (MITM)
2. **Fine-grained access control** để giới hạn service nào được giao tiếp với nhau
3. **Audit logging** để ghi lại AI truy cập service NÀO, KHI NÀO

### 1. Mutual TLS (mTLS)
Istio mTLS đảm bảo CẢ client và server xác thực lẫn nhau + mã hoá TOÀN BỘ data in transit — ngăn eavesdropping và tampering MẶC ĐỊNH.

**Bật mTLS toàn namespace — PeerAuthentication:**
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: default
spec:
  mtls:
    mode: STRICT
```

**DestinationRule cho TLS setting:**
```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: default
  namespace: default
spec:
  host: "*.default.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
```
> STRICT mTLS mode yêu cầu MỌI workload đã inject Istio sidecar. Nếu thiếu sidecar, chạy `kubectl label namespace default istio-injection=enabled`.

### 2. Access Control Policies — AuthorizationPolicy
CRD `AuthorizationPolicy` định nghĩa service nào được nói chuyện với service nào — permit/deny dựa trên namespace, principal, port, request attribute.

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: reviews-access
  namespace: default
spec:
  selector:
    matchLabels:
      app: reviews
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/productpage"]
```
Policy này CHỈ cho phép ServiceAccount `productpage` gọi `reviews`, chặn TẤT CẢ caller khác.

**Common Policy Patterns:**

| Use Case | Resource | Key Field |
|---|---|---|
| Chỉ cho phép 1 service gọi vào | AuthorizationPolicy | `source.principals` |
| Chặn traffic từ nguồn KHÔNG XÁC ĐỊNH | AuthorizationPolicy | không có `from` entry |
| Access control theo port | AuthorizationPolicy | `to.ports` |

> Cấu hình sai policy có thể VÔ TÌNH chặn traffic hợp pháp — luôn test ở staging trước khi đưa vào production.

### 3. Audit Logging
Istio thu thập telemetry + access log chi tiết, export tới Prometheus, Elasticsearch, hoặc Stackdriver.

**Bật access logging qua MeshConfig:**
```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    accessLogFile: /dev/stdout
```

**Custom log format qua EnvoyFilter** (patch trực tiếp vào HTTP connection manager của Envoy) — cho phép định dạng log tuỳ chỉnh, log ra stdout.

---

## 8. Service Mesh Istio Security Architecture

### Istiod = Certificate Authority (CA) tích hợp sẵn
Istiod:
- Cấp phát, xoay vòng, thu hồi certificate + private key của workload
- Quản lý **SPIFFE-based identity** cho workload
- Cung cấp configuration API server để phân phối security policy

### Flow cấp Certificate — 4 bước
```
1. Workload MỚI khởi động -> Envoy sidecar liên hệ Istio agent LOCAL
2. Agent request certificate + private key ĐÃ KÝ từ istiod
3. Istiod ký CSR (Certificate Signing Request), trả về credential
4. Proxy thiết lập kết nối mTLS với service khác bằng certificate này
```

### 3 loại Policy do Configuration API Server (trong istiod) phân phối tới TỪNG Envoy proxy

| Loại Policy | Mô tả |
|---|---|
| Authentication Policies | Định nghĩa workload nào CẦN mTLS hoặc JWT verification |
| Authorization Policies | Kiểm soát access dựa trên attribute như `source.principal` hoặc `request.headers` |
| Secure Naming | Đảm bảo CHỈ service có SPIFFE identity HỢP LỆ mới giao tiếp được |

> Bằng cách enforce policy Ở TỪNG HOP, Istio xây dựng mô hình **Defense-in-Depth** — không chỉ dựa vào perimeter security.

### Data Plane Proxy — 3 loại

| Component | Vai trò |
|---|---|
| Sidecar Proxy | Intercept + bảo vệ traffic pod-to-pod |
| Ingress Gateway | Terminate traffic từ BÊN NGOÀI, áp policy ở "edge" |
| Egress Gateway | Kiểm soát + giám sát traffic đi RA ngoài, policy check |

**Traffic Flow:**
```
Internal: Service A -> Envoy sidecar A (mTLS) -> Envoy sidecar B -> Service B
Ingress:  External client -> Ingress Gateway -> Destination sidecar
Egress:   Service sidecar -> Egress Gateway -> External service
```

### Mutual TLS Handshake — 4 bước
```
1. Sidecar A trình certificate của mình cho Sidecar B
2. Sidecar B VERIFY certificate đó với Istio root CA
3. Cả 2 proxy THOẢ THUẬN encryption key
4. Kênh an toàn được thiết lập — data được mã hoá, xác thực, authorized
```

Ví dụ enforce STRICT mTLS toàn namespace:
```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: your-namespace
spec:
  mtls:
    mode: STRICT
EOF
```

---

## Tổng kết nhanh (Cheat Sheet)

### Falco

| Keyword | Đáp án |
|---|---|
| Tool runtime security của Sysdig | Falco |
| 2 cách bắt kernel event | Kernel Module (intrusive, nhanh) / eBPF (an toàn hơn, overhead cao hơn) |
| 2 cách deploy | Native Linux Install / Kubernetes DaemonSet qua Helm |
| 5 field bắt buộc của 1 rule | rule, desc, condition, output, priority |
| Filter check tên process | `proc.name` |
| Filter check đường dẫn file | `fd.name` |
| Filter check loại syscall | `evt.type` |
| Macro built-in = `container.id != host` | `container` |

### Service Mesh & Istio

| Keyword | Đáp án |
|---|---|
| Lớp hạ tầng quản lý service-to-service communication | Service Mesh |
| Proxy chạy CẠNH mỗi service, tạo Data Plane | Sidecar (Envoy) |
| Binary duy nhất của Istio Control Plane | Istiod (hợp nhất từ Pilot + Citadel + Galley) |
| Component bootstrap Envoy + lấy certificate | Istio Agent |
| Bật mTLS toàn namespace | PeerAuthentication (mode: STRICT) |
| CRD kiểm soát AI được gọi service nào | AuthorizationPolicy |
| Field giới hạn CHỈ 1 caller cụ thể | `source.principals` |
| Istiod đóng vai trò gì về bảo mật | Certificate Authority (CA) tích hợp sẵn |
| Identity chuẩn Istio dùng cho workload | SPIFFE |
| 3 loại Proxy trong Data Plane | Sidecar / Ingress Gateway / Egress Gateway |
| Nguyên tắc bảo mật Istio theo TỪNG hop | Defense-in-Depth |

### Nguyên tắc chung
```
- Microservices giải quyết vấn đề của Monolith NHƯNG sinh ra vấn đề MỚI:
  Service Discovery, Security, Observability, Operational Overhead
  -> Service Mesh ra đời để xử lý các vấn đề NÀY ở tầng hạ tầng, KHÔNG sửa code app
- Falco là runtime security bổ sung cho các lớp phòng thủ TĨNH (RBAC, NetworkPolicy, PSA)
  đã học trước đó — phát hiện hành vi THỜI GIAN THỰC (VD: shell trong container,
  đọc /etc/shadow) mà các control tĩnh không tự phát hiện được
- Istio mTLS + AuthorizationPolicy + Audit Logging = 3 trụ cột bảo mật
  tương ứng ĐÚNG 3 yêu cầu: Encryption, Access Control, Audit
```
