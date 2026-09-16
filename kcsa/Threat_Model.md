# KCSA Study Notes — Kubernetes Threat Model (Domain 3, 16%)

Tổng hợp đầy đủ 8 bài trong section Kubernetes Threat Model: Trust Boundaries & Data Flow, Persistence, Denial of Service, Malicious Code Execution, Compromised Applications in Containers, Attacker on the Network, Access to Sensitive Data, Privilege Escalation.

---

## 1. Kubernetes Trust Boundaries and Data Flow

### Bài này là NỀN TẢNG cho cả domain
Không nói về "kẻ tấn công làm gì" mà nói về cách chia hệ thống thành các vùng (zones) để 1 vùng bị vỡ không kéo theo toàn bộ hệ thống sập.

### 3 Bước của Threat Modeling Process
```
1. Identify potential threats  -> Liệt kê kịch bản tấn công có thể xảy ra
2. Assess impact                -> Đánh giá mức độ nghiêm trọng + khả năng xảy ra
3. Implement countermeasures     -> Thiết kế biện pháp giảm rủi ro
```
Đây là quy trình tổng quát mà STRIDE/DREAD/PASTA (Domain 6) đều tuân theo.

### 5 Trust Boundary — Từ LỚN đến NHỎ (dạng búp bê Nga lồng nhau)

| Trust Boundary | Phạm vi | Ví dụ Control |
|---|---|---|
| 1. Cluster | Toàn bộ cluster | VPC segregation, cluster riêng cho dev/staging/prod |
| 2. Node | 1 máy chủ vật lý/ảo | Node hardening, kubelet auth, patch OS |
| 3. Namespace | Phân vùng logic | RBAC roles, NetworkPolicies |
| 4. Pod | 1 instance ứng dụng | Pod Security Standards, egress/ingress policy |
| 5. Container | 1 process trong Pod | AppArmor, seccomp, minimal base image (Distroless) |

```
CLUSTER > NODE > NAMESPACE > POD > CONTAINER
(lớp ngoài chứa lớp trong, mỗi lớp cần kiểm soát riêng)
```

**Cảnh báo quan trọng nhất bài:** Mặc định, Kubernetes cho phép TOÀN BỘ Pod-to-Pod communication. Không có NetworkPolicy, kẻ tấn công có thể di chuyển ngang (lateral movement) qua các Pod tự do. Pod Boundary là lớp YẾU NHẤT theo mặc định — cần chủ động dùng NetworkPolicy.

### Data Flow qua các Trust Boundary
```
User -> Frontend (Nginx):     HTTPS termination, certificate validation, authentication
Frontend -> Backend API:       mTLS hoặc HTTPS + API token/OAuth
Backend API -> Database:       Encrypted connection, least-privilege SQL account
Pod-to-Pod nội bộ:              NetworkPolicy giới hạn chỉ đường đi cần thiết
```

### 3 Loại Threat Actor
```
1. External Attackers      -> Scan tìm endpoint bị lộ (từ bên ngoài cluster)
2. Compromised Containers   -> Bị khai thác qua lỗ hổng/misconfig (đã ở trong rồi)
3. Malicious Users          -> Insider lạm dụng quyền hạn hợp pháp
```

---

## 2. Persistence

### Định nghĩa
Kẻ tấn công duy trì quyền truy cập vào hệ thống đã chiếm được, NGAY CẢ SAU KHI: Pod/Container bị restart, lỗ hổng ban đầu đã được vá, admin cố dọn dẹp.

```
Persistence KHÁC "chiếm được quyền" (đó là bước Initial Access/Privilege Escalation)
Persistence = "ĐÃ chiếm được quyền RỒI, giờ tìm cách GIỮ QUYỀN ĐÓ LÂU DÀI"
```

### 5 Attack Vector chính thức (CNCF) — sắp xếp theo ĐỘ BỀN tăng dần

| ID | Vector | Mô tả |
|---|---|---|
| 1 | Foothold with No Resilience | Chỗ đứng tạm thời — mất ngay khi Pod restart/xoá |
| 2 | Resilience to Container Restart | Thay đổi trên volume/config sống sót qua container restart |
| 3 | Resilience to Node Restart | Script/container ở tầng HOST sống sót qua Node reboot |
| 4 | Via Kubernetes API & PKI | Chiếm SA token/certificate để điều khiển API |
| 5 | Leveraging Privileged Workloads | Lợi dụng privileged Pod/hostPath để với tới Node |

**Vector 1 — Foothold with No Resilience:**
- Running a Malicious Process: chạy 1 backdoor binary ngay trong Pod
- Using Native Tools: dùng apt/yum/pip/curl/wget có sẵn để tải + chạy code
- Container Hopping: tìm Pod khác có cùng runtime để nhảy sang

**Vector 2 — Resilience to Container Restart:**
- Volume-Backed Config Tweaks: sửa file config (VD: Nginx settings) lưu trên PersistentVolumeClaim
- Forcing a Restart: tự kích hoạt restart để áp dụng thay đổi độc hại

**Vector 3 — Resilience to Node Restart (bypass Kubernetes controls hoàn toàn):**
- Always-Restart Containers: chạy Docker container trên Host với `--restart=always` (qua Docker daemon, không qua kubectl)
- Init Scripts & Cron Jobs: thêm lệnh độc hại vào `/etc/rc.local` hoặc `/etc/cron.d/`
- Host File System Implants: đặt binary/script thẳng lên filesystem của Host

**Vector 4 — Via Kubernetes API & PKI:**
- Service Account Token Theft: đánh cắp token từ `/var/run/secrets/kubernetes.io/serviceaccount`
- Certificate Forgery: trích xuất/giả mạo client certificate để mạo danh admin

**Vector 5 — Leveraging Privileged Workloads:**
- Privileged Mode: `securityContext.privileged: true` cho phép thao túng Host
- HostPath Mounts: truy cập/sửa thư mục Host như `/etc` hoặc `/var/lib/kubelet`

### 5 Mitigation
```
RBAC (least privilege, audit Role/ClusterRole)     -> chặn Vector 4
Secrets Management (giới hạn Pod đọc Secret)       -> chặn Vector 4
Pod Security Standards (chặn privileged, hostPath)  -> chặn Vector 5
Regular Updates & Patching                          -> giảm lỗ hổng ban đầu (Vector 1)
Monitoring & Auditing                               -> phát hiện TẤT CẢ vector
```

### Attack Tree — Cách đọc
Sơ đồ hình cây biểu diễn NHIỀU con đường (nhánh) khác nhau để đạt CÙNG 1 mục tiêu.
```
Quan hệ OR (mặc định): chỉ cần 1 nhánh thành công là đạt mục tiêu
Quan hệ AND (đôi khi):  cần đủ TẤT CẢ bước trong 1 nhánh mới thành công
```
Ý nghĩa: chặn 1 điểm là KHÔNG ĐỦ — cần phòng thủ NHIỀU LỚP vì kẻ tấn công có nhiều nhánh để chọn.

---

## 3. Denial of Service

### DoS khác DDoS
```
DoS  = MỤC TIÊU: làm dịch vụ không dùng được (có thể từ 1 NGUỒN DUY NHẤT)
DDoS = 1 CÁCH THỰC HIỆN DoS, dùng NHIỀU nguồn phân tán (botnet)
```
Trong K8s, DoS phổ biến nhất là Resource Exhaustion nội bộ (1 Pod độc hại "ăn hết" tài nguyên), không nhất thiết phải là DDoS traffic-based.

### 4 Attack Vector chính thức (CNCF)

| Vector | Mô tả |
|---|---|
| Adding processes to a running pod | Sinh thêm process trong container đã bị chiếm để ăn CPU/Memory |
| Privileged container modifications | Dùng `--privileged` để sửa process Host, mount filesystem, lợi dụng Docker socket, join host PID namespace |
| Direct etcd writes | Ghi thẳng vào etcd bằng certificate/token đánh cắp — bypass API server RBAC/admission control |
| API-server scaling abuse | Tạo/scale Deployment qua API server để ép tạo quá nhiều Pod |

**Ví dụ Vector 1:**
```bash
kubectl exec -it compromised-pod -- sh -c "yes > /dev/null &"
```
Chạy process vô hạn ngốn CPU 100%.

**Ví dụ Vector 4 — Mass-create Pod bằng Stolen Token:**
```bash
for i in {1..1000}; do
  kubectl --token=$STOLEN_TOKEN run attack-pod-$i --image=busybox --restart=Never
done
```
Không có ResourceQuota → exhaust CPU/memory toàn cluster.

**API Server Flooding:**
```bash
while true; do curl -k https://api.k8s.example.com:6443/version & done
```

### 3 Tactic Network-Based DoS
```
Resource Exhaustion    -> Flood kubelet/kube-proxy -> lỗi ở tầng Node
Scheduling Disruption   -> Ngập API server/scheduler bằng request giả
Network Disruption      -> Đầu độc DNS, can thiệp CNI plugin -> đứt Pod-to-Pod
```

### Mitigation — ResourceQuota + NetworkPolicy

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
spec:
  hard:
    pods: "10"
    requests.cpu: "2"
    requests.memory: "4Gi"
    limits.cpu: "4"
    limits.memory: "8Gi"
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-api-access
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      component: kube-apiserver
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          trusted: "true"
    - podSelector:
        matchLabels:
          access: api-server
    ports:
    - protocol: TCP
      port: 6443
```

---

## 4. Malicious Code Execution

### Định nghĩa
Kẻ tấn công lợi dụng lỗ hổng trong ứng dụng/cấu hình cluster để chạy lệnh/binary trái phép bên trong container hoặc trên host. Hậu quả: Privilege Escalation, Data Exfiltration, Full Cluster Compromise.

**LƯU Ý QUAN TRỌNG:** 3 vector dưới đây xảy ra SAU KHI kẻ tấn công đã có được lệnh thực thi đầu tiên (thường qua RCE/injection ở ứng dụng — giống Stage 2-3 kịch bản "Cats and Dogs"). Đây KHÔNG PHẢI cách "đột nhập từ bên ngoài" mà là cách LEO THANG/MỞ RỘNG sau khi đã đột nhập.

### 3 Attack Vector chính thức

| Attack Vector | Mô tả | Hậu quả |
|---|---|---|
| Import Tools or Scripts | Container có sẵn curl/wget/package manager tải thêm payload | Arbitrary code execution trong Pod |
| Modify Host Files | hostPath mount cho phép sửa config/startup script của Host | Persistence + backdoor âm thầm |
| Host-Level Process Injection | Lợi dụng host PID namespace hoặc SYS_PTRACE để trace/inject vào process Host | Host compromise + lateral movement |

**Vector 1 liên hệ Distroless:** Image không có shell/curl/wget/package manager (Distroless — do Google phát triển) chặn đứng vector này vì kẻ tấn công không có công cụ để tải thêm payload.

**Vector 2 liên hệ PSS Baseline:** `hostPath` là 1 trong 6 thứ mà PSS mức Baseline chặn (cùng hostNetwork, hostPID, hostIPC, hostPort, extra capabilities).

**Vector 3 — SYS_PTRACE + hostPID:** Container "nhìn thấy" và can thiệp được vào process của chính Node → lateral movement từ 1 container lên toàn bộ Node.

### Post-Compromise via Kubernetes API
Sau khi ở trong container, kẻ tấn công gọi K8s API (dùng SA token nếu chưa tắt automount) để:
```
1. Spawn new pods       -> Tạo thêm Pod độc hại khác
2. Trigger DoS          -> Làm sập dịch vụ
3. Harvest credentials  -> Thu thập Secret/token của Pod/namespace khác
```

### Poisoning the Image Repository
Nếu kẻ tấn công lấy được image pull secret (thường từ bước "harvest credentials" ở trên), họ push image có backdoor lên registry chính thức. Các lần deploy sau (kể cả của team khác không biết gì) sẽ tự động pull đúng image nhiễm độc.

```
Chuỗi liên hoàn: Attack Vector (chiếm container) 
              -> Post-Compromise API (harvest credentials, bao gồm pull secret)
              -> Poisoning Registry (dùng chính secret vừa lấy để đầu độc)
```

### 5 Mitigation

| Mitigation | Chi tiết |
|---|---|
| Scan and Patch Vulnerabilities | Tự động hoá image scanning MỖI build, block deploy nếu có CVE nghiêm trọng |
| Restrict API Server Access | Authentication mạnh + RBAC chi tiết, chỉ identity tin cậy gọi được endpoint nhạy cảm |
| Secure Image Repositories and Pull Secrets | Lưu pull secret trong Vault mã hoá, giới hạn SA nào được tham chiếu, enforce image signing (Cosign) |
| Monitor and Alert | Audit log + Prometheus, phát hiện exec call bất thường, thay đổi Secret, API usage lạ |
| Audit and Review | Định kỳ review RBAC roles, SA permissions, image registry policies + penetration test |

### Ví dụ Image Pull Secret đúng cách
```bash
kubectl create secret docker-registry my-image-pull-secret \
  --docker-username=<username> --docker-password=<password> \
  --docker-server=<registry-url> --namespace=default
```
```yaml
spec:
  serviceAccountName: specific-service-account
  imagePullSecrets:
  - name: my-image-pull-secret
```

### Ví dụ PrometheusRule phát hiện exec bất thường
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-monitoring-rules
spec:
  groups:
  - name: security-alerts
    rules:
    - alert: SecretChangeDetected
      expr: kube_secret_info
    - alert: CommandExecutionInContainer
      expr: increase(kube_audit_event_total{verb="exec"}[5m]) > 0
```

---

## 5. Compromised Applications in Containers

### Vị trí bài — Trả lời câu hỏi "làm sao có được chỗ đứng ban đầu?"
```
Bài trước (Malicious Code Execution): giả định đã có chỗ đứng, hỏi "làm gì tiếp?"
Bài này: xác nhận điểm khởi đầu LUÔN LÀ khai thác lỗ hổng ứng dụng/backend service
         để có được SHELL ACCESS bên trong container
```

### Compromised-Container Attack Tree — 4 nhánh

| Attack Vector | Mô tả |
|---|---|
| Poisoned Images | Chèn mã độc vào image, đẩy image nhiễm độc lên registry |
| Repository Breach | Truy cập trái phép vào image repository, tải image về, thu thập secret/lỗ hổng |
| Data Exfiltration | Trích xuất API token, DB credential, env variable — hoặc triển khai RANSOMWARE vào data store |
| Privilege Escalation | Lợi dụng ServiceAccount token để tương tác K8s API: liệt kê Secret, sửa ConfigMap, tạo resource mới |

**Data Exfiltration + Ransomware (khái niệm mới):** Kẻ tấn công có thể dùng Kubernetes làm bàn đạp để với tới database/data store phía sau, mã hoá toàn bộ database và đòi tiền chuộc — không nhất thiết tấn công trực tiếp vào K8s.

### 3 cách LẤY được Secret

**Case 1 — Pull-only secret bị cấu hình nhầm thành có quyền push:**
Image pull secret vốn chỉ nên có quyền PULL, nếu cấu hình nhầm cấp luôn quyền PUSH, kẻ tấn công dùng nó để đẩy image độc hại lên chính registry của bạn.

**Case 2 — Deploy Pod mới mount vào Secret có sẵn:**
Kẻ tấn công (đã có quyền tạo Pod qua RBAC lỏng lẻo) tự tạo 1 Pod mới, mount vào Secret đã tồn tại sẵn, đọc được nội dung MÀ KHÔNG CẦN xâm nhập vào Pod gốc đang dùng Secret đó.

**Case 3 — kubectl exec vào Pod đang chạy:**
```bash
kubectl exec -it <pod-name> -- /bin/sh
```
Nếu RBAC cho phép, attacker exec thẳng vào Pod sống, xem env variables + file Secret đã mount.

### Escalation via Kubernetes API
```bash
kubectl get secrets --all-namespaces
```
Chuỗi hành động: List/Read Secrets → Inspect/Modify ConfigMaps/Pods/Deployments/Services → Create/Delete resource để duy trì Persistence → có thể leo thang lên cluster-admin nếu RBAC quá rộng.

### Câu tóm tắt quan trọng nhất bài
```
Container compromise + Secret extraction + API abuse
= LATERAL MOVEMENT xuyên suốt cluster
```
(Đây chính là khái niệm "Lateral Movement" trong MITRE ATT&CK.)

### 5 Best Practices

| Practice | Mô tả |
|---|---|
| Minimal Base Images | Dùng image nhẹ, ít lỗ hổng OS (Distroless) |
| Enforce Image Signing | Scan + ký image bằng Notary hoặc Cosign trước khi deploy |
| Rotate Secrets Regularly | Tự động xoay vòng secret, tránh credential sống lâu dài (giống nguyên tắc SA token có expiry từ v1.22) |
| Least-Privilege RBAC | Mỗi ServiceAccount chỉ có đúng quyền cần |
| Network Policies | Phân đoạn giao tiếp Pod, giới hạn egress tới API server |

**Notary** (mới): công cụ ký image thứ 2 ngoài Cosign, thuộc Docker Content Trust, dùng chuẩn TUF (The Update Framework) — cũ hơn Cosign nhưng cùng mục đích.

---

## 6. Attacker on the Network

### Vị trí bài — Góc nhìn HOÀN TOÀN KHÁC 2 bài trước
```
Bài 4-5: Kẻ tấn công ĐÃ Ở BÊN TRONG (có shell trong container)
Bài này: Kẻ tấn công Ở BÊN NGOÀI, tấn công qua NETWORK, không cần vào được container
```

### 3 Nhóm mục tiêu tấn công

**1. Exhausting Compute Resources:**
- Flood kubelet endpoints (`/healthz`, `/metrics`) → Node báo "NotReady"
- Chặn kubelet health check → Scheduler đánh dấu Node "unschedulable"
- Kích hoạt CPU/Memory tiêu thụ mất kiểm soát qua Pod độc hại
- Lưu ý: Resource exhaustion có thể trigger AUTOMATIC NODE REPLACEMENT nếu bật Cluster Autoscaler → tốn chi phí cloud

**2. Disrupting the Control Plane** — Bảng Port CẦN THUỘC LÒNG:

| Component | Port | Hậu quả nếu bị tấn công |
|---|---|---|
| etcd | 2379 (client), 2380 (peer) | Vỡ quorum, hỏng cluster state, chặn đồng bộ peer |
| API Server | 6443 (TLS), 8080 (HTTP, legacy) | Từ chối API call từ kubectl và internal controller |
| Scheduler | 10251 (cũ), 10259 (mới, HTTPS) | Ngăn Pod mới được gán vào Node |
| Controller Manager | 10252 (cũ), 10257 (mới, HTTPS) | Dừng replica loop, scaling, control task |

Cảnh báo: Disrupting API server hoặc etcd có thể gây FULL OUTAGE — đây là single point of failure nếu không có HA setup.

**3. Disrupting Networking:**

| Component | Port | Hậu quả |
|---|---|---|
| kube-proxy | 10256, 10249 | Đóng băng traffic Service-to-Pod |
| DNS | 53 | Chặn DNS resolution, gây lỗi service |
| CNI Overlay Network | (tuỳ CNI) | Ngập overlay network, chậm/đứt Pod-to-Pod |
| PXE/Network Boot | (tuỳ) | Ngăn Node mới join cluster |

### 5 Mitigation

**1. Firewall Configuration:**
- Giới hạn port API server (6443, 8080) chỉ cho bastion host tin cậy
- Chặn mọi port K8s không dùng ở network perimeter
- Dùng cloud-native firewall (Security Groups, Firewall Rules) quản lý động

**2. Securing Nodes:**
- Giữ Host OS + K8s component luôn cập nhật patch
- Áp dụng CIS Benchmark hoặc Node Hardening Guide
- Giám sát runtime bằng Falco hoặc Sysdig Secure

**3. Network Policies** (dùng namespaceSelector):
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: frontend
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: backend
      podSelector: {}
```
Lưu ý: định nghĩa CẢ Ingress và Egress để đảm bảo phân đoạn traffic hoàn chỉnh.

**4. Strong Authentication and Authorization:**
- Bắt buộc MFA cho mọi quyền truy cập control-plane (API server, etcd, SSH)
- RBAC theo Least Privilege
- Xoay vòng SA token + certificate định kỳ

**5. Monitoring and Logging:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: network-alert-rules
spec:
  groups:
  - name: network-alerts
    rules:
    - alert: HighAPIRequests
      expr: sum(rate(apiserver_request_total[5m])) by (client) > 100
    - alert: HighNetworkTraffic
      expr: |
        sum(rate(container_network_receive_bytes_total[5m]) +
            rate(container_network_transmit_bytes_total[5m])) by (pod) > 10000000
```
Rule "HighNetworkTraffic" phát hiện CẢ DoS lẫn Data Exfiltration cùng lúc — vì cả 2 đều có dấu hiệu network traffic tăng đột biến.

---

## 7. Access to Sensitive Data

### Vị trí bài — Mục tiêu CUỐI CÙNG của hầu hết kịch bản tấn công
Đây chính là STRIDE - Information Disclosure, đi sâu vào CỤ THỂ những đâu trong K8s chứa data nhạy cảm.

### 6 Attack Vector chính

| Attack Vector | Mô tả | Mitigation |
|---|---|---|
| etcd Access | Đọc/ghi trực tiếp vào etcd, lộ Secret/ConfigMap/cluster state | TLS cho etcd + RBAC cho etcd API + rotate encryption key |
| Kubelet API | Endpoint kubelet bị lộ: xem log, exec shell, chi tiết Pod | TLS client cert + NetworkPolicy hạn chế kubelet API |
| Application Logs | Log chứa password/token/PII trở thành mục tiêu giá trị cao | Redact field nhạy cảm + tập trung log có access control |
| Persistent Volumes | Mount volume vào Pod khác, hoặc volume lộ qua network | accessModes phù hợp + encryption at rest + Pod Security Standards |
| Network Shares (NFS) | NFS/SMB share không bảo vệ bị client trái phép đọc | Giới hạn mount + network segmentation + authentication |
| Cluster Encryption Keys | Master key bị lộ → toàn bộ data encrypted-at-rest lộ theo | Rotate key định kỳ + lưu trong HSM (Hardware Security Module) |

**Kubelet API — điểm cực kỳ nguy hiểm:** Kubelet có API riêng (port 10250), chạy trên MỖI Node, khác API Server. Nếu expose không bảo vệ, kẻ tấn công gọi TRỰC TIẾP vào kubelet, BỎ QUA HOÀN TOÀN RBAC của API Server (vì không đi qua "cửa chính").

**Cluster Encryption Keys và HSM:** K8s mã hoá Secret trong etcd bằng 1 "master encryption key". Nếu key này lộ, toàn bộ Secret đã mã hoá trở nên vô nghĩa (đọc được ngay). Giải pháp: lưu Master Key trong HSM — phần cứng chuyên dụng, cực khó trích xuất key ra ngoài.

### Ví dụ RBAC Over-Permissive

RBAC SAI (misconfigured):
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: backend-read-only
  namespace: backend
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]    # Gộp chung, quá rộng
  verbs: ["get", "list"]
```

RBAC ĐÚNG (hardened):
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: backend-limited
  namespace: backend
rules:
- apiGroups: [""]
  resources: ["configmaps"]    # Chỉ configmaps, bỏ "secrets"
  verbs: ["get", "list"]
```

### Securing Application Logs

Risky logging (NGUY HIỂM):
```
[DEBUG] Payload: {"creditCardNumber":"4111111111111111","expiration":"12/25","cvv":"123"}
```

Redacted logging (AN TOÀN):
```
[DEBUG] Payload: {"creditCardNumber":"************","expiration":"**/**","cvv":"***"}
```

Nguyên tắc: REDACT field nhạy cảm TRƯỚC KHI ghi log — không phải log hết rồi lọc sau.

Liên hệ Audit Policy Level: nếu app gửi request chứa password plaintext VÀ Audit Policy đang ở level Request/RequestResponse, audit log CŨNG SẼ chứa password đó — lộ thêm 1 lớp. Đây là lý do Secret chỉ nên log ở mức Metadata.

### Encrypting Network Traffic (TLS/mTLS)
HTTP không mã hoá: password truyền dạng plaintext, ai "sniff" packet cũng đọc được.
HTTPS có mã hoá: dữ liệu vẫn có password nhưng được mã hoá trên đường truyền, kẻ nghe lén chỉ thấy dữ liệu đã mã hoá.

### 4 Best Practices chốt
```
1. Apply Least-Privilege RBAC
2. NEVER log sensitive information — mask/omit secret trong log
3. Enforce TLS/mTLS cho mọi giao tiếp inter-service và external
4. Rotate encryption keys và Secrets định kỳ
```

---

## 8. Privilege Escalation

### Điểm đặc biệt — Bài này về LINUX/HOST, không phải Kubernetes-specific
4 bài trước đều mô tả góc nhìn kẻ tấn công trong K8s. Bài này nói về `sudo` trên Linux thông thường — nền tảng để hiểu privilege escalation TRÁI PHÉP (kẻ tấn công lợi dụng sudo cấu hình sai) SAU KHI đã thoát ra khỏi container (qua Host-Level Process Injection ở bài Malicious Code Execution) và đứng trên Node thật.

### sudo là gì và lợi ích
```
KHÔNG cho login trực tiếp bằng root (rủi ro cao)
User thường dùng sudo để chạy TỪNG LỆNH CỤ THỂ với quyền cao hơn

3 lợi ích:
1. Cấp quyền tạm thời, không cần chia sẻ password root
2. Tạo audit trail — ghi lại chính xác lệnh nào, do ai
3. Giới hạn user chỉ dùng đúng lệnh cần thiết (Least Privilege)
```

### /etc/sudoers — Cấu trúc

```
<User/Group>  <Host(s)>=(<Run-As Specification>)  <Commands>

mark    ALL=(ALL:ALL) ALL
 ↑        ↑      ↑        ↑
User    Host  Run-As   Command
```

| Field | Mô tả | Ví dụ |
|---|---|---|
| User or Group | Username hoặc `%group` | `%admin` |
| Host(s) | Host áp dụng rule | `localhost`, `ALL` |
| Run-As Specification | User/group chạy lệnh DƯỚI DANH NGHĨA | `(ALL:ALL)` |
| Commands | Lệnh được phép, hoặc `ALL` | `/usr/bin/shutdown -r now` |
| Comments | Dòng bắt đầu bằng `#` | bị bỏ qua |

Ví dụ least privilege: `sarah localhost=/usr/bin/shutdown -r now` — chỉ được chạy đúng 1 lệnh, trên đúng 1 host, không có Run-As field (dùng mặc định).

### QUY TẮC BẮT BUỘC — Luôn dùng visudo

```bash
sudo visudo
```
KHÔNG BAO GIỜ sửa `/etc/sudoers` bằng editor thường (vim/nano) — lỗi cú pháp có thể KHOÁ TOÀN BỘ quyền sudo, kể cả admin cũng không sửa được (vì cần sudo để sửa) — vòng lặp chết. `visudo` tự động kiểm tra cú pháp trước khi lưu.

### NOPASSWD — Rủi ro cần biết
```
bob    ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
```
Cho phép chạy sudo MÀ KHÔNG CẦN password. Rủi ro: nếu tài khoản bob bị chiếm, kẻ tấn công chạy ngay lệnh đó với quyền root mà không cần biết password — mất 1 lớp xác thực. Chỉ nên dùng khi bắt buộc cho automation.

### /etc/sudoers.d/ — Best practice tổ chức
Thay vì sửa trực tiếp file gốc, tạo file riêng trong `/etc/sudoers.d/` — file gốc có sẵn dòng `#includedir /etc/sudoers.d` tự động nạp mọi file trong thư mục đó. Lợi ích: mỗi team/rule có 1 file riêng, dễ audit, giảm rủi ro làm hỏng cả hệ thống.

### 4 Best Practices
```
1. Chỉ cấp đúng lệnh cần thiết (Least Privilege)
2. Dùng group-based rule thay vì set từng user riêng lẻ
3. Tránh NOPASSWD trừ khi thực sự cần automation
4. Giữ custom rule trong /etc/sudoers.d/ để modular
```

### Liên hệ Threat Model tổng thể
```
Malicious Code Execution: SYS_PTRACE/hostPID -> thoát ra khỏi container, đứng trên Node
      ↓
Privilege Escalation (bài này): kẻ tấn công ở trên Node (user thường)
      ↓ lợi dụng sudo cấu hình sai (NOPASSWD quá rộng, ALL=(ALL:ALL) ALL cho user không nên có)
      ↓
Leo thang lên ROOT trên Node = Host Compromise hoàn toàn
-> Ảnh hưởng MỌI Pod/container khác chạy trên Node đó
```

### So sánh 2 tầng Privilege Escalation

| | Tầng Kubernetes (RBAC) | Tầng Linux/Host (sudo) |
|---|---|---|
| Kiểm soát AI làm gì | Role/ClusterRole + RoleBinding | /etc/sudoers |
| Rủi ro cấu hình sai | RoleBinding quá rộng (cluster-admin cho SA thường) | ALL=(ALL:ALL) ALL cấp quá rộng, NOPASSWD tràn lan |
| Công cụ sửa an toàn | kubectl edit + --dry-run | visudo |

---

## Tổng kết nhanh (Cheat Sheet) — Toàn bộ Domain Threat Model

### Framework nền tảng
```
STRIDE (6 loại): Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
5 Trust Boundary: Cluster > Node > Namespace > Pod > Container
3 bước Threat Modeling: Identify -> Assess -> Implement countermeasures
```

### Bảng Port phải thuộc lòng
```
etcd:                2379 (client), 2380 (peer)
API Server:          6443 (TLS), 8080 (HTTP - legacy, nguy hiểm)
Scheduler:           10251 (cũ), 10259 (mới)
Controller Manager:  10252 (cũ), 10257 (mới)
kube-proxy:          10256, 10249
DNS:                 53
Kubelet API:         10250
```

### Chuỗi tấn công liên hoàn (câu chuyện xuyên suốt domain)
```
[Lỗ hổng ứng dụng - RCE/Injection]
      ↓
[Malicious Code Execution] - Import tools / Modify host files / Process injection
      ↓
[Compromised Applications] - Poisoned images / Repository breach / Data exfiltration / Privilege escalation qua API
      ↓
[Persistence] - Backdoor SA / Rogue controller / Cron job độc hại (giữ chỗ đứng lâu dài)
      ↓
[Access to Sensitive Data] - etcd / Kubelet API / Logs / PV / Encryption keys
      ↓
[Privilege Escalation - Linux] - Lợi dụng sudo misconfiguration -> Root trên Node
      ↓
[Denial of Service / Attacker on the Network] - Phá hoại (nếu là mục tiêu cuối, thay vì âm thầm duy trì)
```

### Công cụ/khái niệm mới đáng nhớ trong domain này
```
HSM (Hardware Security Module) - lưu master encryption key an toàn
Notary - tool ký image (cùng nhóm Cosign), dùng chuẩn TUF
NOPASSWD - rủi ro sudo không cần password
visudo - công cụ BẮT BUỘC khi sửa /etc/sudoers
namespaceSelector - NetworkPolicy chọn theo namespace thay vì chỉ Pod
Lateral Movement - khái niệm MITRE ATT&CK, xuất hiện xuyên suốt domain
```

### Nguyên tắc chung xuyên suốt
```
- Kubernetes mặc định KHÔNG cô lập Pod-to-Pod -> cần NetworkPolicy chủ động
- Mọi lỗ hổng đều CÓ THỂ dẫn tới NHIỀU loại tấn công khác nhau (không phải 1-1)
- Attack Tree = quan hệ OR -> cần phòng thủ NHIỀU lớp, không chỉ 1 điểm
- Distroless + readOnlyRootFilesystem chặn được nhiều Attack Vector cùng lúc
- Principle of Least Privilege là biện pháp lặp lại ở HẦU HẾT mitigation
