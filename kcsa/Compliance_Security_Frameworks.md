# KCSA Study Notes — Compliance and Security Frameworks (Domain 6, 10%)

Tổng hợp đầy đủ 4 bài trong section Compliance and Security Frameworks: Compliance Frameworks, Threat Modelling Frameworks, Supply Chain Compliance, Automation and Tooling.

---

## 1. Compliance Frameworks

### Vấn đề cần giải quyết
Bảo vệ dữ liệu nhạy cảm (thông tin cá nhân, hồ sơ y tế, chi tiết thanh toán) và đảm bảo tuân thủ pháp luật. Bỏ qua các khung này có thể dẫn tới data breach, phạt tiền nặng, mất lòng tin khách hàng.

### Bảng so sánh 5 Framework

| Framework | Scope | Key Requirements |
|---|---|---|
| GDPR | Bảo vệ dữ liệu cá nhân EU | Mã hoá data at rest, giới hạn truy cập dữ liệu |
| HIPAA | PHI (thông tin y tế) tại Mỹ | Mã hoá TLS, access control chặt, bảo mật Secret |
| PCI DSS | Dữ liệu thẻ thanh toán | Mã hoá in-transit & at-rest, auditing, strong auth |
| NIST | Best practice an ninh mạng | Risk assessment, security control, audit định kỳ |
| CIS Benchmarks | Hardening hệ thống IT | Secure config, RBAC, network policy, logging |

### GDPR (General Data Protection Regulation)
Quy định EU bảo vệ dữ liệu cá nhân và quyền riêng tư. Trong bối cảnh web app:
- Mã hoá user data lưu trong database (data at rest)
- Đảm bảo chỉ backend service được authorized mới truy cập được personal data

### HIPAA (Health Insurance Portability and Accountability Act)
Quy định Mỹ bảo vệ Protected Health Information (PHI). Yêu cầu:
- Mã hoá TOÀN BỘ data transfer (frontend ↔ backend ↔ database) bằng TLS
- Implement access control chặt để ngăn truy cập trái phép
- Cấu hình Kubernetes Secrets an toàn cho ứng dụng dùng

TLS certificate cần được quản lý qua CA an toàn và rotate định kỳ.

### PCI DSS (Payment Card Industry Data Security Standard)
Áp dụng cho MỌI hệ thống xử lý dữ liệu thẻ thanh toán:
- Mã hoá cardholder data cả in-transit và at-rest
- Enforce access control mạnh
- Monitor và audit MỌI truy cập vào payment information

### NIST (National Institute of Standards and Technology)
Xuất bản Cybersecurity Framework để cải thiện bảo mật/khả năng phục hồi hệ thống:
- Thực hiện risk assessment định kỳ để tìm lỗ hổng
- Triển khai security controls (firewall, IDS/IPS)
- Thực hiện security audit định kỳ

### CIS Benchmarks (Center for Internet Security)
Cung cấp benchmark chi tiết để bảo mật hệ thống IT, bao gồm Kubernetes:
- Secure config cho control plane component (API server, etcd, kubelet, controller-manager, scheduler)
- Authentication/authorization (enforce RBAC, disable anonymous access)
- Logging, monitoring, network policy, pod security

Công cụ **kube-bench** (của Aqua Security) tự động verify các benchmark này.

Ví dụ output kube-bench:
```
[INFO]  1.1 API Server
[FAIL]  1.1.1 Ensure that the --allow-privileged argument is set to false (Scored)
[FAIL]  1.1.2 Ensure that the --anonymous-auth argument is set to false (Scored)
[PASS]  1.1.3 Ensure that the --basic-auth-file argument is not set (Scored)
[FAIL]  1.1.14 Ensure that the --audit-log-path argument is set as appropriate (Scored)
[FAIL]  1.1.15 Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (Scored)
[FAIL]  1.1.16 Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (Scored)
[FAIL]  1.1.17 Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (Scored)
[FAIL]  1.1.18 Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored)
```
Lưu ý: các con số mặc định CIS gợi ý khớp với giá trị mình đã ôn: `audit-log-maxage=30`, `audit-log-maxbackup=10`, `audit-log-maxsize=100`.

### Key takeaways
- Compliance framework hướng dẫn data protection, encryption, access control
- GDPR nhắm vào personal data của EU citizen
- HIPAA bảo vệ PHI
- PCI DSS bảo mật payment card data
- NIST cung cấp risk assessment + security control guideline
- CIS Benchmarks cung cấp check tự động, chi tiết cho Kubernetes security

---

## 2. Threat Modelling Frameworks

### Compliance Framework vs Threat Modeling — Phân biệt cốt lõi
```
Compliance Framework (GDPR, HIPAA, PCI DSS, NIST, CIS) -> Định nghĩa "WHAT" (cái GÌ) cần làm
Threat Modeling Framework (STRIDE, MITRE ATT&CK)        -> Định nghĩa "HOW" (LÀM SAO) để làm

VD: GDPR bắt buộc bảo vệ personal data khỏi truy cập trái phép,
    NHƯNG KHÔNG chỉ định CÁCH LÀM cụ thể ra sao
    -> Threat Modeling Framework lấp đầy khoảng trống này bằng phương pháp có cấu trúc
       (attack tree, matrix) để tìm ra tấn công tiềm ẩn và đề xuất biện pháp cụ thể
```

2 framework phổ biến nhất: **STRIDE** (Microsoft) và **MITRE ATT&CK** (global knowledge base).

### STRIDE — 6 loại Threat

| Threat Type | Định nghĩa | Mitigation phổ biến |
|---|---|---|
| Spoofing | Giả mạo danh tính user/system hợp pháp | MFA, certificate-based auth |
| Tampering | Sửa đổi trái phép dữ liệu in-transit hoặc at-rest | Encryption, digital signature |
| Repudiation | Chối bỏ hành động đã thực hiện (VD: giao dịch) | Logging toàn diện, kỹ thuật non-repudiation |
| Information Disclosure | Lộ dữ liệu nhạy cảm | TLS cho transit, disk encryption |
| Denial of Service | Cạn tài nguyên hoặc gián đoạn dịch vụ | Rate limiting, resource quota, autoscaling policy |
| Elevation of Privilege | Chiếm quyền cao hơn trái phép | RBAC, least privilege |

**Chi tiết từng loại (theo ví dụ chính thức của course):**

1. **Spoofing**: Attacker forge credential để truy cập frontend (VD: NGINX). Mitigation: enforce strong authentication + certificate validation.

2. **Tampering**: Adversary alter data khi đang truyền hoặc lưu trên backend service. Mitigation: end-to-end encryption + checksum/digital signature.

3. **Repudiation**: User/attacker deny đã thực hiện hành động cụ thể (VD: chuyển tiền). Mitigation: immutable audit log + digital-signature-based non-repudiation.

4. **Information Disclosure**: Thông tin nhạy cảm (VD: customer PII trong MySQL) bị lộ. Mitigation: encrypt data at rest + enforce TLS/TCP encryption in transit.

5. **Denial of Service**: Attacker flood application, làm cạn resource gây outage. Mitigation: configure rate limit, implement Kubernetes resource quota, deploy autoscaling.

6. **Elevation of Privilege**: 1 principal không được authorized chiếm được admin-level right trong cluster. Mitigation: enforce strict RBAC policy + review privilege định kỳ.

> Tích hợp STRIDE SỚM trong quá trình thiết kế giúp phát hiện lỗ hổng TRƯỚC KHI đưa vào production.

### MITRE ATT&CK — Tactics và Techniques thực tế

Catalog các tactic (mục tiêu) và technique (phương pháp) của adversary quan sát được TRONG THỰC TẾ. Với Kubernetes, các technique map vào kịch bản cluster cụ thể:

```
Initial Access:      Khai thác authentication yếu, chiếm cloud credentials
Execution:            Deploy malicious container hoặc init-hook
Persistence:          Tạo backdoor user account, cài rogue controller
Privilege Escalation: Lợi dụng RBAC/admission controller cấu hình sai
Defense Evasion:      Tắt logging, sửa đổi audit trail
```

### MITRE Kubernetes Threat Matrix
Microsoft điều chỉnh ATT&CK cho bối cảnh cluster, giúp team visualize attacker pathway và thiết kế mitigation nhắm đúng mục tiêu.

Ví dụ dưới tactic "Using Cloud Credentials" (Initial Access), ATT&CK khuyến nghị:
- Bật multi-factor authentication
- Giới hạn API server exposure bằng IP allowlist
- Áp dụng least-privilege principle cho ServiceAccount

> Bỏ qua việc map MITRE technique vào deployment Kubernetes của bạn có thể để lại attack path quan trọng KHÔNG được xử lý.

### Tổng kết — Kết hợp Compliance + Threat Modeling
```
1. Compliance Framework -> Hiểu WHAT requirement áp dụng cho môi trường của bạn
2. Threat Modeling      -> Xác định HOW để triển khai control giảm thiểu rủi ro thực tế
3. Liên tục tinh chỉnh phòng thủ qua threat analysis có cấu trúc
```
Tích hợp cả 2 model vào SDLC (Software Development Life Cycle) để xác định rủi ro SỚM và xây dựng hệ thống resilient.

---

## 3. Supply Chain Compliance

### Vấn đề — Vượt ra ngoài Threat Modeling nội bộ
Supply chain security đảm bảo MỌI external dependency (library, container image, third-party API) đều được verify, không bị tamper, và tuân thủ.

### 4 Core Area của Supply Chain Security

| Core Area | Mô tả | Tool/Standard |
|---|---|---|
| Artifacts | Build output: image, binary | Sigstore Cosign |
| Metadata | Software Bill of Materials (SBOM) | SPDX |
| Attestations | Signed provenance statement | in-toto |
| Policies | Automated compliance enforcement | Sigstore Policy Controller |

### 1. Artifacts — Ký và Verify

Artifact (image, binary, library) PHẢI được ký để chứng minh tính toàn vẹn + nguồn gốc.

Cosign (của Sigstore) cung cấp workflow ký KEYLESS đơn giản:
```bash
cosign sign $IMAGE
```
Output mẫu:
```
Generating ephemeral keys...
Retrieving signed certificate...
Successfully verified SCT...
tlog entry created with index: 12086900
Pushing signature to: $IMAGE
```

Verify binary/image:
```bash
cosign verify-blob "$BINARY" \
  --signature "$BINARY.sig" \
  --certificate "$BINARY.cert" \
  --certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com \
  --certificate-oidc-issuer https://accounts.google.com
```

### 2. Metadata — Sinh và Validate SBOM

SBOM = "danh sách nguyên liệu" của ứng dụng — liệt kê file checksum, license, nguồn gốc từng component. Thường viết bằng format **SPDX**.

Ví dụ excerpt SPDX:
```
FileName: bin/linux/amd64/kube-controller-manager
SPDXID: SPDXRef-File-kube-controller-manager-v1.31.2
FileChecksum: SHA1: c5e8da214abd18e96aabe7d1bab6addf76455
FileChecksum: SHA256: b16b6becee2bc76af97384ca611d8e972aa7ed213ea75255
LicenseConcluded: Apache-2.0
```

Retrieve và verify SBOM của Kubernetes chính thức:
```bash
VERSION=$(curl -Ls https://dl.k8s.io/release/stable.txt)
curl -Ls "https://sbom.k8s.io/$VERSION/release" -o "$VERSION.spdx"
echo "$(curl -Ls "https://sbom.k8s.io/$VERSION/release.sha512")  $VERSION.spdx" | sha512sum --check
curl -Ls "https://sbom.k8s.io/$VERSION/release.sig"  -o "$VERSION.spdx.sig"
curl -Ls "https://sbom.k8s.io/$VERSION/release.cert" -o "$VERSION.spdx.cert"
cosign verify-blob \
  --certificate "$VERSION.spdx.cert" --signature "$VERSION.spdx.sig" \
  --certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com \
  --certificate-oidc-issuer https://accounts.google.com "$VERSION.spdx"
```

### 3. Attestations — Xây dựng Chain of Trust

Attestation = phát biểu mật mã (cryptographic statement) xác nhận metadata như provenance, tính xác thực SBOM, hoặc kết quả vulnerability scan.

Ký SBOM attestation:
```bash
cosign sign --key <PRIVATE_KEY> sbom.k8s.io/v1.27.4/release.spdx > sbom.attestation
```

Verify attestation:
```bash
cosign verify-attestation \
  --key <PUBLIC_KEY> \
  --certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com \
  --certificate-oidc-issuer https://accounts.google.com \
  sbom.k8s.io/v1.27.4/release.spdx
```

**in-toto** định nghĩa và verify attestation xuyên suốt TOÀN BỘ pipeline (KHÔNG PHẢI 1 tool, mà là 1 FRAMEWORK). Ví dụ step definition:
```yaml
- name: build
  expected_command:
    - "make"
  pubkeys: ["developer"]
  expected_materials:
    - "MATCH repo/* WITH REPO"
  expected_products:
    - "CREATE binary"
```

### 4. Policies — Automated Compliance Enforcement

Policy chặn deploy artifact chưa ký hoặc không tuân thủ. Ví dụ `ClusterImagePolicy`:
```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: secure-image-policy
spec:
  images:
    - glob: "gcr.io/my-organization/*"
  authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          YOUR_PUBLIC_KEY_HERE
          -----END PUBLIC KEY-----
  attestations:
    - name: sbom-check
      predicateType: https://in-toto.io/Statement/v0.1
    - name: vulnerability-check
      predicateType: https://slsa.dev/provenance/v0.2
  policy:
    validate:
      all:
        - name: sbom-validation
          match:
            attestation-name: sbom-check
        - name: vulnerability-validation
          match:
            attestation-name: vulnerability-check
        - name: signing-validation
          match:
            signed: true
```
Enforce policy tại thời điểm admission bằng **Sigstore Policy Controller**.

### Sơ đồ toàn cảnh Supply Chain Security
```
1. Artifacts (Cosign sign)
      ↓
2. Metadata/SBOM (SPDX format, liệt kê thành phần + license)
      ↓
3. Attestations (Cosign attest, ký SBOM/metadata — theo chuẩn in-toto)
      ↓
4. Policies (ClusterImagePolicy, verify chữ ký + attestation tại admission time)
```

---

## 4. Automation and Tooling

### Nguồn tham khảo chính thức
**Cloud Native Security Whitepaper** (SIG Security/TAG Security) — Cloud Native Security Map tương tác tại **cnsmap.netlify.app**, tổ chức tool theo 4 giai đoạn: **Develop, Distribute, Deploy, Runtime**.

---

### Giai đoạn DEVELOP — "Shift-Left" testing

Tích hợp bảo mật SỚM vào code, Dockerfile, infrastructure-as-code. Commit artifact lên repository (GitHub, GitLab...) với automated check để:
- Block lỗ hổng nghiêm trọng khi ĐÃ CÓ fix
- Enforce container chạy non-root
- Giới hạn base image được phép dùng

**Fuzz Testing — OSS-Fuzz (Google):**
Tự động fuzz test open-source project để phát hiện crash và undefined behavior.

Ví dụ hàm cần test:
```python
def parse_integer(input_string):
    try:
        return int(input_string)
    except ValueError:
        return "Error: Not a valid integer"
```

Fuzz harness đơn giản:
```python
import random, string

def generate_random_string(length=10):
    charset = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(charset) for _ in range(length))

def fuzz_test_parse_integer(iterations=10):
    for _ in range(iterations):
        rand_in = generate_random_string(random.randint(1, 20))
        print(f"Testing: '{rand_in}' -> {parse_integer(rand_in)}")

fuzz_test_parse_integer()
```
Output mẫu:
```
Testing: '@123$%' -> Error: Not a valid integer
Testing: '87ab1' -> Error: Not a valid integer
Testing: '' -> Error: Not a valid integer
Testing: '42' -> 42
```

**IDE & CLI Security Extension:**
- **Snyk VS Code Extension** — quét lỗ hổng ngay trong IDE
- **Fabric8 (Red Hat)** — VS Code plugin, quét dependency, tích hợp workflow dev
- **kube-linter** — scan Kubernetes YAML:
```bash
kube-linter lint pod.yaml
```

---

### Giai đoạn DISTRIBUTE — CI/CD build, test, push image

**CI/CD Pipeline Tool:**

| Tool | Use Case |
|---|---|
| Tekton | Kubernetes-native pipeline |
| Jenkins | Automation server mở rộng được |
| Travis CI | Continuous testing hosted trên cloud |
| CircleCI | CI dựa trên container |
| Flux CD | GitOps continuous delivery |
| Argo CD | GitOps controller khai báo (declarative) |

**Trước khi build image — Enforce policy compliance trên manifest:**
- **KubeSec** — scan Kubernetes YAML tìm misconfiguration
- **TeraScan** — validate IaC (Terraform, Dockerfile, Helm, CloudFormation) theo CIS, NIST, GDPR, HIPAA

Ví dụ output TeraScan:
```
Violation Details =
  Description: [Enabling S3 versioning allows easy recovery]
  file: modules/s3/main.tf
  Severity: 101
  Rule ID: AWS.S3Bucket.IAM.High.0370
```
Luôn validate manifest TRƯỚC khi build image để tránh deploy config không an toàn.

**Sau validation — Build và Scan image:**

| Scanner | Scope | Ví dụ lệnh |
|---|---|---|
| Trivy | Container image, filesystem, Git repo | `trivy image myapp:latest` |
| Clair | Static image analysis qua API | API integration |
| Grype | Image & filesystem scanning | `grype myimage:tag` |
| Nuclei | Custom check qua YAML template | `nuclei -t templates/` |

**Signing framework bảo mật supply chain:**
- **in-toto** — end-to-end supply chain security
- **Notary**, **TUF** (The Update Framework), **Sigstore**

---

### Giai đoạn DEPLOY — Pre-flight check, Observability, Incident Response

**Pre-flight Checks (Policy Enforcement):**
- **OPA Gatekeeper** — viết policy bằng ngôn ngữ Rego
- **Kyverno** — quản lý policy dựa trên YAML

**Observability:**
- **Prometheus** + **Grafana**
- **Elasticsearch** + **Kibana**
- **OpenTelemetry**

**Response & Investigation:**
- **Wazuh**
- **Snort**
- **Zeek**

---

### Giai đoạn RUNTIME — Bảo mật + độ tin cậy liên tục

**CIS Benchmarking:**
- **kube-bench** — CIS check cho Kubernetes cluster:
```
[FAIL] 1.1.1 Ensure --allow-privileged is false
[PASS] 1.1.2 Ensure --anonymous-auth is not set
```

**Runtime Security:**
- **Falco** — giám sát system call
- **Trivy** — quét workload liên tục
- **SPIFFE** — workload identity qua certificate

**Service Mesh:**
- **Istio**, **Linkerd**

**Storage Orchestration:**
- **Rook**, **Ceph**, **Gluster**

**Access Management:**
- **Keycloak**, **Teleport**, **HashiCorp Vault**

---

### Tổng kết — Map Tool theo 4 giai đoạn lifecycle

```
Develop:     Shift-left scanner (OSS-Fuzz, Snyk Code, Fabric8, kube-linter) & IDE plugin
Distribute:  CI/CD pipeline (Tekton/Jenkins/ArgoCD), manifest scanner (KubeSec/TeraScan),
             image scanner (Trivy/Clair/Grype/Nuclei), signing framework (in-toto/Notary/Sigstore)
Deploy:      Policy enforcement (OPA Gatekeeper/Kyverno), observability (Prometheus+Grafana,
             ELK stack, OpenTelemetry), incident response (Wazuh/Snort/Zeek)
Runtime:     CIS benchmark (kube-bench), runtime security (Falco/Trivy/SPIFFE),
             service mesh (Istio/Linkerd), storage (Rook/Ceph/Gluster),
             access management (Keycloak/Teleport/Vault)
```

---

## Tổng kết nhanh (Cheat Sheet) — Toàn bộ Domain

### Compliance Framework — Keyword hay gặp

| Keyword trong đề | Đáp án |
|---|---|
| Bảo vệ personal data công dân EU | GDPR |
| Bảo vệ Protected Health Information (Mỹ) | HIPAA |
| Bảo mật dữ liệu thẻ thanh toán | PCI DSS |
| Risk assessment, security control framework | NIST |
| Hardening checklist chi tiết cho K8s, tool tự động check | CIS Benchmarks + kube-bench |

### Threat Modeling Framework

| Câu hỏi | Đáp án |
|---|---|
| Framework định nghĩa "WHAT" cần tuân thủ | Compliance Framework |
| Framework định nghĩa "HOW" để triển khai | Threat Modeling (STRIDE, MITRE ATT&CK) |
| 6 loại threat của Microsoft | STRIDE |
| Catalog tactic/technique THỰC TẾ trong tự nhiên | MITRE ATT&CK |
| Bản đồ ATT&CK áp dụng riêng cho K8s | MITRE Kubernetes Threat Matrix |

### Supply Chain Compliance

| Khái niệm | Công cụ/Chuẩn tương ứng |
|---|---|
| Ký artifact (image/binary) | Cosign (Sigstore) |
| Định dạng SBOM | SPDX |
| Framework định nghĩa/verify attestation toàn pipeline | in-toto |
| Enforce policy tại admission time | Sigstore Policy Controller |
| Object K8s để chặn image không tuân thủ | ClusterImagePolicy |

### Automation and Tooling — Bảng tool theo giai đoạn

| Giai đoạn | Tool tiêu biểu |
|---|---|
| Develop | OSS-Fuzz, Snyk Code, Fabric8 (Red Hat), kube-linter |
| Distribute | Tekton/Jenkins/ArgoCD, KubeSec/TeraScan, Trivy/Clair/Grype/Nuclei, in-toto/Notary/Sigstore |
| Deploy | OPA Gatekeeper/Kyverno, Prometheus+Grafana, Wazuh/Snort/Zeek |
| Runtime | kube-bench, Falco/SPIFFE, Istio/Linkerd, Rook/Ceph, Keycloak/Vault |

### Nguyên tắc chung xuyên suốt domain
```
- Compliance framework = pháp lý/tiêu chuẩn ngành (WHAT)
- Threat modeling framework = phương pháp kỹ thuật (HOW)
- Supply chain compliance = áp compliance CHUYÊN SÂU vào artifact/build pipeline
- Automation/tooling = KHÔNG dạy khái niệm mới, mà RÁP NỐI toàn bộ tool đã học
  theo đúng 4 giai đoạn lifecycle: Develop -> Distribute -> Deploy -> Runtime
- "Shift-left" = đưa kiểm tra bảo mật CÀNG SỚM CÀNG TỐT trong vòng đời phát triển
```
