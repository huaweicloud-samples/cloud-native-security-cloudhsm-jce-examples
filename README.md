# cloud-native-security-cloudhsm-jce-examples / CloudHSM JCE Examples

[![License](https://img.shields.io/badge/License-MIT%20No%20Attribution-blue.svg)](LICENSE)
[![Huawei Cloud](https://img.shields.io/badge/Huawei%20Cloud-IAM%20Auth-red.svg)](https://support.huaweicloud.com/intl/en-us/)
[中文版](README.cn.md)

> CloudHSM (Hardware Security Module) JCE Java Examples

## 1. Overview

This practice provides **Java JCE integration with a Cloud HSM** examples for **encryption / signing / secure key storage**. It is intended for Java backend / security engineers and can be used as a reference / algorithm baseline.

- 26 example classes: symmetric (AES ECB/CBC/CTR/GCM, DESede) / asymmetric (RSA, EC, ECDH) / signing (HMAC, EdDSA, ML-DSA) / key management (KeyStore, KeyUtilities, Login)
- Standard JCE interface (cross-platform; algorithm flows unchanged), provider adapted to DEW CloudHSM
- Maven build + one-command run

## 2. Table of Contents

- [1. Overview](#1-overview) / [2. TOC](#2-table-of-contents) / [3. Architecture](#3-architecture) / [4. Highlights](#4-highlights) / [5. Services](#5-involved-cloud-services) / [6. Prerequisites](#6-prerequisites-critical) / [7. Quick Start](#7-quick-start-critical) / [8. Deployment](#8-step-by-step-deployment) / [9. Verification](#9-usage--verification-critical) / [10. Cleanup](#10-clean-up-resources) / [11. Details](#11-detailed-explanation) / [12. Dependencies](#12-dependencies) / [13. FAQ](#13-faq--troubleshooting) / [14. Contribution](#14-contribution-guide) / [15. License](#15-license-critical) / [16. Contact](#16-contact--maintainers-critical)

## 3. Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                     Java 应用（JCE 标准接口）                      │
│                  Cipher / KeyStore / KeyGenerator                  │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │ 标准 JCE 调用
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│              HsmProvider（DEW 云加密机 JCE Provider）              │
└──────────────────────────────────┬─────────────────────────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│                      DEW 云加密机（HSM）实例                       │
│                          密钥不出硬件边界                          │
└────────────────────────────────────────────────────────────────────┘
```

## 4. Highlights

- **Standard JCE**: algorithm flows unchanged, cross-platform
- **Hardware-rooted keys**: keys generated and operated inside HSM
- **Full coverage**: AES/DESede/RSA/EC/ECDH/HMAC/EdDSA/ML-DSA/key management (26 examples)
- **Maven build + one-command run**

## 5. Involved Cloud Services

| Service | Purpose | Notes |
|---|---|---|
| DEW CloudHSM | hardware security module | JCE provider adaptation |
| Java JCE | standard crypto interfaces | zero dependency change |

> Note: code-only repository (no IaC); runtime needs a DEW CloudHSM instance.

## 6. Prerequisites

| Item | Requirement | Notes |
|---|---|---|
| **Account** | Huawei Cloud + DEW CloudHSM availability | create HSM instance |
| **OpenJDK** | 17+ | build/run |
| **Maven** | 3+ | build |
| **DEW HSM JCE SDK** | per instance version | jar path to pom `cloudhsmJarPath` |

## 7. Quick Start

```bash
git clone <repo-https-url> cloud-native-security-cloudhsm-jce-examples
cd cloud-native-security-cloudhsm-jce-examples
vim pom.xml   # cloudhsmJarPath
mvn validate && mvn package
java -jar target/assembly/cloudhsm-jce-examples-1.0.0.jar
```

## 8. Step-by-step Deployment

1. Create a DEW CloudHSM instance in the console
2. Install the matching DEW HSM JCE SDK; set its jar path in `pom.xml`
3. `mvn validate && mvn package`
4. `java -jar target/assembly/cloudhsm-jce-examples-1.0.0.jar`

## 9. Usage / Verification

> **Mandatory verification note**: build flow verified by the agent (`mvn compile`); **runtime requires a real DEW CloudHSM instance** (sandbox has no HSM; honest statement).

- Build: `mvn compile` -> BUILD SUCCESS
- Example count: `find src/main/java -name "*.java" | wc -l` -> 26
- End-to-end: run jar with a real HSM instance, assert encrypt/decrypt/sign outputs

## 10. Clean Up Resources

Code-only; release DEW CloudHSM instances in the console after use (instance metered).

## 11. Detailed Explanation

| Group | Classes |
|---|---|
| symmetric | AES ECB/CBC/CTR/GCM, DESede, AES wrap, CMAC-KDF |
| asymmetric | RSA ops/import/wrap, EC, ECDH-X963 |
| signing | HMAC, EdDSA, ML-DSA |
| key mgmt | KeyStore, KeyUtilities, KeyAttributes, Login, MultiUser, Symmetric/AsymmetricKeys |

Adaptation: `HsmProvider.PROVIDER_NAME` placeholder (calibrate per DEW HSM JCE SDK); login keeps three modes (explicit/properties/env).

## 12. Dependencies

| Name | Version | Purpose |
|---|---|---|
| OpenJDK | 17+ | runtime |
| Maven | 3+ | build |
| DEW HSM JCE SDK | per instance | HSM provider |

## 13. FAQ / Troubleshooting

- `HsmProvider` not found? Install the DEW HSM JCE SDK and set `cloudhsmJarPath`; calibrate provider constant.
- Login failed? Check DEW HSM instance connectivity/credentials; see LoginRunner.
- Compiles but cannot connect? Need a real DEW CloudHSM instance + network (no HSM in sandbox).

## 14. Contribution Guide

Issue / PR; run `mvn compile` before submitting.

## 15. License

Released under the **MIT No Attribution** license. See [`LICENSE`](LICENSE) in the repo root.

```
MIT No Attribution

Copyright (c) Huawei Cloud
```

## 16. Contact / Maintainers

[@<github-username>](https://github.com/<github-username>) via GitHub Issues / PR.
