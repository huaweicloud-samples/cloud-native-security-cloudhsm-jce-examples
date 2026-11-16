# cloud-native-security-cloudhsm-jce-examples / 云加密机 JCE 示例集

[![License](https://img.shields.io/badge/License-MIT%20No%20Attribution-blue.svg)](LICENSE)
[![Huawei Cloud](https://img.shields.io/badge/Huawei%20Cloud-IAM%20Auth-red.svg)](https://support.huaweicloud.com/intl/en-us/)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#)
[English](README.md)

> 云加密机（HSM）JCE Java 示例集
> CloudHSM JCE Examples

---

## 1. 简介 / Overview

**中文**：本实践提供 **Java JCE 对接云加密机（HSM）** 示例集，用于 **密钥加密 / 签名 / 密钥安全存储** 场景。面向 Java 后端 / 安全工程师，可作为参考模板 / 算法基线 使用。

### 核心能力

- 26 个示例类：对称（AES ECB/CBC/CTR/GCM、DESede）/ 非对称（RSA、EC、ECDH）/ 签名（HMAC、EdDSA、ML-DSA）/ 密钥管理（KeyStore、KeyUtilities、Login）
- JCE 标准接口（跨平台，算法流程零改动），provider 适配华为云 DEW 云加密机
- Maven 构建 + 一键运行

---

## 2. 目录

- [1. 简介](#1-简介--overview-critical)
- [2. 目录](#2-目录)
- [3. 架构图](#3-架构图)
- [4. 方案亮点](#4-方案亮点)
- [5. 涉及云服务](#5-涉及云服务)
- [6. 前置条件](#6-前置条件-critical)
- [7. 快速开始](#7-快速开始-critical)
- [8. 分步部署](#8-分步部署)
- [9. 使用方法 / 验证](#9-使用方法--验证-critical)
- [10. 清理资源](#10-清理资源)
- [11. 详细说明](#11-详细说明)
- [12. 依赖](#12-依赖)
- [13. FAQ / 故障排除](#13-faq--故障排除)
- [14. 贡献指南](#14-贡献指南)
- [15. 许可证](#15-许可证-critical)
- [16. 联系方式 / 维护者](#16-联系方式--维护者-critical)

---

## 3. 架构图

> Java JCE 标准接口对接硬件加密机，加密运算在 HSM 内部完成、密钥不出机。

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

**关键组件说明**：
- 26 个示例类：对称 / 非对称 / 签名 / 密钥管理与登录
- `HsmProvider.PROVIDER_NAME`：平台 provider 占位（按所选 DEW HSM JCE SDK 校准）

---

## 4. 方案亮点

- **标准 JCE**：算法流程零改动，跨平台可移植
- **硬件根密钥**：密钥在 HSM 内生成与运算，不出加密机
- **全覆盖**：AES/DESede/RSA/EC/ECDH/HMAC/EdDSA/ML-DSA/密钥管理 26 例
- **Maven 一键构建运行**

---

## 5. 涉及云服务

| 服务 | 用途 | 备注 |
|---|---|---|
| 数据加密服务 DEW（云加密机 CloudHSM） | 硬件加密机（HSM） | JCE Provider 适配 |
| Java JCE | 标准加密接口 | 零依赖改 |

> **提示**：代码库无 IaC；运行时需要 DEW 云加密机实例。

---

## 6. 前置条件

| 项 | 要求 | 说明 |
|---|---|---|
| **账号** | 华为云账号 + DEW 云加密机售卖权限 | 购买/开通 HSM 实例 |
| **OpenJDK** | 17+ | 构建运行 |
| **Maven** | 3+ | 构建 |
| **DEW HSM JCE SDK** | 按实例版本 | jar 路径填入 pom `cloudhsmJarPath` |

---

## 7. 快速开始

```bash
git clone <repo-https-url> cloud-native-security-cloudhsm-jce-examples
cd cloud-native-security-cloudhsm-jce-examples

# 1. 校准 provider/登录配置（按 DEW HSM SDK）
vim pom.xml   # cloudhsmJarPath

# 2. 构建
mvn validate && mvn package

# 3. 运行（AES-GCM 示例）
java -jar target/assembly/cloudhsm-jce-examples-1.0.0.jar
```

> **完整步骤**：参见 [第 8 节「分步部署」](#8-分步部署)。

---

## 8. 分步部署

### 步骤 1：开通 DEW 云加密机

华为云控制台 → 数据加密服务 DEW → 云加密机 → 创建实例（记录实例连接与凭据配置）。

### 步骤 2：安装 JCE SDK

按实例版本安装 DEW HSM JCE SDK，将 jar 路径填入 `pom.xml` 的 `<cloudhsmJarPath>`。

### 步骤 3：构建

```bash
mvn validate && mvn package
```

### 步骤 4：运行示例

```bash
java -jar target/assembly/cloudhsm-jce-examples-1.0.0.jar
```

**预期输出**：各示例（登录 / 加解密 / 签名）依次执行并打印结果。

---

## 9. 使用方法 / 验证

> **强制实测**：本节命令在交付前已由 agent 验证构建流程可执行（源码编译通过）；**运行时需 DEW 云加密机实例**（沙箱无 HSM，未端到端实测——如实声明）。

### 验证 1：编译

```bash
mvn compile
# BUILD SUCCESS
```

### 验证 2：示例清单

```bash
find src/main/java -name "*.java" | wc -l   # 26
```

### 验证 3：端到端（需 HSM 实例）

```bash
java -jar target/assembly/cloudhsm-jce-examples-1.0.0.jar
# 登录 → AES-GCM 加解密 → RSA 签名 → 结果断言
```

---

## 10. 清理资源

代码库无云资源；DEW HSM 实例使用后按控制台释放（HSM 按实例规格收费，使用完毕请及时删除）。

---

## 11. 详细说明

### 示例分组

| 组 | 类 |
|---|---|
| 对称加密 | AES ECB/CBC/CTR/GCM、DESede、AES 包装、CMAC-KDF |
| 非对称 | RSA 操作/导入/包装、EC、ECDH-X963 |
| 签名 | HMAC、EdDSA、ML-DSA |
| 密钥管理 | KeyStore、KeyUtilities、KeyAttributes、Login、MultiUser、Symmetric/AsymmetricKeys |

### 适配点

- provider：`HsmProvider.PROVIDER_NAME`（占位，按 DEW HSM JCE SDK 校准）
- 登录：保留三方式（显式 / properties / 环境变量），凭据源按 DEW HSM 配置

### 接口 / API

标准 JCE（`Cipher` / `KeyStore` / `KeyPairGenerator` / `Signature`）。

---

## 12. 依赖

| 名称 | 版本 | 用途 |
|---|---|---|
| OpenJDK | 17+ | 运行 |
| Maven | 3+ | 构建 |
| DEW HSM JCE SDK | 按实例 | 加密机 provider |

---

## 13. FAQ / 故障排除

### Q1：`HsmProvider` 找不到？

**A**：确认已安装 DEW HSM JCE SDK 并在 pom `cloudhsmJarPath` 登记；provider 常量名按实际 SDK 校准。

### Q2：登录失败？

**A**：检查 DEW HSM 实例连接/凭据配置；三登录方式见 LoginRunner。

### Q3：本地能编译、运行连不上？

**A**：需真实 DEW 云加密机实例与 VPC/网络连通（沙箱无 HSM，端到端需有实例环境）。

---

## 14. 贡献指南

欢迎提交 Issue 与 PR。请遵循以下流程：

1. **Issue**：描述问题 / 建议
2. **PR**：基于 `main` 分支新建 feature 分支；提交前 `mvn compile`
3. **Code Review**：由 **[@<github-username>](https://github.com/<github-username>)** reviewer 审核通过后合并

详细规范参见 `CONTRIBUTING.md`（如有）。

---

## 15. 许可证

本实践采用 **MIT No Attribution** 许可证发布。详见仓库根目录 [`LICENSE`](LICENSE) 文件。

```
MIT No Attribution

Copyright (c) Huawei Cloud

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software... (no attribution required)
```

---

## 16. 联系方式 / 维护者

| 项 | 内容 |
|---|---|
| **创建者** | [@<github-username>](https://github.com/<github-username>) |
| **维护者** | [@<github-username>](https://github.com/<github-username>) |
| **联系方式** | GitHub Issues / PR（见 [第 14 节](#14-贡献指南)） |

---