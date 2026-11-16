# 使用指导书

## 1. 前置条件

- DEW 云加密机（CloudHSM）实例（华为云数据加密服务 DEW → 云加密机）
- OpenJDK 17 + Maven 3
- DEW HSM JCE SDK（按所选实例版本安装，jar 路径登记在 pom.xml `<cloudhsmJarPath>`）

## 2. 构建

```bash
mvn validate && mvn package
# 产物在 target/assembly/*.jar
```

## 3. 运行示例（以 AES-GCM 为例）

```bash
java -jar target/assembly/cloudhsm-jce-examples-1.0.0.jar
# 或按 pom assembly 配置运行指定 mainClass
```

## 4. 登录与配置

- 示例保留三登录方式（显式凭据 / Java properties / 环境变量），凭据源按 DEW HSM 实例配置
- `<cloudhsmJarPath>` 与 provider 常量请按实际 SDK 版本校准

## 5. 清理

本仓库为代码示例库，无云资源；使用后的 HSM 实例按 DEW 控制台释放。
