# yukvault 真实验收手册

这份文档用于在一台 Linux 主机上，使用真实 YubiKey 和真实本地文件系统，把 `yukvault` 的关键链路手工跑通。

本文档目标不是解释设计，而是给出一套你可以直接照着执行的操作步骤、预期结果和验收标志。

适用范围：

- 操作系统：Ubuntu / Debian 系 Linux
- 硬件：支持 FIDO2 的 YubiKey
- 当前仓库路径示例：`~/workspace/fidov`
- 当前二进制：`./yukvault`

## 一、验收目标

本轮验收至少要覆盖以下链路：

1. 构建成功
2. 真实 YubiKey `init` 成功
3. 真实 YubiKey `open` 成功
4. 在挂载点内创建测试文件
5. `close` 后数据写回 `.vault`
6. 再次 `open` 后文件仍然存在
7. 如启用恢复密钥，验证 `recover` 能打开 vault

## 二、前置条件

### 1. Go 与系统依赖

确认 Go 可用：

```bash
go version
```

推荐输出示例：

```text
go version go1.26.2 linux/amd64
```

确认依赖包已安装：

```bash
sudo apt update
sudo apt install -y build-essential pkg-config git curl
sudo apt install -y libfido2-dev libfido2-1 e2fsprogs
```

### 2. YubiKey 已插入

检查系统是否看到 `hidraw` 设备：

```bash
ls -l /dev/hidraw*
```

如果完全没有 `hidraw` 设备，不继续验收，先排查 USB 识别问题。

### 3. 挂载方式确认

当前 Linux 挂载逻辑如下：

- 如果系统有 `fuse2fs`，优先走无特权挂载
- 如果没有 `fuse2fs`，会退回到 `sudo mount -o loop`

先检查：

```bash
which fuse2fs
```

如果有输出，后续大概率不需要 sudo 密码。

如果没有输出，则 `open` / `recover` / 部分 `close` 路径可能要求 sudo。

### 4. 当前版本不包含开发伪实现开关

当前代码已经移除了 `YUKVAULT_FAKE_FIDO2` 这类开发绕过路径。验收时应直接使用真实 FIDO2 设备。

## 三、准备测试目录

在仓库根目录执行：

```bash
cd ~/workspace/fidov
rm -f ./secrets.vault ./secrets.vault.credid
rm -rf ./test-mount
mkdir -p ./test-mount
```

验收中会使用：

- vault 文件：`./secrets.vault`
- credential sidecar：`./secrets.vault.credid`
- 挂载点：`./test-mount`

## 四、构建验收

### 步骤

```bash
go mod tidy
go build -o yukvault ./main.go
go test ./...
```

### 预期结果

- `go mod tidy` 无错误
- `go build` 无错误
- `go test ./...` 通过

允许出现的输出：

- `? ... [no test files]`

### 失败判定

以下任一情况都算未通过：

- 依赖下载失败
- 编译失败
- `go test ./...` 报错

### 验收标志

- [ ] 构建通过
- [ ] 测试通过

## 五、初始化验收

### 步骤

执行：

```bash
./yukvault init --vault ./secrets.vault --size 256M --fs ext4
```

程序会要求：

1. 输入 YubiKey PIN
2. 再输入一次确认 PIN
3. 触摸 YubiKey

### 预期终端行为

典型过程：

```text
Enter YubiKey PIN:
Confirm YubiKey PIN:
Touch your YubiKey now…
Touch your YubiKey now…
Vault created: /absolute/path/to/secrets.vault
```

说明：

- 可能出现一次或两次 `Touch your YubiKey now…`
- 这是正常的，因为创建凭据和获取 HMAC 都可能触发用户在环确认

### 初始化后检查

执行：

```bash
ls -l ./secrets.vault ./secrets.vault.credid
```

### 预期结果

- `secrets.vault` 存在
- `secrets.vault.credid` 存在
- 两个文件权限都应为 `600`，表现为 `-rw-------`

### 失败判定

以下任一情况都算未通过：

- 提示 `no YubiKey detected`
- PIN 校验失败
- 触摸后报 FIDO2 错误
- 没有生成 `.credid`
- 没有生成 `.vault`

### 验收标志

- [ ] `init` 成功
- [ ] `.vault` 文件存在
- [ ] `.credid` 文件存在

## 六、打开挂载验收

### 步骤

执行：

```bash
./yukvault open --vault ./secrets.vault --mount ./test-mount
```

程序会要求：

1. 输入 YubiKey PIN
2. 触摸 YubiKey
3. 如果没有 `fuse2fs`，可能还会要求输入 sudo 密码

### 预期终端行为

成功时应看到类似：

```text
Enter YubiKey PIN:
Touch your YubiKey now…
Vault mounted at ./test-mount
```

### 挂载成功后检查

执行：

```bash
mount | grep test-mount
```

以及：

```bash
ls -la ./test-mount
```

### 预期结果

- `mount | grep test-mount` 有输出
- `./test-mount` 看起来像一个已格式化的文件系统目录，而不是空普通目录

### 状态文件检查

执行：

```bash
cat ~/.config/yukvault/mounts.json
```

### 预期结果

应能看到一个包含以下字段的挂载记录：

- `vault_path`
- `image_path`
- `mount_point`
- `opened_at`

### 失败判定

以下任一情况都算未通过：

- FIDO2 assertion 失败
- sudo 挂载失败
- 挂载点目录未真正挂载
- `mounts.json` 没有记录

### 验收标志

- [ ] `open` 成功
- [ ] 挂载点已真正挂载
- [ ] `mounts.json` 已记录

## 七、写入文件验收

### 步骤

在挂载点中创建测试文件：

```bash
echo 'hello from yukvault acceptance test' > ./test-mount/hello.txt
sync
cat ./test-mount/hello.txt
```

### 预期结果

输出应为：

```text
hello from yukvault acceptance test
```

### 验收标志

- [ ] 测试文件写入成功
- [ ] 文件内容读取正确

## 八、关闭写回验收

### 步骤

执行：

```bash
./yukvault close --vault ./secrets.vault
```

程序可能要求：

1. 输入 YubiKey PIN
2. 触摸 YubiKey
3. 如果之前挂载使用了 root mount，可能还需要 sudo 卸载

### 预期结果

成功时应看到：

```text
Vault closed and saved
```

### 关闭后检查

执行：

```bash
mount | grep test-mount
```

以及：

```bash
cat ~/.config/yukvault/mounts.json
```

### 预期结果

- `mount | grep test-mount` 无输出
- `mounts.json` 中对应记录被移除

### 失败判定

以下任一情况都算未通过：

- 卸载失败
- 重加密失败
- 临时镜像未删除
- 状态记录未清除

### 验收标志

- [ ] `close` 成功
- [ ] 挂载点已卸载
- [ ] 状态记录已清除

## 九、重开持久化验收

### 步骤

再次执行：

```bash
./yukvault open --vault ./secrets.vault --mount ./test-mount
```

然后检查测试文件：

```bash
cat ./test-mount/hello.txt
```

### 预期结果

输出仍应为：

```text
hello from yukvault acceptance test
```

### 失败判定

以下任一情况都算未通过：

- `open` 成功但文件不存在
- 文件存在但内容不一致
- 文件系统损坏无法读取

### 验收标志

- [ ] 二次 `open` 成功
- [ ] 测试文件仍存在
- [ ] 文件内容一致

## 十、恢复密钥验收

这一节仅在你使用 `--recover` 初始化时执行。

### 1. 重新初始化带恢复密钥的 vault

建议先清理旧文件：

```bash
./yukvault close --vault ./secrets.vault
rm -f ./secrets.vault ./secrets.vault.credid
rm -rf ./test-mount
mkdir -p ./test-mount
```

然后执行：

```bash
./yukvault init --vault ./secrets.vault --size 256M --fs ext4 --recover
```

### 2. 记录恢复助记词

程序会打印 24 个词。你必须完整保存下来。

### 3. 用恢复密钥打开

执行：

```bash
./yukvault recover \
  --vault ./secrets.vault \
  --key "word1 word2 word3 ... word24" \
  --mount ./test-mount
```

### 预期结果

成功时应看到：

```text
Vault mounted at ./test-mount
```

### 验收标志

- [ ] `--recover` 初始化成功
- [ ] 助记词已记录
- [ ] `recover` 成功挂载

## 十一、问题定位指南

### 场景 1：`select device` / `no YubiKey detected`

检查：

```bash
ls -l /dev/hidraw*
```

以及重新插拔 YubiKey。

### 场景 2：PIN 正确但 assertion / make credential 失败

常见原因：

- 触摸未及时完成
- 设备并非目标 YubiKey
- FIDO2 功能被策略限制

建议：

- 重试一次
- 如有多个 YubiKey，仅保留一个
- 明确传 `--device /dev/hidrawX`

### 场景 3：卡在 sudo 密码

说明当前机器没有走 `fuse2fs`，回退到了 loop mount。

检查：

```bash
which fuse2fs
```

如果为空，可安装：

```bash
sudo apt install -y e2fsprogs
```

### 场景 4：`Vault mounted at ...` 但目录没挂载

检查：

```bash
mount | grep test-mount
```

以及：

```bash
cat ~/.config/yukvault/mounts.json
```

### 场景 5：`close` 后重开文件丢失

需要收集：

1. `open` 时完整输出
2. `close` 时完整输出
3. `mounts.json` 内容
4. `ls -l` vault 文件时间戳变化

## 十二、最终通过标准

当且仅当下面所有项都勾选完成，才认为本轮真实验收通过：

- [ ] `go build -o yukvault ./main.go` 成功
- [ ] `go test ./...` 成功
- [ ] 真实 YubiKey `init` 成功
- [ ] `.vault` 与 `.credid` 文件都生成
- [ ] 真实 YubiKey `open` 成功
- [ ] 挂载点已真正挂载
- [ ] `mounts.json` 有记录
- [ ] 挂载点内能写入文件
- [ ] `close` 成功
- [ ] 挂载点已卸载
- [ ] `mounts.json` 记录已清除
- [ ] 再次 `open` 后文件仍存在

如果你启用了恢复功能，还要额外满足：

- [ ] `recover` 成功挂载

## 十三、建议的操作记录模板

你可以把下面这段复制到一个临时笔记里，边做边填：

```text
[构建]
- go mod tidy:
- go build:
- go test ./...:

[init]
- 命令:
- 输出:
- 是否成功:
- .vault 是否生成:
- .credid 是否生成:

[open #1]
- 命令:
- 是否要求 PIN:
- 是否要求触摸:
- 是否要求 sudo:
- 是否挂载成功:
- mounts.json 是否记录:

[写文件]
- 文件路径:
- 文件内容:

[close]
- 命令:
- 是否成功:
- 是否卸载:
- mounts.json 是否清理:

[open #2]
- 命令:
- 是否成功:
- hello.txt 是否存在:
- 内容是否一致:

[recover 可选]
- init --recover 是否成功:
- 助记词是否记录:
- recover 是否成功:
```
