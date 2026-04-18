# yukvault 使用指南

`yukvault` 是一个基于 YubiKey FIDO2 的命令行加密文件库工具。它不会逐个文件加密，而是把一个完整的文件系统镜像加密封装到单个 `.vault` 文件里。打开 vault 时，需要真实 YubiKey 参与密钥派生；关闭 vault 时，挂载中的数据会重新加密写回容器。

这份指南面向实际使用者，重点回答这些问题：

- 需要准备什么环境
- 如何创建、打开、关闭一个 vault
- 如何启用和使用恢复密钥
- 如何轮换 YubiKey 凭据
- 如何查看当前挂载状态
- 遇到常见错误时怎么处理

## 1. 核心概念

- `.vault` 文件：加密后的容器文件。
- `.credid` 文件：和 `.vault` 同路径的 sidecar 文件，保存 YubiKey FIDO2 credential ID。
- 挂载点：打开 vault 后，解密出的文件系统会挂载到一个目录。
- 恢复密钥：可选的 24 词 BIP-39 助记词，用于在 YubiKey 丢失或损坏时恢复打开 vault。

一个典型的文件组合长这样：

```text
secrets.vault
secrets.vault.credid
test-mount/
```

注意：

- `secrets.vault` 和 `secrets.vault.credid` 必须一起保留。
- 没有 `.credid` 时，正常 `open` / `close` / `rotate-key` 无法工作。
- 恢复密钥不是默认开启的，只有创建 vault 时加 `--recover` 才会生成。

## 2. 环境要求

### 2.1 操作系统

- Linux：当前最完整、已经实机验证过的路径。
- Windows：代码里有挂载接口，但建议先做真实环境验收再投入使用。

### 2.2 Go 版本

- Go `1.22+`

检查方式：

```bash
go version
```

### 2.3 Linux 依赖

Ubuntu / Debian 上建议安装：

```bash
sudo apt update
sudo apt install -y build-essential pkg-config git curl
sudo apt install -y libfido2-dev libfido2-1 e2fsprogs
```

其中：

- `libfido2-dev` / `libfido2-1`：真实 YubiKey FIDO2 接入需要。
- `e2fsprogs`：提供 `mkfs.ext4` 和 `fuse2fs`。
- 如果系统没有 `fuse2fs`，Linux 会尝试回退到 `sudo mount -o loop`。

### 2.4 硬件要求

- 一把支持 FIDO2 的 YubiKey
- 已知的 YubiKey PIN
- 能进行触摸确认

## 3. 构建与安装

在仓库根目录执行：

```bash
go mod tidy
make build
```

或者：

```bash
CGO_ENABLED=1 go build -o yukvault ./main.go
```

安装到本地：

```bash
make install
```

如果只想确认代码状态正常：

```bash
go test ./...
```

## 4. 基本命令结构

根命令格式：

```bash
yukvault --vault ./vault.vault --device /dev/hidrawX <subcommand>
```

全局参数：

- `--vault`：vault 文件路径。默认是 `./vault.vault`。
- `--device`：指定 FIDO2 设备路径。可选；不指定时会自动探测，如果有多个设备会提示你选择。

可用子命令：

- `init`
- `open`
- `close`
- `recover`
- `rotate-key`
- `list`

## 5. 快速开始

这是最常见的一条使用链路。

### 5.1 创建一个 vault

```bash
./yukvault init --vault ./secrets.vault --size 256M --fs ext4
```

运行过程会要求：

1. 输入 YubiKey PIN
2. 再输入一次 PIN 确认
3. 触摸 YubiKey
4. 可能再次触摸 YubiKey

成功时会看到：

```text
Vault created: /absolute/path/to/secrets.vault
```

成功后应生成两个文件：

- `./secrets.vault`
- `./secrets.vault.credid`

### 5.2 打开并挂载

```bash
mkdir -p ./test-mount
./yukvault open --vault ./secrets.vault --mount ./test-mount
```

运行过程会要求：

1. 输入 YubiKey PIN
2. 触摸 YubiKey

成功时会看到：

```text
Vault mounted at ./test-mount
```

此时你就可以像使用普通目录一样读写：

```bash
echo "hello" > ./test-mount/hello.txt
ls -la ./test-mount
cat ./test-mount/hello.txt
```

### 5.3 关闭并保存

```bash
./yukvault close --vault ./secrets.vault --mount ./test-mount
```

运行过程会要求：

1. 卸载挂载点
2. 输入 YubiKey PIN
3. 触摸 YubiKey
4. 重新加密镜像并写回 `.vault`

成功时会看到：

```text
Vault closed and saved
```

## 6. 命令详解

### 6.1 `init`

用途：初始化一个新的 vault。

示例：

```bash
./yukvault init \
  --vault ./secrets.vault \
  --size 512M \
  --fs ext4
```

参数：

- `--vault`：输出容器路径。
- `--size`：镜像大小，支持 `K`、`M`、`G` 后缀，如 `256M`、`1G`。
- `--fs`：文件系统类型，当前支持 `ext4` 和 `exfat`。
- `--mount`：创建完成后立即挂载。
- `--recover`：同时生成恢复密钥。

示例：创建后立即挂载

```bash
./yukvault init \
  --vault ./secrets.vault \
  --size 256M \
  --fs ext4 \
  --mount ./test-mount
```

示例：创建时同时生成恢复密钥

```bash
./yukvault init \
  --vault ./secrets.vault \
  --size 256M \
  --fs ext4 \
  --recover
```

如果启用了 `--recover`，程序会在终端输出 24 词恢复助记词。你必须离线、安全地保存它。

### 6.2 `open`

用途：用真实 YubiKey 打开 vault，并挂载到指定目录。

示例：

```bash
./yukvault open --vault ./secrets.vault --mount ./test-mount
```

要求：

- `.vault` 文件存在
- `.credid` 文件存在
- YubiKey 可访问
- PIN 正确

说明：

- `--mount` 必填
- 如果 Linux 上有 `fuse2fs`，优先使用 `fuse2fs`
- 如果没有 `fuse2fs`，会尝试回退到 `sudo mount -o loop`

### 6.3 `close`

用途：关闭已挂载的 vault，把当前挂载内的数据重新加密写回容器。

示例：

```bash
./yukvault close --vault ./secrets.vault --mount ./test-mount
```

说明：

- `close` 会先查状态文件，找到这个 vault 当前对应的临时镜像与挂载点。
- 如果之前是 root loop mount，卸载时可能需要 `sudo`。
- 关闭成功后，临时镜像会被擦除删除。

如果你不写 `--mount`，`close` 会按 `--vault` 试图定位挂载记录；但在存在多个挂载记录时，显式给 `--mount` 更稳妥。

### 6.4 `recover`

用途：在没有 YubiKey 正常打开路径可用时，使用恢复密钥打开 vault。

推荐方式：不要在命令行直接写出恢复密钥，直接执行：

```bash
./yukvault recover \
  --vault ./secrets.vault \
  --mount ./test-mount
```

程序会以不回显方式在终端提示输入恢复密钥。

示例，使用 24 词助记词：

```bash
./yukvault recover \
  --vault ./secrets.vault \
  --mount ./test-mount \
  --key "word1 word2 ... word24"
```

示例，使用 32 字节 hex：

```bash
./yukvault recover \
  --vault ./secrets.vault \
  --mount ./test-mount \
  --key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

限制：

- 当前实现只接受 24 词助记词，不接受 12 词。
- hex 必须能解码为恰好 32 字节，也就是 64 个十六进制字符。
- 如果 vault 创建时没有启用 `--recover`，这个命令会直接失败。

重要说明：

- 默认推荐通过终端安全输入恢复密钥，而不是通过 `--key` 暴露在命令行参数里。
- `--key` 仍然保留，主要用于兼容已有自动化或受控环境。
- `recover` 只负责打开并挂载。
- 当前 `close` 仍然需要正常的 YubiKey 路径，因为重新加密时需要再次派生主密钥。

如果你准备依赖恢复链路，建议先在真实环境完整演练一次：`init --recover -> recover -> close`。

### 6.5 `rotate-key`

用途：轮换 YubiKey 凭据和 vault 主密钥。

示例：

```bash
./yukvault rotate-key --vault ./secrets.vault
```

说明：

- 轮换前 vault 必须处于关闭状态，不能仍然挂载着。
- 轮换过程会读取旧 vault、解密、创建新凭据、重新派生新主密钥、重新加密并替换 `.vault` / `.credid`。
- 如果原 vault 启用了恢复密钥，轮换后会生成一套新的恢复助记词，并打印到终端。旧恢复助记词不应再继续使用。

建议：

1. 轮换前先做文件备份。
2. 轮换成功后立刻执行一次 `open` 验证。
3. 如果生成了新的恢复助记词，立刻更新你的离线备份。

### 6.6 `list`

用途：列出当前状态文件里记录的已挂载 vault。

示例：

```bash
./yukvault list
```

输出类似：

```text
VAULT PATH    MOUNT POINT    OPENED AT
/path/a.vault /mnt/a         2026-04-19 12:34:56
```

这个列表来自状态文件，不是实时扫描系统挂载表。如果你之前异常退出，状态记录和真实挂载状态可能出现短暂不一致。

## 7. 推荐工作流

### 7.1 日常使用

```bash
./yukvault open --vault ./secrets.vault --mount ./test-mount
```

在 `./test-mount` 内处理文件后：

```bash
./yukvault close --vault ./secrets.vault --mount ./test-mount
```

### 7.2 首次创建并启用恢复能力

```bash
./yukvault init \
  --vault ./secrets.vault \
  --size 256M \
  --fs ext4 \
  --recover
```

创建成功后：

1. 保存好 24 词恢复助记词
2. 执行一次 `open`
3. 写入一个测试文件
4. 执行 `close`
5. 再用 `recover` 演练一遍

### 7.3 更换 YubiKey 或定期轮换

```bash
./yukvault rotate-key --vault ./secrets.vault
```

完成后：

1. 重新 `open`
2. 检查老文件仍然可见
3. 如果有新恢复助记词，更新你的离线备份

## 8. 状态文件与临时文件

### 8.1 挂载状态文件

Linux / Windows 默认会把挂载状态写到：

```text
~/.config/yukvault/mounts.json
```

这个文件记录：

- vault 路径
- 临时镜像路径
- 挂载点
- 打开时间

注意：

- 这个状态文件用于定位当前挂载对应的临时镜像和挂载点。
- 不要手工编辑它。
- 如果程序异常退出，应优先核对真实挂载状态，再做清理。

### 8.2 临时镜像

打开 vault 时，程序会把明文镜像写到系统临时目录下的一个临时 `.img` 文件，再把它挂载出去。

这意味着：

- 在 vault 处于打开状态时，系统上确实存在一份明文镜像文件
- 正常 `close` 成功后，这个临时镜像会被擦除删除
- 如果程序异常退出，可能会留下状态文件或已挂载镜像，需要手工清理
- 这是当前架构的核心边界，因此不适合把“打开状态下本机完全不可信”的场景当成受保护目标

这是当前实现的设计事实，不是异常现象。

## 9. 验收与自检

### 9.1 运行自动验收脚本

仓库已经提供 Linux 端到端验收脚本：

```bash
make acceptance
```

它会执行：

- `go test ./...`
- `go build`
- `init`
- `open`
- 在挂载点写入测试文件
- `close`
- 再次 `open`
- 校验文件仍然存在
- 再次 `close`

### 9.2 验证恢复链路

```bash
WITH_RECOVERY=1 RECOVERY_KEY='你的24词或64位hex' make acceptance
```

### 9.3 手工检查权限

```bash
ls -l ./secrets.vault ./secrets.vault.credid
```

建议看到：

```text
-rw-------  ... secrets.vault
-rw-------  ... secrets.vault.credid
```

## 10. 常见问题

### 10.1 `no YubiKey detected`

说明程序没有找到可用的 FIDO2 设备。

检查：

```bash
ls -l /dev/hidraw*
```

如果你知道设备路径，也可以显式传：

```bash
./yukvault --device /dev/hidraw2 open --vault ./secrets.vault --mount ./test-mount
```

### 10.2 `invalid device selection`

说明探测到多个设备后，交互选择输入不合法。重新运行并输入有效编号即可。

### 10.3 `credential id hash mismatch`

通常表示：

- `.credid` 文件和 `.vault` 不是同一对
- `.credid` 被替换或损坏
- 你拿错了 sidecar 文件

处理方式：

- 确认 `.vault` 和 `.credid` 来自同一套备份
- 不要手工修改 `.credid`

### 10.4 `vault does not contain a recovery key`

说明这个 vault 创建时没有加 `--recover`，因此不能走 `recover` 命令。

### 10.5 挂载点 `Device or resource busy`

通常表示旧挂载还没卸掉。

先检查：

```bash
mountpoint -q ./test-mount && echo mounted
```

如果还挂着：

```bash
fusermount -u ./test-mount
```

如果不行，再尝试：

```bash
sudo umount ./test-mount
```

### 10.6 `fuse2fs` 不可用

Linux 下如果没有 `fuse2fs`，程序会尝试回退到 `sudo mount -o loop`。这时：

- 打开和关闭过程中可能需要 sudo
- 某些环境下挂载权限策略会更严格

安装 `e2fsprogs` 后再试：

```bash
sudo apt install -y e2fsprogs
```

### 10.7 `PINs do not match`

只会出现在 `init`，重新执行并确保两次输入一致。

## 11. 安全建议

- 把 `.vault` 和 `.credid` 一起备份，但不要和恢复助记词放在同一位置。
- 恢复助记词应离线保存，不要放进密码管理器之外的明文同步系统。
- 每次使用完都执行 `close`，不要长期让 vault 处于挂载状态。
- 不要把挂载点放到公共共享目录。
- `rotate-key` 成功后，旧恢复助记词如果已失效，应明确标记废弃。
- 对高敏感数据，建议先在单独机器上做真实恢复演练，再进入正式使用。

## 12. 当前实现边界

在使用前，你应该知道这些边界：

- 当前代码不再提供 fake FIDO2 开发绕过模式，必须使用真实设备。
- Linux 是当前最推荐的使用平台。
- 打开 vault 时会在本地临时目录产生明文镜像，这是当前架构的一部分。
- `recover` 可以打开 vault，但当前 `close` 仍然走正常 YubiKey 路径，因此恢复链路更适合作为应急打开能力，而不是长期替代 YubiKey 的工作模式。

## 13. 一套最小可用命令

创建：

```bash
./yukvault init --vault ./secrets.vault --size 256M --fs ext4 --recover
```

打开：

```bash
mkdir -p ./test-mount
./yukvault open --vault ./secrets.vault --mount ./test-mount
```

关闭：

```bash
./yukvault close --vault ./secrets.vault --mount ./test-mount
```

恢复打开：

```bash
./yukvault recover --vault ./secrets.vault --mount ./test-mount
```

查看挂载：

```bash
./yukvault list
```

轮换：

```bash
./yukvault rotate-key --vault ./secrets.vault
```
