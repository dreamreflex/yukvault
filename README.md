# yukvault

`yukvault` 是一个基于 YubiKey FIDO2 的加密文件库命令行工具。

它会把整个文件系统镜像加密成单个 `.vault` 文件。打开时需要 YubiKey；可选地生成一组恢复助记词，用于在没有 YubiKey 时恢复。

## 核心能力

- 使用 YubiKey FIDO2 `hmac-secret` 派生 vault 密钥
- 把整个镜像加密到一个 `.vault` 容器文件
- 支持恢复助记词
- 提供 `init`、`open`、`close`、`recover`、`rotate-key`、`list` 命令

## 前提条件

- Go `1.22+`
- YubiKey，且支持 FIDO2
- Linux 上安装 `libfido2` 和 `e2fsprogs`

Ubuntu / Debian:

```bash
sudo apt update
sudo apt install -y libfido2-dev libfido2-1 pkg-config e2fsprogs
```

## 构建

```bash
make build
```

也可以直接执行：

```bash
CGO_ENABLED=1 go build -o yukvault ./main.go
```

## 快速开始

创建一个新 vault：

```bash
./yukvault --vault ./secrets.vault init --size 256M --fs ext4
```

创建并生成恢复助记词：

```bash
./yukvault --vault ./secrets.vault init --size 256M --recover
```

打开并挂载：

```bash
./yukvault --vault ./secrets.vault open --mount ./mnt
```

关闭并保存：

```bash
./yukvault --vault ./secrets.vault close --mount ./mnt
```

使用恢复助记词打开：

```bash
./yukvault --vault ./secrets.vault recover --mount ./mnt
```

查看当前已打开的 vault：

```bash
./yukvault list
```

轮换 YubiKey 凭据和 vault 密钥：

```bash
./yukvault --vault ./secrets.vault rotate-key
```

## 常用参数

- `--vault`: `.vault` 文件路径
- `--device`: 指定 FIDO2 设备路径；不传时自动选择
- `init --size`: vault 大小，默认 `256M`
- `init --fs`: 文件系统类型，默认 `ext4`
- `init --recover`: 生成恢复助记词
- `open --mount`: 挂载目录
- `recover --key`: 直接传入恢复助记词或十六进制恢复密钥

## 安全说明

- 打开 vault 时，程序会在本地临时目录创建明文镜像并挂载
- 正常执行 `close` 后会重新加密并删除临时镜像
- 挂载状态保存在本地状态文件中，不应手动修改

## 更多文档

- 使用说明：[GUIDE.md](./GUIDE.md)
- 验收测试：[ACCEPTANCE_TEST.md](./ACCEPTANCE_TEST.md)
