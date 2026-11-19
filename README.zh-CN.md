# ed25519

**支持：**[问题与反馈](https://github.com/turlamai/ed25519/issues) · [当前交付策略](https://github.com/turlamai/turlamai.github.io/blob/master/PORTFOLIO.zh-CN.md)

纯 Racket 的 Ed25519 签名——无 FFI、无原生库、无外部工具。

[English](README.md)

`ed25519` 严格按 [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) 用纯
Racket 大数运算实现 Ed25519。签名与 OpenSSL 3、libsodium 及所有其他
Ed25519 实现逐字节互操作。

## 安装

```sh
raco pkg install ed25519
```

## 示例

```racket
(require ed25519)

(define kp (generate-keypair))
(define message #"update manifest 2026-11-04")

(define sig (sign message (keypair-secret kp)))
(verify message sig (keypair-public kp)) ; => #t
(verify #"tampered" sig (keypair-public kp)) ; => #f
```

已有的 32 字节 seed 同样可用：

```racket
(secret->public seed)          ; 推导公钥
(sign message seed)            ; 用现有 seed 签名
```

## 定位

本包是 Ed25519 provider 链的**最后兜底**，不是原生密码学的替代品：

1. OpenSSL 3（经 `crypto-lib`）——凡是可用一律优先；
2. libsodium——有打包处优先；
3. Nettle——其 Ed25519 后端可用处优先；
4. `ed25519`（本包）——保证*任何* Racket 环境都能签名验签，不依赖任何原生库。

公开数据的验签（更新 manifest、license 凭证、签名证词）在任何环境用本包
都安全。持有私钥的生产 *issuer* 应优先原生 provider；只能用本包时见下方
安全说明。

## API

| 绑定 | 合同 |
|---|---|
| `generate-keypair` | `-> ed25519-keypair?` |
| `keypair-public kp` | `-> 32 字节` |
| `keypair-secret kp` | `-> 32 字节`（RFC 8032 seed） |
| `secret->public secret` | `32 字节 -> 32 字节` |
| `sign message secret` | `bytes? 32 字节 -> 64 字节`，确定性 |
| `verify message signature public` | `bytes? 64 字节 32 字节 -> boolean?` |
| `public-key-length` / `secret-key-length` / `signature-length` | `32` / `32` / `64` |

`verify` 对不可信输入绝不抛异常：篡改的消息或签名、错 key、非规范编码
（`y >= p`、非规范符号位、曲线外点）、非规范标量（`S >= L`）、小阶公钥，
一律返回 `#f`。参数类型或长度错误抛 `exn:fail:contract`。验签是
cofactorless 的，与 OpenSSL 3 对齐。

## 安全

- **非常量时间。** Racket 大数运算存在时序泄露。攻击者能测量高价值密钥
  签名耗时的场景不要用本包。
- **未经第三方审计。** 实现遵循 RFC 8032 与公有领域的 ref10 解压技术，
  通过全部 RFC 8032 §7.1 测试向量，并与 OpenSSL 3 做了逐字节交叉验证——
  但没有经过独立的密码学审计。
- **只做签名。** Ed25519 不提供加密，也不提供密钥协商。
- `generate-keypair` 使用操作系统熵源（`racket/random` 的
  `crypto-random-bytes`），不涉及任何伪随机数播种。

## 性能

实测于 Racket 9.3 CS（Racket CS 大数，未做 JIT 调优），Apple Silicon：

| 消息 | 签名 | 验签 |
|---|---|---|
| 空 | 约 3.9 ms | 约 5.4 ms |
| 32 B | 约 3.6 ms | 约 4.9 ms |
| 1 KB | 约 5.1 ms | 约 6.5 ms |
| 4 KB | 约 9.3 ms | 约 7.8 ms |

正确性优先，速度其次：比原生 provider 慢得多，对 license 与更新验签场景
足够。发布门禁的 CI 预算（sign < 500 ms、verify < 250 ms）以大裕量满足。

## 兼容性

- RFC 8032 §7.1 全部测试向量逐字节通过（公钥、签名、验签）。
- 与 OpenSSL 3（`pkeyutl -rawin`）做了 1000+ 组随机交叉验证：
  Racket 签的消息 OpenSSL 验通过，OpenSSL 签的消息 Racket 验通过，
  双方签名逐字节相同。
- 负例矩阵：消息每一位翻转、签名全部 512 位逐位翻转、`S + L` 可塑性、
  非规范编码、小阶公钥，全部拒绝。

## 许可

Apache-2.0。算法来源见 [LICENSE](LICENSE) 与
[NOTICE](NOTICE)（RFC 8032；ref10 解压技术，公有领域）。
