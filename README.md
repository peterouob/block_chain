# 從零實現一條區塊鏈

本文件將帶你從概念到實作，逐步理解並建構一條 Move-based 區塊鏈的基礎設施。架構參考 Sui / Aptos 的設計，以 Go 語言實作。

---

## 目錄

1. [整體架構概覽](#1-整體架構概覽)
2. [第一層：密鑰與帳戶 (Account & Key)](#2-第一層密鑰與帳戶)
3. [第二層：簽名系統 (Signature)](#3-第二層簽名系統)
4. [第三層：意圖訊息 (Intent)](#4-第三層意圖訊息)
5. [第四層：物件模型 (Object)](#5-第四層物件模型)
6. [第五層：物件儲存 (ObjectStore)](#6-第五層物件儲存)
7. [第六層：gRPC 服務節點 (Node)](#7-第六層grpc-服務節點)
8. [資料流：一筆交易的完整生命週期](#8-資料流一筆交易的完整生命週期)
9. [快速開始](#9-快速開始)
10. [下一步：尚未實作的部分](#10-下一步尚未實作的部分)

---

## 1. 整體架構概覽

```
┌─────────────────────────────────────────────────────┐
│                   cmd/server                         │
│            gRPC Server (:50051)                      │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│               node/service                           │
│          AccountService (gRPC Handler)               │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│                    chain/                            │
│                                                      │
│  Account ──────► Sign() ──────► Signature.Verify()  │
│     │                                ▲               │
│     │                                │               │
│     ▼                         IntentMessage.Hash()   │
│  Address                             │               │
│                               Intent (scope)         │
│                                                      │
│  Object ──────────────────► ObjectStore (in-memory) │
│  (MoveObject / MovePackage)                          │
└─────────────────────────────────────────────────────┘
```

區塊鏈的核心問題只有三個：
- **誰**在操作？ → Account / Signature
- **操作什麼**？ → Object / ObjectStore
- **如何防止偽造**？ → Intent / Signature

---

## 2. 第一層：密鑰與帳戶

### 2.1 為什麼用 Secp256k1？

Secp256k1 是比特幣、以太坊、Sui 都採用的橢圓曲線。它的特性：
- 256-bit 私鑰，安全性極高
- 公鑰可壓縮成 33 bytes（省空間）
- 有成熟的 Go library：`github.com/dustinxie/ecc`

### 2.2 公鑰的表示方式

橢圓曲線上的點由 (X, Y) 兩個座標組成，未壓縮格式：

```
[0x04 | X(32 bytes) | Y(32 bytes)] = 65 bytes
```

由於橢圓曲線的對稱性，已知 X 可以還原 Y（只需知道 Y 的奇偶），所以可壓縮：

```go
// account_key.go
func (p *p256k1PublicKey) Compress() []byte {
    comp := make([]byte, 33)
    y := p.Y()
    comp[0] = 0x02 + (y[len(y)-1] & 0x01) // 0x02 = Y 為偶數, 0x03 = Y 為奇數
    copy(comp[1:], p.X())
    return comp
}
```

還原壓縮公鑰（解壓縮）需用 Secp256k1 方程式 `y² = x³ + 7 (mod P)` 求解：

```go
// account_key.go
func DeCompressPubKey(pub []byte) (*big.Int, *big.Int, error) {
    x := new(big.Int).SetBytes(pub[1:])
    // 計算 y^2 = x^3 + 7 mod P
    x3 := new(big.Int).Exp(x, big.NewInt(3), P)
    ySQ := new(big.Int).Add(x3, big.NewInt(7))
    // 用模數開根號求 y（P ≡ 3 mod 4 的特性讓這步很高效）
    ex := new(big.Int).Add(P, big.NewInt(1))
    ex.Div(ex, big.NewInt(4))
    y := new(big.Int).Exp(ySQMod, ex, P)
    // 根據 prefix 決定取哪個根
    if (y.Bit(0) == 1) != (pub[0] == 0x03) {
        y.Sub(P, y)
    }
    ...
}
```

### 2.3 地址生成

地址 = SHA3-256(JSON(公鑰))，取前 32 bytes，以 hex 字串表示：

```go
// account.go
func NewAddress(pub *ecdsa.PublicKey) Address {
    jpub, _ := json.Marshal(newP256k1PublicKey(pub))
    hash := make([]byte, 64)
    sha3.ShakeSum256(hash, jpub)
    return Address(hex.EncodeToString(hash[:32]))
}
```

> **為什麼 hash 公鑰而不是直接用公鑰當地址？**
> 公鑰是 33~65 bytes，而 hash 後固定長度且不可逆——即使未來量子電腦破解 ECDSA，攻擊者也無法從地址推算出公鑰。

### 2.4 私鑰加密存儲

私鑰不能明文存在磁盤，採用 `Argon2 + AES-GCM` 兩層保護：

```
磁盤存儲格式：
[salt(32B) | nonce(12B) | AES-GCM 密文]

解密步驟：
1. 讀取 salt
2. key = Argon2(password, salt)  ← 慢雜湊，防暴力破解
3. 用 key 初始化 AES-256
4. AES-GCM.Open(nonce, 密文) → 私鑰 JSON
```

```go
// account.go
func (a *Account) encPassword(msg, pass []byte) ([]byte, error) {
    salt := make([]byte, encLen)
    rand.Read(salt)

    key := argon2.IDKey(pass, salt, 1, 256, 1, encLen) // Argon2id
    blk, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(blk)

    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)

    ciph := gcm.Seal(nonce, nonce, msg, nil)
    return append(salt, ciph...), nil
}
```

---

## 3. 第二層：簽名系統

### 3.1 簽名格式

本系統定義了一個統一的 97-byte 簽名格式，方便未來支援多種簽名演算法：

```
signatureByte[97] = [flag:1B | r(32B) + s(32B) | compressed_pubkey(33B)]
                     └─ 0x01 = Secp256k1
```

```go
// account.go
func (a *Account) Sign(data []byte) ([]byte, error) {
    r, s, _ := ecdsa.Sign(rand.Reader, a.prvKey, data)

    signBytes := make([]byte, 64)
    copy(signBytes[32-len(r.Bytes()):], r.Bytes()) // 右對齊填充
    copy(signBytes[64-len(s.Bytes()):], s.Bytes())

    signatureByte := make([]byte, 98)
    signatureByte[0] = 0x01                         // Secp256k1 flag
    copy(signatureByte[1:65], signBytes)             // r || s
    copy(signatureByte[65:], pub.Compress())         // 壓縮公鑰
    return signatureByte, nil
}
```

### 3.2 驗簽流程

```go
// singature.go
func (s *Signature) Verify(intentMsg []byte) (bool, error) {
    // 1. 從壓縮公鑰還原 (x, y)
    x, y, _ := DeCompressPubKey(s.PubKey)

    // 2. 重建 ecdsa.PublicKey
    pubKey := &ecdsa.PublicKey{Curve: ecc.P256k1(), X: x, Y: y}

    // 3. 將 sig bytes 拆成 r, s
    rV := new(big.Int).SetBytes(s.SigBytes[:32])
    sV := new(big.Int).SetBytes(s.SigBytes[32:])

    // 4. 驗證
    return ecdsa.Verify(pubKey, intentMsg, rV, sV), nil
}
```

---

## 4. 第三層：意圖訊息

### 4.1 為什麼需要 Intent？

如果直接對交易資料簽名，攻擊者可以把同一個簽名重放到不同情境（例如把一筆交易的簽名偽裝成個人訊息的簽名）。Intent 在資料前加上「用途標頭」，防止跨情境重放攻擊。

```
IntentMessage 序列化：
[Scope(1B) | Version(1B) | AppId(1B) | BCS(交易資料)]
```

| 欄位 | 說明 |
|------|------|
| `Scope` | 用途：`0x00` = 交易資料，`0x03` = 個人訊息 |
| `Version` | 協議版本，未來升級時用於區分 |
| `AppId` | 哪個應用或鏈發出的 |

### 4.2 雜湊計算

對 IntentMessage 進行 Blake2B-256 哈希，結果才是真正要簽名的資料：

```go
// intent.go
func (i *IntentMessage[T]) Hash() ([]byte, error) {
    valueByte, _ := i.Value.BCSByte()   // BCS 序列化交易資料
    intentMsg := i.Intent.ToBytes()      // [scope, version, appId]

    h, _ := blake2b.New256(nil)
    h.Write(intentMsg[:])
    h.Write(valueByte)
    return h.Sum(nil), nil              // 這才是 Account.Sign() 的輸入
}
```

### 4.3 BCS 序列化

BCS（Binary Canonical Serialization）來自 Diem/Libra，是確定性的二進制序列化格式：
- 相同資料永遠序列化出相同 bytes（這對哈希至關重要）
- 使用 `github.com/fardream/go-bcs` 實作

---

## 5. 第四層：物件模型

### 5.1 設計理念

Move-based 區塊鏈的核心概念：**區塊鏈狀態由一系列 Object 組成**，而不是帳戶餘額表。每個 Object 都有唯一 ID、版本號，以及一個擁有者。

```go
// object.go
type Object struct {
    data                ObjectData  // MoveObject 或 MovePackage
    owner               Owner       // 誰擁有這個 Object
    previousTransaction Digest      // 上一筆修改此 Object 的交易哈希
    storageRebate       uint64      // 刪除此 Object 時退還的 gas
}
```

### 5.2 ObjectData：兩種類型

```
ObjectData
├── MoveObject   ── 智能合約實例（有狀態的 token、NFT 等）
│   ├── ObjectId   [32]byte
│   ├── Version    uint64
│   ├── Type       string     （例如 "0x2::coin::Coin<SUI>"）
│   ├── Contents   []byte     （BCS 序列化的合約狀態）
│   └── HasPublicTransfer bool
│
└── MovePackage  ── 已發佈的智能合約模組庫
    ├── ObjectId   [32]byte
    ├── Version    uint64
    └── Module     map[string][]byte  （模組名 → 位元組碼）
```

### 5.3 四種擁有權

```
Owner
├── AddressOwner  ── 由某個地址控制（最常見，如個人資產）
├── ObjectOwner   ── 由另一個 Object 包含（動態欄位、父子關係）
├── SharedOwner   ── 所有人可讀寫（如 DEX 的流動池）
└── ImmutableOwner── 不可修改（如已發佈的合約程式碼）
```

### 5.4 序列化格式

物件序列化用於計算 Digest（哈希）以形成鏈上的不可篡改引用：

```
Object 二進制格式（Little-Endian）：
[ObjectData | Owner | previousTxDigest(32B) | storageRebate(8B)]

MoveObject：
[0x0A | ObjectId(32B) | Version(8B) | typeLen(4B) | type | contentsLen(4B) | contents | hasPublicTransfer(1B)]

MovePackage：
[0x0B | ObjectId(32B) | Version(8B) | moduleCount(4B) | (nameLen+name+codeLen+code)×N]
注意：MovePackage 的模組按 key 排序後序列化，確保確定性
```

### 5.5 ObjectRef：輕量引用

任何時候需要「指向」一個 Object，用 ObjectRef：

```go
type ObjectRef struct {
    ObjectId ObjectId  // 是什麼
    Version  uint64    // 哪個版本
    Digest   Digest    // 內容哈希（防篡改）
}
```

---

## 6. 第五層：物件儲存

### 6.1 介面設計

```go
// object_store.go
type ObjectStorer interface {
    Get(id ObjectId) (Object, error)
    Put(object Object) error
    Delete(id ObjectId) error
    GetByOwner(address Address) ([]Object, error)
    Exists(id ObjectId) bool
}
```

定義介面而非具體結構，讓未來可以替換成 RocksDB、PostgreSQL 等持久化後端。

### 6.2 反向索引

`InMemStore` 維護兩個資料結構：

```
objects:       map[ObjectId]Object              ← 主索引，by ID 查找
reverseObject: map[Address]map[ObjectId]struct{} ← 反向索引，by 地址查找
```

`Put()` 時同步維護兩個索引；`Delete()` 時同步清理（若某地址下已無 Object，連 key 一起刪除防止 map 洩漏）。

### 6.3 並發安全

使用 `sync.RWMutex`：
- 讀操作（`Get`, `GetByOwner`, `Exists`）持 `RLock`，多個讀可並行
- 寫操作（`Put`, `Delete`）持 `Lock`，獨佔

---

## 7. 第六層：gRPC 服務節點

### 7.1 Protobuf 定義

```protobuf
// node/rpc/proto/account.proto
service Account {
  rpc AccountCreate(AccountRequest) returns (AccountResponse);
  rpc AccountBalance(AccountBalanceReq) returns (AccountBalanceRes);
}
```

修改 proto 後，用以下命令重新生成 Go 代碼：

```bash
protoc --go_out=. --go-grpc_out=. ./node/rpc/proto/account.proto
```

### 7.2 服務層設計

`AccountService` 依賴注入 `BalanceChecker` 介面，與帳本的具體實作解耦：

```go
// node/service/account.go
type BalanceChecker interface {
    Balance(address string) (uint64, bool)
}

type AccountService struct {
    rpc.UnimplementedAccountServer
    BalanceChecker BalanceChecker  // 注入，方便測試與替換
    KeyStorePath   string
}
```

### 7.3 AccountCreate 流程

```
Client ──gRPC──► AccountCreate(pass)
                      │
                      ▼
              chain.NewAccount()         ← 生成 ECDSA 密鑰對
                      │
                      ▼
              acc.Write(keystore, pass)  ← 加密存到磁盤
                      │
                      ▼
              return Address             ← 回傳地址給 Client
```

### 7.4 啟動伺服器

```go
// cmd/server/main.go
s := grpc.NewServer()
rpc.RegisterAccountServer(s, &service.AccountService{
    KeyStorePath:   "keystore",
    BalanceChecker: &mockBalanceChecker{},
})
reflection.Register(s) // 啟用反射，grpcurl 可直接探索 API
s.Serve(lis)
```

---

## 8. 資料流：一筆交易的完整生命週期

以下是當用戶發起一筆「轉移 Object 所有權」的交易時，各層組件如何協作：

```
1. 建構交易資料
   txData := TransactionData{...}

2. 包裝成 IntentMessage（防重放）
   intent := IntentTransaction()  // Scope=0x00, Version=0, AppId=0
   msg := NewIntentMessage(*intent, txData)

3. 計算待簽名哈希
   hash := msg.Hash()
   // Blake2B-256([0x00, 0x00, 0x00] || BCS(txData))

4. 用帳戶私鑰簽名
   sig := account.Sign(hash)
   // [0x01 | r(32B) | s(32B) | compressedPubKey(33B)]

5. 驗簽（節點收到交易後執行）
   parsed := ParseSignature(sig)
   parsed.Verify(hash)            // ECDSA 驗證

6. 執行交易：修改 ObjectStore
   store.Put(newObject)           // 更新 Object 的 Owner
   store.Delete(oldObjectId)      // 刪除舊版本（版本號不同即為新物件）
```

---

## 9. 快速開始

**環境需求**
- Go 1.21+
- `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`（僅在修改 proto 時需要）

```bash
# 克隆並安裝依賴
git clone <repo>
cd block_chain_grpc
go mod download

# 執行所有測試
go test ./...

# 執行單一套件測試
go test ./chain/... -v

# 執行單一測試函數
go test ./chain/... -run TestObjectSerialize

# 啟動 gRPC 伺服器（監聽 :50051）
go run ./cmd/server/main.go

# 用 grpcurl 測試（需先安裝 grpcurl）
grpcurl -plaintext -d '{"pass":"mypassword"}' localhost:50051 Account/AccountCreate
```

---

## 10. 下一步：尚未實作的部分

目前 `chain/transcation.go` 是空檔，以下是完整區塊鏈還需要的核心模組：

| 模組 | 說明 |
|------|------|
| **Transaction** | 定義 TransactionData 結構（輸入 Object、指令列表、gas 設定） |
| **Execution Engine** | 執行 Move 字節碼，對 ObjectStore 進行讀寫 |
| **Mempool** | 收集待處理交易，按 gas price 排序 |
| **Consensus** | 共識協議（PoS / BFT / DAG），決定交易執行順序 |
| **Block / Checkpoint** | 將有序交易打包成區塊，計算全局狀態哈希 |
| **P2P Network** | 節點間廣播交易與區塊 |
| **持久化儲存** | 將 `InMemStore` 替換為 RocksDB 等持久化後端 |
| **Gas 計費** | 計算指令執行成本，防止 DoS 攻擊 |
