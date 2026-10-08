//
//  KeychainForensics.h
//  钥匙串取证接口（移植自 FomoPeek / libapptracecore.framework 的 keychain_core.cpp）
//
//  用途：在具备 root / 已越狱（可访问 AppleKeyStore 内核服务）的设备上，
//        复制并解密 /private/var/Keychains/keychain-2.db，输出可读条目。
//        仅限授权的安全研究 / 取证场景。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface KeychainForensics : NSObject

/// 复制 /private/var/Keychains/keychain-2.db 并解密全部条目。
/// @return 按表（genp/inet/cert/keys）分组的条目数组；失败返回 nil 并填充 error。
+ (nullable NSArray<NSDictionary<NSString *, id> *> *)dumpKeychainWithError:(NSError **)error;

/// 解密钥匙串并将结果导出为 JSON 文件到指定目录，返回写入的文件路径。
+ (nullable NSString *)exportKeychainToDirectory:(NSString *)directory error:(NSError **)error;

/// 沙盒内日志文件路径（Documents/keychain-forensics.log，可经「文件」App 查看）。
+ (NSString *)logFilePath;

@end

NS_ASSUME_NONNULL_END
