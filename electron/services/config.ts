import { join } from 'path'
import { app, safeStorage } from 'electron'
import Store from 'electron-store'

// safeStorage 加密后的前缀标记，用于区分明文和密文
const SAFE_PREFIX = 'safe:'

interface ConfigSchema {
  // 数据库相关
  dbPath: string        // 数据库根目录 (xwechat_files)
  decryptKey: string    // 解密密钥
  myWxid: string        // 当前用户 wxid
  onboardingDone: boolean
  imageXorKey: number
  imageAesKey: string
  wxidConfigs: Record<string, { decryptKey?: string; imageXorKey?: number; imageAesKey?: string; updatedAt?: number }>

  // 缓存相关
  cachePath: string

  lastOpenedDb: string
  lastSession: string

  // 界面相关
  theme: 'light' | 'dark' | 'system'
  themeId: string
  language: string
  logEnabled: boolean
  llmModelPath: string
  whisperModelName: string
  whisperModelDir: string
  whisperDownloadSource: string
  autoTranscribeVoice: boolean
  transcribeLanguages: string[]
  exportDefaultConcurrency: number
  analyticsExcludedUsernames: string[]

  // 安全相关（通过 safeStorage 加密存储，JSON 中为密文）
  authEnabled: boolean
  authPassword: string // SHA-256 hash
  authUseHello: boolean

  // 更新相关
  ignoredUpdateVersion: string

  // 通知
  notificationEnabled: boolean
  notificationPosition: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left'
  notificationFilterMode: 'all' | 'whitelist' | 'blacklist'
  notificationFilterList: string[]
  wordCloudExcludeWords: string[]
}

// 需要 safeStorage 加密的字段集合
const ENCRYPTED_STRING_KEYS: Set<string> = new Set(['decryptKey', 'imageAesKey', 'authPassword'])
const ENCRYPTED_BOOL_KEYS: Set<string> = new Set(['authEnabled', 'authUseHello'])
const ENCRYPTED_NUMBER_KEYS: Set<string> = new Set(['imageXorKey'])

export class ConfigService {
  private static instance: ConfigService
  private store!: Store<ConfigSchema>

  static getInstance(): ConfigService {
    if (!ConfigService.instance) {
      ConfigService.instance = new ConfigService()
    }
    return ConfigService.instance
  }

  constructor() {
    if (ConfigService.instance) {
      return ConfigService.instance
    }
    ConfigService.instance = this
    this.store = new Store<ConfigSchema>({
      name: 'WeFlow-config',
      defaults: {
        dbPath: '',
        decryptKey: '',
        myWxid: '',
        onboardingDone: false,
        imageXorKey: 0,
        imageAesKey: '',
        wxidConfigs: {},
        cachePath: '',

        lastOpenedDb: '',
        lastSession: '',
        theme: 'system',
        themeId: 'cloud-dancer',
        language: 'zh-CN',
        logEnabled: false,
        llmModelPath: '',
        whisperModelName: 'base',
        whisperModelDir: '',
        whisperDownloadSource: 'tsinghua',
        autoTranscribeVoice: false,
        transcribeLanguages: ['zh'],
        exportDefaultConcurrency: 2,
        analyticsExcludedUsernames: [],

        authEnabled: false,
        authPassword: '',
        authUseHello: false,

        ignoredUpdateVersion: '',
        notificationEnabled: true,
        notificationPosition: 'top-right',
        notificationFilterMode: 'all',
        notificationFilterList: [],
        wordCloudExcludeWords: []
      }
    })

    // 首次启动时迁移旧版明文安全字段
    this.migrateAuthFields()
  }

  get<K extends keyof ConfigSchema>(key: K): ConfigSchema[K] {
    const raw = this.store.get(key)

    // 布尔型加密字段：存储为加密字符串，读取时解密还原为布尔值
    if (ENCRYPTED_BOOL_KEYS.has(key)) {
      const str = typeof raw === 'string' ? raw : ''
      if (!str || !str.startsWith(SAFE_PREFIX)) return raw
      const decrypted = this.safeDecrypt(str)
      return (decrypted === 'true') as ConfigSchema[K]
    }

    // 数字型加密字段：存储为加密字符串，读取时解密还原为数字
    if (ENCRYPTED_NUMBER_KEYS.has(key)) {
      const str = typeof raw === 'string' ? raw : ''
      if (!str || !str.startsWith(SAFE_PREFIX)) return raw
      const decrypted = this.safeDecrypt(str)
      const num = Number(decrypted)
      return (Number.isFinite(num) ? num : 0) as ConfigSchema[K]
    }

    // 字符串型加密字段
    if (ENCRYPTED_STRING_KEYS.has(key) && typeof raw === 'string') {
      return this.safeDecrypt(raw) as ConfigSchema[K]
    }

    // wxidConfigs 中嵌套的敏感字段
    if (key === 'wxidConfigs' && raw && typeof raw === 'object') {
      return this.decryptWxidConfigs(raw as any) as ConfigSchema[K]
    }

    return raw
  }

  set<K extends keyof ConfigSchema>(key: K, value: ConfigSchema[K]): void {
    let toStore = value

    // 布尔型加密字段：序列化为字符串后加密
    if (ENCRYPTED_BOOL_KEYS.has(key)) {
      toStore = this.safeEncrypt(String(value)) as ConfigSchema[K]
    }
    // 数字型加密字段：序列化为字符串后加密
    else if (ENCRYPTED_NUMBER_KEYS.has(key)) {
      toStore = this.safeEncrypt(String(value)) as ConfigSchema[K]
    }
    // 字符串型加密字段
    else if (ENCRYPTED_STRING_KEYS.has(key) && typeof value === 'string') {
      toStore = this.safeEncrypt(value) as ConfigSchema[K]
    }
    // wxidConfigs 中嵌套的敏感字段
    else if (key === 'wxidConfigs' && value && typeof value === 'object') {
      toStore = this.encryptWxidConfigs(value as any) as ConfigSchema[K]
    }

    this.store.set(key, toStore)
  }

  // === safeStorage 加解密 ===

  private safeEncrypt(plaintext: string): string {
    if (!plaintext) return ''
    if (plaintext.startsWith(SAFE_PREFIX)) return plaintext
    if (!safeStorage.isEncryptionAvailable()) return plaintext
    const encrypted = safeStorage.encryptString(plaintext)
    return SAFE_PREFIX + encrypted.toString('base64')
  }

  private safeDecrypt(stored: string): string {
    if (!stored) return ''
    if (!stored.startsWith(SAFE_PREFIX)) {
      return stored
    }
    if (!safeStorage.isEncryptionAvailable()) return ''
    try {
      const buf = Buffer.from(stored.slice(SAFE_PREFIX.length), 'base64')
      return safeStorage.decryptString(buf)
    } catch {
      return ''
    }
  }

  // === 旧版本迁移 ===

  // 将旧版明文 auth 字段迁移为 safeStorage 加密格式
  private migrateAuthFields(): void {
    if (!safeStorage.isEncryptionAvailable()) return

    // 迁移字符串型字段（decryptKey, imageAesKey, authPassword）
    for (const key of ENCRYPTED_STRING_KEYS) {
      const raw = this.store.get(key as keyof ConfigSchema)
      if (typeof raw === 'string' && raw && !raw.startsWith(SAFE_PREFIX)) {
        this.store.set(key as any, this.safeEncrypt(raw))
      }
    }

    // 迁移布尔型字段（authEnabled, authUseHello）
    for (const key of ENCRYPTED_BOOL_KEYS) {
      const raw = this.store.get(key as keyof ConfigSchema)
      // 如果是原始布尔值（未加密），转为加密字符串
      if (typeof raw === 'boolean') {
        this.store.set(key as any, this.safeEncrypt(String(raw)))
      }
    }

    // 迁移数字型字段（imageXorKey）
    for (const key of ENCRYPTED_NUMBER_KEYS) {
      const raw = this.store.get(key as keyof ConfigSchema)
      // 如果是原始数字值（未加密），转为加密字符串
      if (typeof raw === 'number') {
        this.store.set(key as any, this.safeEncrypt(String(raw)))
      }
    }

    // 迁移 wxidConfigs 中的嵌套敏感字段
    const wxidConfigs = this.store.get('wxidConfigs')
    if (wxidConfigs && typeof wxidConfigs === 'object') {
      let needsUpdate = false
      const updated = { ...wxidConfigs }
      for (const [wxid, cfg] of Object.entries(updated)) {
        if (cfg.decryptKey && !cfg.decryptKey.startsWith(SAFE_PREFIX)) {
          updated[wxid] = { ...cfg, decryptKey: this.safeEncrypt(cfg.decryptKey) }
          needsUpdate = true
        }
        if (cfg.imageAesKey && !cfg.imageAesKey.startsWith(SAFE_PREFIX)) {
          updated[wxid] = { ...updated[wxid], imageAesKey: this.safeEncrypt(cfg.imageAesKey) }
          needsUpdate = true
        }
        if (cfg.imageXorKey !== undefined && typeof cfg.imageXorKey === 'number') {
          updated[wxid] = { ...updated[wxid], imageXorKey: this.safeEncrypt(String(cfg.imageXorKey)) as any }
          needsUpdate = true
        }
      }
      if (needsUpdate) {
        this.store.set('wxidConfigs', updated)
      }
    }

    // 清理旧版 authSignature 字段（不再需要）
    this.store.delete('authSignature' as any)
  }

  // === wxidConfigs 加解密 ===

  private encryptWxidConfigs(configs: ConfigSchema['wxidConfigs']): ConfigSchema['wxidConfigs'] {
    const result: ConfigSchema['wxidConfigs'] = {}
    for (const [wxid, cfg] of Object.entries(configs)) {
      result[wxid] = { ...cfg }
      if (cfg.decryptKey) result[wxid].decryptKey = this.safeEncrypt(cfg.decryptKey)
      if (cfg.imageAesKey) result[wxid].imageAesKey = this.safeEncrypt(cfg.imageAesKey)
      if (cfg.imageXorKey !== undefined) {
        (result[wxid] as any).imageXorKey = this.safeEncrypt(String(cfg.imageXorKey))
      }
    }
    return result
  }

  private decryptWxidConfigs(configs: ConfigSchema['wxidConfigs']): ConfigSchema['wxidConfigs'] {
    const result: ConfigSchema['wxidConfigs'] = {}
    for (const [wxid, cfg] of Object.entries(configs)) {
      result[wxid] = { ...cfg }
      if (cfg.decryptKey) result[wxid].decryptKey = this.safeDecrypt(cfg.decryptKey)
      if (cfg.imageAesKey) result[wxid].imageAesKey = this.safeDecrypt(cfg.imageAesKey)
      if (cfg.imageXorKey !== undefined) {
        const raw = cfg.imageXorKey as any
        if (typeof raw === 'string' && raw.startsWith(SAFE_PREFIX)) {
          const decrypted = this.safeDecrypt(raw)
          const num = Number(decrypted)
          result[wxid].imageXorKey = Number.isFinite(num) ? num : 0
        }
      }
    }
    return result
  }

  // === 应用锁验证 ===

  // 验证应用锁状态，防篡改：
  // - 所有 auth 字段都是 safeStorage 密文，删除/修改密文 → 解密失败
  // - 解密失败时，检查 authPassword 密文是否曾经存在（非空非默认值）
  //   如果存在则说明被篡改，强制锁定
  verifyAuthEnabled(): boolean {
    // 用 as any 绕过泛型推断，因为加密后实际存储的是字符串而非 boolean
    const rawEnabled: any = this.store.get('authEnabled')
    const rawPassword: any = this.store.get('authPassword')

    // 情况1：字段是加密密文，正常解密
    if (typeof rawEnabled === 'string' && rawEnabled.startsWith(SAFE_PREFIX)) {
      const enabled = this.safeDecrypt(rawEnabled) === 'true'
      const password = typeof rawPassword === 'string' ? this.safeDecrypt(rawPassword) : ''

      if (!enabled && !password) return false
      return enabled
    }

    // 情况2：字段是原始布尔值（旧版本，尚未迁移）
    if (typeof rawEnabled === 'boolean') {
      return rawEnabled
    }

    // 情况3：字段被删除（electron-store 返回默认值 false）或被篡改为无法解密的值
    // 检查 authPassword 是否有密文残留（说明之前设置过密码）
    if (typeof rawPassword === 'string' && rawPassword.startsWith(SAFE_PREFIX)) {
      // 密码密文还在，说明之前启用过应用锁，字段被篡改了 → 强制锁定
      return true
    }

    return false
  }

  // === 其他 ===

  getCacheBasePath(): string {
    const configured = this.get('cachePath')
    if (configured && configured.trim().length > 0) {
      return configured
    }
    return join(app.getPath('documents'), 'WeFlow')
  }

  getAll(): ConfigSchema {
    return this.store.store
  }

  clear(): void {
    this.store.clear()
  }
}
