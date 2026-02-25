import { useState, useEffect, useRef } from 'react'
import * as configService from '../services/config'
import { ArrowRight, Fingerprint, Lock, ScanFace, ShieldCheck } from 'lucide-react'
import './LockScreen.scss'

interface LockScreenProps {
    onUnlock: () => void
    avatar?: string
    useHello?: boolean
}

async function sha256(message: string) {
    const msgBuffer = new TextEncoder().encode(message)
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    return hashHex
}

export default function LockScreen({ onUnlock, avatar, useHello = false }: LockScreenProps) {
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [isVerifying, setIsVerifying] = useState(false)
    const [isUnlocked, setIsUnlocked] = useState(false)
    const [showHello, setShowHello] = useState(false)
    const [helloAvailable, setHelloAvailable] = useState(false)

    // 用于取消 WebAuthn 请求
    const abortControllerRef = useRef<AbortController | null>(null)
    const inputRef = useRef<HTMLInputElement>(null)

    useEffect(() => {
        // 快速检查配置并启动
        quickStartHello()
        inputRef.current?.focus()

        return () => {
            // 组件卸载时取消请求
            abortControllerRef.current?.abort()
        }
    }, [])

    const handleUnlock = () => {
        setIsUnlocked(true)
        setTimeout(() => {
            onUnlock()
        }, 1500)
    }

    const quickStartHello = async () => {
        try {
            // 如果父组件已经告诉我们要用 Hello，直接开始，不等待 IPC
            let shouldUseHello = useHello

            // 为了稳健，如果 prop 没传（虽然现在都传了），再 check 一次 config
            if (!shouldUseHello) {
                shouldUseHello = await configService.getAuthUseHello()
            }

            if (shouldUseHello) {
                // 标记为可用，显示按钮
                setHelloAvailable(true)
                setShowHello(true)
                // 立即执行验证 (0延迟)
                verifyHello()
            }
        } catch (e) {
            console.error('Quick start hello failed', e)
        }
    }

    const verifyHello = async () => {
        if (isVerifying || isUnlocked) return

        setIsVerifying(true)
        setError('')

        try {
            const result = await window.electronAPI.auth.hello()

            if (result.success) {
                handleUnlock()
            } else {
                console.error('Hello verification failed:', result.error)
                setError(result.error || '验证失败')
            }
        } catch (e: any) {
            console.error('Hello verification error:', e)
            setError(`验证失败: ${e.message || String(e)}`)
        } finally {
            setIsVerifying(false)
        }
    }

    const handlePasswordSubmit = async (e?: React.FormEvent) => {
        e?.preventDefault()
        if (!password || isUnlocked) return

        // 如果正在进行 Hello 验证，它会自动失败或被取代，UI上不用特意取消
        // 因为 native 调用是模态的或者独立的，我们只要让 JS 状态不对锁住即可

        // 不再检查 isVerifying，因为我们允许打断 Hello
        setIsVerifying(true)
        setError('')

        try {
            const storedHash = await configService.getAuthPassword()

            // 兜底：如果没有设置过密码，直接放行并关闭应用锁
            if (!storedHash) {
                await configService.setAuthEnabled(false)
                handleUnlock()
                return
            }

            const inputHash = await sha256(password)

            if (inputHash === storedHash) {
                // 解锁成功，重新写入 authEnabled 以修复可能被篡改的签名
                await configService.setAuthEnabled(true)
                handleUnlock()
            } else {
                setError('密码错误')
                setPassword('')
                setIsVerifying(false)
                // 如果密码错误，是否重新触发 Hello? 
                // 用户可能想重试密码，暂时不自动触发
            }
        } catch (e) {
            setError('验证失败')
            setIsVerifying(false)
        }
    }

    return (
        <div className={`lock-screen ${isUnlocked ? 'unlocked' : ''}`}>
            <div className="lock-content">
                <div className="lock-avatar">
                    {avatar ? (
                        <img src={avatar} alt="User" style={{ width: '100%', height: '100%', borderRadius: '50%' }} />
                    ) : (
                        <Lock size={40} />
                    )}
                </div>

                <h2 className="lock-title">WeFlow 已锁定</h2>

                <form className="lock-form" onSubmit={handlePasswordSubmit}>
                    <div className="input-group">
                        <input
                            ref={inputRef}
                            type="password"
                            placeholder="输入应用密码"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        // 移除 disabled，允许用户随时输入
                        />
                        <button type="submit" className="submit-btn" disabled={!password}>
                            <ArrowRight size={18} />
                        </button>
                    </div>

                    {showHello && (
                        <button
                            type="button"
                            className={`hello-btn ${isVerifying ? 'loading' : ''}`}
                            onClick={verifyHello}
                        >
                            <Fingerprint size={20} />
                            {isVerifying ? '验证中...' : '使用 Windows Hello 解锁'}
                        </button>
                    )}
                </form>

                {error && <div className="lock-error">{error}</div>}
            </div>
        </div>
    )
}
