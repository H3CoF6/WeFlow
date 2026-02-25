/// <reference types="vite/client" />

interface Window {
    electronAPI: {
        // ... other methods ...
        auth: {
            hello: (message?: string) => Promise<{ success: boolean; error?: string }>
            verifyEnabled: () => Promise<boolean>
            unlock: (password: string) => Promise<{ success: boolean; error?: string }>
            enableLock: (password: string) => Promise<{ success: boolean; error?: string }>
            disableLock: (password: string) => Promise<{ success: boolean; error?: string }>
            changePassword: (oldPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>
            setHelloSecret: (password: string) => Promise<{ success: boolean }>
            clearHelloSecret: () => Promise<{ success: boolean }>
            isLockMode: () => Promise<boolean>
        }
        // For brevity, using 'any' for other parts or properly importing types if available.
        // In a real scenario, you'd likely want to keep the full interface definition consistent with preload.ts
        // or import a shared type definition.
        [key: string]: any
    }
}
