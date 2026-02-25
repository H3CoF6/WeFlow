/// <reference types="vite/client" />

interface Window {
    electronAPI: {
        // ... other methods ...
        auth: {
            hello: (message?: string) => Promise<{ success: boolean; error?: string }>
            verifyEnabled: () => Promise<boolean>
        }
        // For brevity, using 'any' for other parts or properly importing types if available.
        // In a real scenario, you'd likely want to keep the full interface definition consistent with preload.ts
        // or import a shared type definition.
        [key: string]: any
    }
}
