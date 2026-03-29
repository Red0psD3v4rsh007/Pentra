import { create } from "zustand"
import { createJSONStorage, persist } from "zustand/middleware"

export interface Notification {
  id: string
  type: "scan_completed" | "scan_failed" | "finding" | "info"
  title: string
  message: string
  timestamp: number
  read: boolean
  scanId?: string
  eventKey?: string
}

interface NotificationState {
  items: Notification[]
  unreadCount: number
  addNotification: (notification: Omit<Notification, "id" | "timestamp" | "read">) => void
  markRead: (id: string) => void
  markAllRead: () => void
  clearAll: () => void
}

let counter = 0

function unreadCount(items: Notification[]): number {
  return items.filter((item) => !item.read).length
}

export const useNotificationStore = create<NotificationState>()(
  persist(
    (set) => ({
      items: [],
      unreadCount: 0,

      addNotification: (notification) =>
        set((state) => {
          const eventKey = notification.eventKey?.trim() ?? ""
          if (eventKey) {
            const existing = state.items.find((item) => item.eventKey === eventKey)
            if (existing) {
              return state
            }
          }
          const item: Notification = {
            ...notification,
            id: `notif-${Date.now()}-${++counter}`,
            timestamp: Date.now(),
            read: false,
          }
          const next = [item, ...state.items].slice(0, 100)
          return { items: next, unreadCount: unreadCount(next) }
        }),

      markRead: (id) =>
        set((state) => {
          const next = state.items.map((n) => (n.id === id ? { ...n, read: true } : n))
          return { items: next, unreadCount: unreadCount(next) }
        }),

      markAllRead: () =>
        set((state) => ({
          items: state.items.map((n) => ({ ...n, read: true })),
          unreadCount: 0,
        })),

      clearAll: () => set({ items: [], unreadCount: 0 }),
    }),
    {
      name: "pentra.notifications",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        items: state.items,
        unreadCount: state.unreadCount,
      }),
      onRehydrateStorage: () => (state) => {
        if (!state) {
          return
        }
        state.unreadCount = unreadCount(state.items)
      },
    }
  )
)
