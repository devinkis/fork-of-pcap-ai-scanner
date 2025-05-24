// Simple in-memory database for demonstration
// In a production app, you would use a real database like MongoDB, PostgreSQL, etc.

interface User {
  id: string
  email: string
  password: string
  name: string | null
  role: "ADMIN" | "USER"
  createdAt: string
  updatedAt: string
}

interface PcapFile {
  id: string
  fileName: string
  originalName: string
  size: number
  blobUrl: string | null
  analysisId: string
  userId: string
  createdAt: string
  updatedAt: string
}

// In-memory storage
const db = {
  users: new Map<string, User>(),
  pcapFiles: new Map<string, PcapFile>(),
}

// User methods
export const userDb = {
  findUnique: async (where: { id?: string; email?: string }) => {
    if (where.id) {
      return db.users.get(where.id) || null
    }
    if (where.email) {
      return Array.from(db.users.values()).find((user) => user.email === where.email) || null
    }
    return null
  },

  findFirst: async (options: { where: any }) => {
    const { where } = options
    if (where.email && where.NOT?.id) {
      return (
        Array.from(db.users.values()).find((user) => user.email === where.email && user.id !== where.NOT.id) || null
      )
    }
    return null
  },

  findMany: async (options?: { select?: any; orderBy?: any }) => {
    const users = Array.from(db.users.values())
    let result = users

    if (options?.orderBy?.createdAt === "desc") {
      result = users.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    }

    // Handle select option
    if (options?.select) {
      return result.map((user) => {
        const selected: any = {}
        Object.keys(options.select).forEach((key) => {
          if (options.select[key] && key in user) {
            selected[key] = (user as any)[key]
          }
        })
        return selected
      })
    }

    return result
  },

  create: async (options: { data: Partial<User>; select?: any }) => {
    const { data, select } = options
    const id = data.id || crypto.randomUUID()
    const now = new Date().toISOString()
    const user: User = {
      id,
      email: data.email || "",
      password: data.password || "",
      name: data.name || null,
      role: data.role || "USER",
      createdAt: now,
      updatedAt: now,
    }
    db.users.set(id, user)

    // Handle select option
    if (select) {
      const selected: any = {}
      Object.keys(select).forEach((key) => {
        if (select[key] && key in user) {
          selected[key] = (user as any)[key]
        }
      })
      return selected
    }

    return user
  },

  update: async (options: { where: { id: string }; data: Partial<User>; select?: any }) => {
    const { where, data, select } = options
    const user = db.users.get(where.id)
    if (!user) return null

    const updatedUser = {
      ...user,
      ...data,
      updatedAt: new Date().toISOString(),
    }
    db.users.set(where.id, updatedUser)

    // Handle select option
    if (select) {
      const selected: any = {}
      Object.keys(select).forEach((key) => {
        if (select[key] && key in updatedUser) {
          selected[key] = (updatedUser as any)[key]
        }
      })
      return selected
    }

    return updatedUser
  },

  delete: async (options: { where: { id: string } }) => {
    const { where } = options
    const user = db.users.get(where.id)
    if (!user) return null

    db.users.delete(where.id)

    // Delete associated PCAP files
    for (const [id, file] of db.pcapFiles.entries()) {
      if (file.userId === where.id) {
        db.pcapFiles.delete(id)
      }
    }

    return user
  },

  upsert: async (options: {
    where: { email: string }
    update: {}
    create: Partial<User>
  }) => {
    const { where, update, create } = options
    const user = Array.from(db.users.values()).find((u) => u.email === where.email)

    if (user) {
      return userDb.update({ where: { id: user.id }, data: update })
    } else {
      return userDb.create({ data: create })
    }
  },
}

// PcapFile methods
export const pcapFileDb = {
  findUnique: async (where: { id?: string; analysisId?: string }) => {
    if (where.id) {
      return db.pcapFiles.get(where.id) || null
    }
    if (where.analysisId) {
      return Array.from(db.pcapFiles.values()).find((file) => file.analysisId === where.analysisId) || null
    }
    return null
  },

  findFirst: async (where: { analysisId?: string; userId?: string }) => {
    return (
      Array.from(db.pcapFiles.values()).find(
        (file) =>
          (!where.analysisId || file.analysisId === where.analysisId) &&
          (!where.userId || file.userId === where.userId),
      ) || null
    )
  },

  create: async (data: { data: Partial<PcapFile> }) => {
    const id = data.data.id || crypto.randomUUID()
    const now = new Date().toISOString()
    const file: PcapFile = {
      id,
      fileName: data.data.fileName || "",
      originalName: data.data.originalName || "",
      size: data.data.size || 0,
      blobUrl: data.data.blobUrl || null,
      analysisId: data.data.analysisId || "",
      userId: data.data.userId || "",
      createdAt: now,
      updatedAt: now,
    }
    db.pcapFiles.set(id, file)
    return file
  },
}

// Initialize with some test data
export const initializeDb = () => {
  // Add admin user
  userDb.create({
    data: {
      id: "admin-id",
      email: "admin@pcapscanner.com",
      password: "$2a$12$K8GpYeWkOyYC1Db0jqx8W.HR/RQGGn1bCh0uliZsUYaZDUzDzNRyG", // admin123
      name: "Admin User",
      role: "ADMIN",
    },
  })

  // Add regular user
  userDb.create({
    data: {
      id: "user-id",
      email: "user@pcapscanner.com",
      password: "$2a$12$K8GpYeWkOyYC1Db0jqx8W.HR/RQGGn1bCh0uliZsUYaZDUzDzNRyG", // user123
      name: "Regular User",
      role: "USER",
    },
  })
}

// Mock database query for health check
export const queryRaw = async (query: string) => {
  if (query === "SELECT 1") {
    return [{ "?column?": 1 }]
  }
  throw new Error("Unsupported query")
}

// Initialize the database
initializeDb()

export default {
  user: userDb,
  pcapFile: pcapFileDb,
  $queryRaw: queryRaw,
  $disconnect: async () => {
    // Nothing to do for in-memory DB
  },
}
