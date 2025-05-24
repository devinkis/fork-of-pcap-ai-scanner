// Path: devinkis/fork-of-pcap-ai-scanner/fork-of-pcap-ai-scanner-fb3444031e0b44895e9fddc8cf7c92cce4812117/lib/neon-db.ts
import { createClient } from "@vercel/postgres"
import { v4 as uuidv4 } from "uuid"

// Get the connection string from environment variables
const getConnectionString = () => {
  return process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_URL_NON_POOLING
}

// Check database connection with better error handling
const checkDatabaseConnection = () => {
  const databaseUrl = getConnectionString()

  if (!databaseUrl) {
    console.error("❌ No database connection string found!")
    console.error("Please ensure one of these environment variables is set:")
    console.error("- DATABASE_URL")
    console.error("- POSTGRES_URL")
    console.error("- POSTGRES_URL_NON_POOLING")
    return false
  }

  console.log("✅ Database connection string found")
  return true
}

// Initialize connection check
checkDatabaseConnection()

// Function to create a client with proper connection string
const createDbClient = () => {
  // First check for non-pooling connection string
  if (process.env.POSTGRES_URL_NON_POOLING) {
    return createClient({
      connectionString: process.env.POSTGRES_URL_NON_POOLING,
      ssl: { rejectUnauthorized: false },
    })
  }

  // Then check for regular connection strings
  const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL
  if (!connectionString) {
    throw new Error("No database connection string available")
  }

  // For pooled connections, we need to use createClient with the right options
  return createClient({
    connectionString,
    ssl: { rejectUnauthorized: false },
  })
}

// Export the createDbClient function for use in debug endpoint
export { createDbClient }

// Function to initialize the database schema
export async function initializeDatabase() {
  try {
    console.log("🔄 Initializing database schema...")
    const client = createDbClient()
    await client.connect()

    try {
      // Create users table if it doesn't exist
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          name TEXT,
          role TEXT NOT NULL DEFAULT 'USER',
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `)

      // Create pcap_files table if it doesn't exist
      await client.query(`
        CREATE TABLE IF NOT EXISTS pcap_files (
          id TEXT PRIMARY KEY,
          file_name TEXT NOT NULL,
          original_name TEXT NOT NULL,
          size INTEGER NOT NULL,
          blob_url TEXT,
          analysis_id TEXT UNIQUE NOT NULL,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `)

      // Create indexes for better performance
      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
      `)

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_pcap_files_analysis_id ON pcap_files(analysis_id)
      `)

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_pcap_files_user_id ON pcap_files(user_id)
      `)

      console.log("✅ Database schema initialized successfully")
      return { success: true, message: "Database schema initialized successfully" }
    } finally {
      await client.end()
    }
  } catch (error) {
    console.error("❌ Error initializing database schema:", error)
    throw error
  }
}

// Function to seed initial users
export async function seedUsers(adminPassword: string, userPassword: string) {
  try {
    console.log("🔄 Seeding users...")
    const client = createDbClient()
    await client.connect()

    try {
      // Check if admin user already exists
      const adminResult = await client.query("SELECT * FROM users WHERE email = $1", ["admin@pcapscanner.com"])

      if (adminResult.rows.length === 0) {
        console.log("Creating admin user...")
        // Create admin user
        await client.query("INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)", [
          `admin-${uuidv4()}`,
          "admin@pcapscanner.com",
          adminPassword,
          "Admin User",
          "ADMIN",
        ])
        console.log("✅ Admin user created")
      } else {
        console.log("ℹ️ Admin user already exists")
      }

      // Check if regular user already exists
      const userResult = await client.query("SELECT * FROM users WHERE email = $1", ["user@pcapscanner.com"])

      if (userResult.rows.length === 0) {
        console.log("Creating regular user...")
        // Create regular user
        await client.query("INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)", [
          `user-${uuidv4()}`,
          "user@pcapscanner.com",
          userPassword,
          "Regular User",
          "USER",
        ])
        console.log("✅ Regular user created")
      } else {
        console.log("ℹ️ Regular user already exists")
      }

      // Get all users to return
      const allUsers = await client.query("SELECT id, email, name, role FROM users ORDER BY email")

      console.log("✅ User seeding completed")
      return {
        success: true,
        message: "Users seeded successfully",
        users: allUsers.rows,
      }
    } finally {
      await client.end()
    }
  } catch (error) {
    console.error("❌ Error seeding users:", error)
    throw error
  }
}

// User methods with improved error handling
export const userDb = {
  findUnique: async (where: { id?: string; email?: string }) => {
    const client = createDbClient()
    await client.connect()

    try {
      if (where.id) {
        const result = await client.query("SELECT * FROM users WHERE id = $1", [where.id])
        if (result.rows.length === 0) {
          return null
        }

        const user = result.rows[0]
        return {
          ...user,
          createdAt: user.created_at,
          updatedAt: user.updated_at,
        }
      } else if (where.email) {
        console.log(`🔍 Looking for user with email: ${where.email}`)

        const result = await client.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [where.email])

        if (result.rows.length === 0) {
          console.log(`❌ No user found with email: ${where.email}`)
          return null
        }

        const user = result.rows[0]
        console.log(`✅ User found: ${user.email}`)
        return {
          ...user,
          createdAt: user.created_at,
          updatedAt: user.updated_at,
        }
      }
      return null
    } catch (error) {
      console.error("❌ Error finding user:", error)
      throw error
    } finally {
      await client.end()
    }
  },

  findFirst: async (options: { where: any }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const { where } = options

      if (where.email && where.NOT?.id) {
        const result = await client.query("SELECT * FROM users WHERE email = $1 AND id != $2", [
          where.email,
          where.NOT.id,
        ])
        if (result.rows.length === 0) return null

        const user = result.rows[0]
        return {
          ...user,
          createdAt: user.created_at,
          updatedAt: user.updated_at,
        }
      }

      return null
    } catch (error) {
      console.error("❌ Error finding user:", error)
      return null
    } finally {
      await client.end()
    }
  },

  findMany: async (options?: { select?: any; orderBy?: any }) => {
    const client = createDbClient()
    await client.connect()

    try {
      let query = "SELECT "

      if (options?.select) {
        const fields = Object.keys(options.select)
          .filter((key) => options.select[key])
          .map((key) => {
            return key === "createdAt" ? "created_at" : key === "updatedAt" ? "updated_at" : key
          })

        query += fields.length > 0 ? fields.join(", ") : "*"
      } else {
        query += "*"
      }

      query += " FROM users"

      if (options?.orderBy?.createdAt === "desc") {
        query += " ORDER BY created_at DESC"
      }

      const result = await client.query(query)

      return result.rows.map((row) => {
        const user: any = {}
        Object.keys(row).forEach((key) => {
          if (key === "created_at") user.createdAt = row[key]
          else if (key === "updated_at") user.updatedAt = row[key]
          else user[key] = row[key]
        })
        return user
      })
    } catch (error) {
      console.error("❌ Error finding users:", error)
      return []
    } finally {
      await client.end()
    }
  },

  create: async (options: { data: any; select?: any }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const { data, select } = options
      const id = data.id || uuidv4()
      const now = new Date()

      const result = await client.query(
        `INSERT INTO users (id, email, password, name, role, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [id, data.email || "", data.password || "", data.name || null, data.role || "USER", now, now],
      )

      const user = result.rows[0]

      if (select) {
        const selectedUser: any = {}
        Object.keys(select).forEach((key) => {
          if (select[key]) {
            if (key === "createdAt") selectedUser[key] = user.created_at
            else if (key === "updatedAt") selectedUser[key] = user.updated_at
            else selectedUser[key] = user[key]
          }
        })
        return selectedUser
      }

      return {
        ...user,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      }
    } catch (error) {
      console.error("❌ Error creating user:", error)
      throw error
    } finally {
      await client.end()
    }
  },

  update: async (options: { where: { id: string }; data: any; select?: any }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const { where, data } = options
      const now = new Date()

      const updates = []
      const values = []
      let paramIndex = 1

      if (data.email !== undefined) {
        updates.push(`email = $${paramIndex++}`)
        values.push(data.email)
      }

      if (data.password !== undefined) {
        updates.push(`password = $${paramIndex++}`)
        values.push(data.password)
      }

      if (data.name !== undefined) {
        updates.push(`name = $${paramIndex++}`)
        values.push(data.name)
      }

      if (data.role !== undefined) {
        updates.push(`role = $${paramIndex++}`)
        values.push(data.role)
      }

      updates.push(`updated_at = $${paramIndex++}`)
      values.push(now)

      if (updates.length === 1) {
        return null
      }

      values.push(where.id)
      const updateQuery = `UPDATE users SET ${updates.join(", ")} WHERE id = $${paramIndex} RETURNING *`

      const result = await client.query(updateQuery, values)

      if (result.rows.length === 0) {
        return null
      }

      const user = result.rows[0]

      if (select) {
        const selectedUser: any = {}
        Object.keys(select).forEach((key) => {
          if (select[key]) {
            if (key === "createdAt") selectedUser[key] = user.created_at
            else if (key === "updatedAt") selectedUser[key] = user.updated_at
            else selectedUser[key] = user[key]
          }
        })
        return selectedUser
      }

      return {
        ...user,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      }
    } catch (error) {
      console.error("❌ Error updating user:", error)
      return null
    } finally {
      await client.end()
    }
  },

  delete: async (options: { where: { id: string } }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const { where } = options

      const getResult = await client.query("SELECT * FROM users WHERE id = $1", [where.id])

      if (getResult.rows.length === 0) {
        return null
      }

      const user = getResult.rows[0]

      await client.query("DELETE FROM users WHERE id = $1", [where.id])

      return {
        ...user,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      }
    } catch (error) {
      console.error("❌ Error deleting user:", error)
      return null
    } finally {
      await client.end()
    }
  },

  upsert: async (options: {
    where: { email: string }
    update: any
    create: any
  }) => {
    try {
      const { where, update, create } = options

      const existingUser = await userDb.findUnique({ email: where.email })

      if (existingUser) {
        return userDb.update({
          where: { id: existingUser.id },
          data: update,
        })
      } else {
        return userDb.create({ data: create })
      }
    } catch (error) {
      console.error("❌ Error upserting user:", error)
      throw error
    }
  },
}

// PcapFile methods with improved error handling
export const pcapFileDb = {
  findUnique: async (where: { id?: string; analysisId?: string }) => {
    const client = createDbClient()
    await client.connect()

    try {
      if (where.id) {
        console.log(`🔍 Finding PCAP file by ID: ${where.id}`)
        const result = await client.query("SELECT * FROM pcap_files WHERE id = $1", [where.id])
        if (result.rows.length === 0) {
          console.log(`❌ No PCAP file found with ID: ${where.id}`)
          return null
        }
        const file = result.rows[0]
        console.log(`✅ Found PCAP file by ID:`, file)
        return {
          id: file.id,
          fileName: file.file_name,
          originalName: file.original_name,
          size: file.size,
          blobUrl: file.blob_url,
          analysisId: file.analysis_id,
          userId: file.user_id,
          createdAt: file.created_at,
          updatedAt: file.updated_at,
        }
      } else if (where.analysisId) {
        console.log(`🔍 Finding PCAP file by analysis ID: ${where.analysisId}`)
        const result = await client.query("SELECT * FROM pcap_files WHERE analysis_id = $1", [where.analysisId])
        if (result.rows.length === 0) {
          console.log(`❌ No PCAP file found with analysis ID: ${where.analysisId}`)
          return null
        }
        const file = result.rows[0]
        console.log(`✅ Found PCAP file by analysis ID:`, file)
        return {
          id: file.id,
          fileName: file.file_name,
          originalName: file.original_name,
          size: file.size,
          blobUrl: file.blob_url,
          analysisId: file.analysis_id,
          userId: file.user_id,
          createdAt: file.created_at,
          updatedAt: file.updated_at,
        }
      }
      return null
    } catch (error) {
      console.error("❌ Error finding pcap file:", error)
      return null
    } finally {
      await client.end()
    }
  },

  findFirst: async (where: { analysisId?: string; userId?: string }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const conditions = []
      const values = []
      let paramIndex = 1

      // Ensure analysisId is a non-empty string before adding to conditions
      if (typeof where.analysisId === 'string' && where.analysisId.length > 0) {
        conditions.push(`analysis_id = $${paramIndex++}`)
        values.push(where.analysisId)
      }

      // Ensure userId is a non-empty string before adding to conditions
      if (typeof where.userId === 'string' && where.userId.length > 0) {
        conditions.push(`user_id = $${paramIndex++}`)
        values.push(where.userId)
      }

      if (conditions.length === 0) {
        console.log("❌ No search conditions provided for findFirst")
        return null
      }

      const query = `SELECT * FROM pcap_files WHERE ${conditions.join(" AND ")} LIMIT 1`
      console.log(`🔍 Executing findFirst query: ${query} with values:`, values)

      const result = await client.query(query, values)
      console.log(`📊 Query returned ${result.rows.length} rows`)

      if (result.rows.length === 0) {
        console.log(`❌ No PCAP file found with conditions:`, where)

        // Debug: Let's see what records exist for this user
        if (where.userId) {
          const debugResult = await client.query("SELECT analysis_id, user_id FROM pcap_files WHERE user_id = $1", [
            where.userId,
          ])
          console.log(`🔍 Debug: All analysis IDs for user ${where.userId}:`, debugResult.rows)
        }

        return null
      }

      const file = result.rows[0]
      console.log(`✅ Found PCAP file with findFirst:`, {
        id: file.id,
        analysisId: file.analysis_id,
        userId: file.user_id,
        originalName: file.original_name,
      })

      return {
        id: file.id,
        fileName: file.file_name,
        originalName: file.original_name,
        size: file.size,
        blobUrl: file.blob_url,
        analysisId: file.analysis_id,
        userId: file.user_id,
        createdAt: file.created_at,
        updatedAt: file.updated_at,
      }
    } catch (error) {
      console.error("❌ Error in findFirst pcap file:", error)
      return null
    } finally {
      await client.end()
    }
  },

  findMany: async (where: { userId?: string }) => {
    const client = createDbClient()
    await client.connect()

    try {
      let query = "SELECT * FROM pcap_files"
      const values = []

      if (where.userId) {
        query += " WHERE user_id = $1"
        values.push(where.userId)
      }

      query += " ORDER BY created_at DESC"

      const result = await client.query(query, values)

      return result.rows.map((file) => ({
        id: file.id,
        fileName: file.file_name,
        originalName: file.original_name,
        size: file.size,
        blobUrl: file.blob_url,
        analysisId: file.analysis_id,
        userId: file.user_id,
        createdAt: file.created_at,
        updatedAt: file.updated_at,
      }))
    } catch (error) {
      console.error("❌ Error finding pcap files:", error)
      return []
    } finally {
      await client.end()
    }
  },

  create: async (data: { data: any }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const fileData = data.data
      const id = fileData.id || uuidv4()
      const now = new Date()

      console.log(`🔄 Creating PCAP file record with data:`, {
        id,
        fileName: fileData.fileName,
        originalName: fileData.originalName,
        size: fileData.size,
        analysisId: fileData.analysisId,
        userId: fileData.userId,
      })

      const result = await client.query(
        `INSERT INTO pcap_files (
          id, file_name, original_name, size, blob_url, analysis_id, user_id, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *`,
        [
          id,
          fileData.fileName || "",
          fileData.originalName || "",
          fileData.size || 0,
          fileData.blobUrl || null,
          fileData.analysisId || "",
          fileData.userId || "",
          now,
          now,
        ],
      )

      const file = result.rows[0]
      console.log(`✅ PCAP file record created successfully:`, {
        id: file.id,
        analysisId: file.analysis_id,
        userId: file.user_id,
        originalName: file.original_name,
      })

      return {
        id: file.id,
        fileName: file.file_name,
        originalName: file.original_name,
        size: file.size,
        blobUrl: file.blob_url,
        analysisId: file.analysis_id,
        userId: file.user_id,
        createdAt: file.created_at,
        updatedAt: file.updated_at,
      }
    } catch (error) {
      console.error("❌ Error creating pcap file:", error)
      throw error
    } finally {
      await client.end()
    }
  },

  update: async (options: { where: { id: string }; data: any }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const { where, data } = options
      const now = new Date()

      const updates = []
      const values = []
      let paramIndex = 1

      if (data.fileName !== undefined) {
        updates.push(`file_name = $${paramIndex++}`)
        values.push(data.fileName)
      }

      if (data.blobUrl !== undefined) {
        updates.push(`blob_url = $${paramIndex++}`)
        values.push(data.blobUrl)
      }

      updates.push(`updated_at = $${paramIndex++}`)
      values.push(now)

      if (updates.length === 1) {
        return null
      }

      values.push(where.id)
      const updateQuery = `UPDATE pcap_files SET ${updates.join(", ")} WHERE id = $${paramIndex} RETURNING *`

      const result = await client.query(updateQuery, values)

      if (result.rows.length === 0) {
        return null
      }

      const file = result.rows[0]

      return {
        id: file.id,
        fileName: file.file_name,
        originalName: file.original_name,
        size: file.size,
        blobUrl: file.blob_url,
        analysisId: file.analysis_id,
        userId: file.user_id,
        createdAt: file.created_at,
        updatedAt: file.updated_at,
      }
    } catch (error) {
      console.error("❌ Error updating pcap file:", error)
      return null
    } finally {
      await client.end()
    }
  },
}

// Health check query with better error handling
export const queryRaw = async (query: string) => {
  if (query !== "SELECT 1") {
    throw new Error("Unsupported query")
  }

  const client = createDbClient()
  await client.connect()

  try {
    const result = await client.query("SELECT 1")
    return result.rows
  } catch (error) {
    console.error("❌ Error executing raw query:", error)
    throw error
  } finally {
    await client.end()
  }
}

// Test database connection
export const testConnection = async () => {
  const client = createDbClient()
  await client.connect()

  try {
    console.log("🔄 Testing database connection...")
    const result = await client.query("SELECT 1 as test, NOW() as current_time")
    console.log("✅ Database connection successful")
    return { success: true, result: result.rows }
  } catch (error) {
    console.error("❌ Database connection failed:", error)
    throw error
  } finally {
    await client.end()
  }
}

export default {
  user: userDb,
  pcapFile: pcapFileDb,
  $queryRaw: queryRaw,
  $disconnect: async () => {
    // No need to explicitly disconnect with @vercel/postgres client
  },
  initializeDatabase,
  seedUsers,
  testConnection,
}
