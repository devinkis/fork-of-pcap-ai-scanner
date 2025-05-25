// lib/neon-db.ts
import { createClient } from "@vercel/postgres";
import { v4 as uuidv4 } from "uuid";

const getConnectionString = () => {
  return process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_URL_NON_POOLING;
};

const checkDatabaseConnection = () => {
  const databaseUrl = getConnectionString();
  if (!databaseUrl) {
    console.error("❌ No database connection string found!");
    console.error("Please ensure one of these environment variables is set:");
    console.error("- DATABASE_URL");
    console.error("- POSTGRES_URL");
    console.error("- POSTGRES_URL_NON_POOLING");
    return false;
  }
  console.log("✅ Database connection string found");
  return true;
};

checkDatabaseConnection();

// Fungsi createDbClient diekspor agar bisa digunakan di tempat lain jika perlu,
// misalnya di API route lain atau skrip.
export const createDbClient = () => {
  if (process.env.POSTGRES_URL_NON_POOLING) {
    return createClient({
      connectionString: process.env.POSTGRES_URL_NON_POOLING,
      // Opsi SSL mungkin perlu disesuaikan tergantung konfigurasi NeonDB Anda
      // Untuk Vercel KV (Postgres), rejectUnauthorized: false biasanya diperlukan.
      ssl: { rejectUnauthorized: false }, 
    });
  }
  const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!connectionString) {
    throw new Error("No database connection string available for pooled connection");
  }
  return createClient({
    connectionString,
    ssl: { rejectUnauthorized: false },
  });
};

export async function initializeDatabase() {
  console.log("🔄 Initializing database schema...");
  const client = createDbClient();
  try {
    await client.connect();
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
    `);
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
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_pcap_files_analysis_id ON pcap_files(analysis_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_pcap_files_user_id ON pcap_files(user_id)`);
    console.log("✅ Database schema initialized successfully");
    return { success: true, message: "Database schema initialized successfully" };
  } catch (error) {
    console.error("❌ Error initializing database schema:", error);
    throw error; // Lempar ulang error agar bisa ditangani oleh pemanggil
  } finally {
    await client.end();
  }
}

export async function seedUsers(adminPassword: string, userPassword: string) {
  console.log("🔄 Seeding users...");
  const client = createDbClient();
  try {
    await client.connect();
    // Admin user
    const adminResult = await client.query("SELECT * FROM users WHERE email = $1", ["admin@pcapscanner.com"]);
    if (adminResult.rows.length === 0) {
      await client.query("INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)", [
        `admin-${uuidv4()}`, "admin@pcapscanner.com", adminPassword, "Admin User", "ADMIN",
      ]);
      console.log("✅ Admin user created");
    } else {
      console.log("ℹ️ Admin user already exists");
    }
    // Regular user
    const userResult = await client.query("SELECT * FROM users WHERE email = $1", ["user@pcapscanner.com"]);
    if (userResult.rows.length === 0) {
      await client.query("INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)", [
        `user-${uuidv4()}`, "user@pcapscanner.com", userPassword, "Regular User", "USER",
      ]);
      console.log("✅ Regular user created");
    } else {
      console.log("ℹ️ Regular user already exists");
    }
    const allUsers = await client.query("SELECT id, email, name, role FROM users ORDER BY email");
    console.log("✅ User seeding completed");
    return { success: true, message: "Users seeded successfully", users: allUsers.rows };
  } catch (error) {
    console.error("❌ Error seeding users:", error);
    throw error;
  } finally {
    await client.end();
  }
}

// Helper untuk memetakan row ke objek User dengan createdAt dan updatedAt
const mapUserRow = (row: any) => {
  if (!row) return null;
  return {
    ...row,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

// Helper untuk memetakan row ke objek PcapFile dengan createdAt dan updatedAt
const mapPcapFileRow = (row: any) => {
  if (!row) return null;
  return {
    id: row.id,
    fileName: row.file_name,
    originalName: row.original_name,
    size: row.size,
    blobUrl: row.blob_url,
    analysisId: row.analysis_id,
    userId: row.user_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};


export const userDb = {
  findUnique: async (where: { id?: string; email?: string }) => {
    const client = createDbClient();
    try {
      await client.connect();
      let result;
      if (where.id) {
        result = await client.query("SELECT * FROM users WHERE id = $1", [where.id]);
      } else if (where.email) {
        result = await client.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [where.email.toLowerCase()]);
      } else {
        return null;
      }
      return mapUserRow(result?.rows[0]);
    } catch (error) {
      console.error("❌ Error finding unique user:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  findFirst: async (options: { where: { email?: string; NOT?: { id?: string } } }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { where } = options;
      if (where.email && where.NOT?.id) {
        const result = await client.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND id != $2 LIMIT 1", [
          where.email.toLowerCase(),
          where.NOT.id,
        ]);
        return mapUserRow(result.rows[0]);
      }
      // Tambahkan kondisi lain jika diperlukan
      return null;
    } catch (error) {
      console.error("❌ Error finding first user:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  findMany: async (options?: { select?: any; orderBy?: { createdAt?: 'asc' | 'desc' } }) => {
    const client = createDbClient();
    try {
      await client.connect();
      let query = "SELECT ";
      if (options?.select) {
        const fields = Object.keys(options.select).filter(key => options.select[key]).map(key => key === 'createdAt' ? 'created_at' : key === 'updatedAt' ? 'updated_at' : key);
        query += fields.length > 0 ? fields.join(", ") : "*";
      } else {
        query += "*";
      }
      query += " FROM users";
      if (options?.orderBy?.createdAt) {
        query += ` ORDER BY created_at ${options.orderBy.createdAt.toUpperCase()}`;
      }
      const result = await client.query(query);
      return result.rows.map(mapUserRow);
    } catch (error) {
      console.error("❌ Error finding many users:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  create: async (options: { data: Partial<Omit<ReturnType<typeof mapUserRow>, 'createdAt'|'updatedAt'|'id'> & {id?: string, password?: string}>; select?: any }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { data, select } = options;
      const id = data.id || uuidv4();
      const now = new Date();
      const result = await client.query(
        `INSERT INTO users (id, email, password, name, role, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [id, data.email!, data.password!, data.name || null, data.role || "USER", now, now],
      );
      const user = mapUserRow(result.rows[0]);
      if (select && user) {
        const selectedUser: any = {};
        Object.keys(select).forEach(key => { if (select[key]) selectedUser[key] = (user as any)[key]; });
        return selectedUser;
      }
      return user;
    } catch (error) {
      console.error("❌ Error creating user:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  update: async (options: { where: { id: string }; data: Partial<Omit<ReturnType<typeof mapUserRow>, 'createdAt'|'updatedAt'|'id'|'email'>>; select?: any }) => {
    const client = createDbClient();
     try {
      await client.connect();
      const { where, data, select } = options;
      const now = new Date();
      const updates = []; const values = []; let paramIndex = 1;

      Object.entries(data).forEach(([key, value]) => {
        if (value !== undefined) {
            updates.push(`${key === 'createdAt' ? 'created_at' : key === 'updatedAt' ? 'updated_at' : key} = $${paramIndex++}`);
            values.push(value);
        }
      });
      if (updates.length === 0) return userDb.findUnique({id: where.id}); // No fields to update besides timestamp

      updates.push(`updated_at = $${paramIndex++}`);
      values.push(now);
      values.push(where.id);

      const updateQuery = `UPDATE users SET ${updates.join(", ")} WHERE id = $${paramIndex} RETURNING *`;
      const result = await client.query(updateQuery, values);
      const user = mapUserRow(result.rows[0]);

      if (select && user) {
        const selectedUser: any = {};
        Object.keys(select).forEach(key => { if (select[key]) selectedUser[key] = (user as any)[key]; });
        return selectedUser;
      }
      return user;
    } catch (error) {
      console.error("❌ Error updating user:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  delete: async (options: { where: { id: string } }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { where } = options;
      const getResult = await client.query("SELECT * FROM users WHERE id = $1", [where.id]);
      if (getResult.rows.length === 0) return null;
      const user = mapUserRow(getResult.rows[0]);
      await client.query("DELETE FROM users WHERE id = $1", [where.id]);
      return user;
    } catch (error) {
      console.error("❌ Error deleting user:", error);
      throw error;
    } finally {
      await client.end();
    }
  },
};


export const pcapFileDb = {
  findUnique: async (where: { id?: string; analysisId?: string }) => {
    const client = createDbClient();
    try {
      await client.connect();
      let result;
      if (where.id) {
        result = await client.query("SELECT * FROM pcap_files WHERE id = $1", [where.id]);
      } else if (where.analysisId) {
        result = await client.query("SELECT * FROM pcap_files WHERE analysis_id = $1", [where.analysisId]);
      } else {
        return null;
      }
      return mapPcapFileRow(result?.rows[0]);
    } catch (error) {
      console.error("❌ Error finding unique pcap_file:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  findFirst: async (options: { where: { analysisId?: string; userId?: string } }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { where } = options;
      const conditions = []; const values = []; let paramIndex = 1;
      if (where.analysisId) { conditions.push(`analysis_id = $${paramIndex++}`); values.push(where.analysisId); }
      if (where.userId) { conditions.push(`user_id = $${paramIndex++}`); values.push(where.userId); }
      if (conditions.length === 0) return null; // Atau error jika tidak ada kondisi
      const query = `SELECT * FROM pcap_files WHERE ${conditions.join(" AND ")} LIMIT 1`;
      const result = await client.query(query, values);
      return mapPcapFileRow(result.rows[0]);
    } catch (error) {
      console.error("❌ Error finding first pcap_file:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  findMany: async (options: { userId?: string } = {}) => {
    const client = createDbClient();
    try {
      await client.connect();
      let query = "SELECT * FROM pcap_files";
      const values = [];
      if (options.userId) {
        query += " WHERE user_id = $1";
        values.push(options.userId);
      }
      query += " ORDER BY created_at DESC";
      const result = await client.query(query, values);
      return result.rows.map(mapPcapFileRow);
    } catch (error) {
      console.error("❌ Error finding many pcap_files:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  create: async (options: { data: Partial<Omit<ReturnType<typeof mapPcapFileRow>, 'createdAt'|'updatedAt'|'id'>> & {id?:string} }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const fileData = options.data;
      const id = fileData.id || uuidv4();
      const now = new Date();
      const result = await client.query(
        `INSERT INTO pcap_files (id, file_name, original_name, size, blob_url, analysis_id, user_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          id, fileData.fileName!, fileData.originalName!, fileData.size!,
          fileData.blobUrl || null, fileData.analysisId!, fileData.userId!, now, now
        ],
      );
      return mapPcapFileRow(result.rows[0]);
    } catch (error) {
      console.error("❌ Error creating pcap_file:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  update: async (options: { where: { id: string }; data: Partial<Omit<ReturnType<typeof mapPcapFileRow>, 'createdAt'|'updatedAt'|'id'|'analysisId'|'userId'|'originalName'|'size'>> }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { where, data } = options;
      const now = new Date();
      const updates = []; const values = []; let paramIndex = 1;

      Object.entries(data).forEach(([key, value]) => {
        if (value !== undefined) {
            updates.push(`${key === 'fileName' ? 'file_name' : key === 'blobUrl' ? 'blob_url' : key} = $${paramIndex++}`);
            values.push(value);
        }
      });
      if (updates.length === 0) return pcapFileDb.findUnique({id: where.id});

      updates.push(`updated_at = $${paramIndex++}`);
      values.push(now);
      values.push(where.id);
      
      const updateQuery = `UPDATE pcap_files SET ${updates.join(", ")} WHERE id = $${paramIndex} RETURNING *`;
      const result = await client.query(updateQuery, values);
      return mapPcapFileRow(result.rows[0]);
    } catch (error) {
      console.error("❌ Error updating pcap_file:", error);
      throw error;
    } finally {
      await client.end();
    }
  },

  delete: async (options: { where: { id: string } }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { where } = options;
      if (!where.id) {
        throw new Error("ID is required to delete a pcap_file record.");
      }
      const getResult = await client.query("SELECT * FROM pcap_files WHERE id = $1", [where.id]);
      if (getResult.rows.length === 0) {
        console.warn(`[NEON-DB] pcapFile.delete: Record with ID ${where.id} not found.`);
        return null;
      }
      const fileToDelete = mapPcapFileRow(getResult.rows[0]);
      await client.query("DELETE FROM pcap_files WHERE id = $1", [where.id]);
      console.log(`[NEON-DB] pcapFile.delete: Record with ID ${where.id} deleted.`);
      return fileToDelete;
    } catch (error) {
      console.error("❌ Error deleting pcap_file record:", error);
      throw error;
    } finally {
      await client.end();
    }
  },
  // --- TAMBAHKAN METODE BARU DI SINI ---
  deleteManyByUserId: async (options: { where: { userId: string } }) => {
    const client = createDbClient();
    try {
      await client.connect();
      const { where } = options;
      if (!where.userId) {
        throw new Error("User ID is required to delete multiple pcap_file records.");
      }
      
      // Tidak perlu mengambil record dulu karena kita menghapus berdasarkan userId
      // dan ON DELETE CASCADE pada foreign key user_id di tabel pcap_files akan menangani ini
      // jika kita menghapus user. Namun, karena kita menghapus pcap_files berdasarkan userId,
      // kita langsung saja.

      // Yang akan kita kembalikan adalah jumlah record yang dihapus.
      const result = await client.query("DELETE FROM pcap_files WHERE user_id = $1 RETURNING id", [where.userId]);
      
      const deletedCount = result.rowCount || 0;
      console.log(`[NEON-DB] pcapFile.deleteManyByUserId: ${deletedCount} records deleted for user ID ${where.userId}.`);
      
      return { count: deletedCount }; // Mengembalikan jumlah record yang berhasil dihapus
    } catch (error) {
      console.error("❌ Error deleting multiple pcap_file records by user ID:", error);
      throw error;
    } finally {
      await client.end();
    }
  },
};

export const queryRaw = async (query: string) => {
  if (query !== "SELECT 1") { // Batasi hanya query tertentu untuk keamanan
    throw new Error("Unsupported raw query");
  }
  const client = createDbClient();
  try {
    await client.connect();
    const result = await client.query(query); // Jalankan query yang diberikan
    return result.rows;
  } catch (error) {
    console.error("❌ Error executing raw query:", error);
    throw error;
  } finally {
    await client.end();
  }
};

export const testConnection = async () => {
  const client = createDbClient();
  try {
    await client.connect();
    console.log("🔄 Testing database connection...");
    const result = await client.query("SELECT 1 as test, NOW() as current_time");
    console.log("✅ Database connection successful");
    return { success: true, result: result.rows };
  } catch (error) {
    console.error("❌ Database connection failed:", error);
    throw error;
  } finally {
    await client.end();
  }
};

export default {
  user: userDb,
  pcapFile: pcapFileDb,
  $queryRaw: queryRaw,
  $disconnect: async () => {
    // Tidak ada yang perlu dilakukan secara eksplisit untuk @vercel/postgres pool
  },
  initializeDatabase,
  seedUsers,
  testConnection,
};
