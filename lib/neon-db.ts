// Path: devinkis/fork-of-pcap-ai-scanner/fork-of-pcap-ai-scanner-fb3444031e0b44895e9fddc8cf7c92cce4812117/lib/neon-db.ts
// ... (keep previous code as is, only modify findFirst function)

export const pcapFileDb = {
  // ... (findUnique function as is)

  findFirst: async (where: { analysisId?: string; userId?: string }) => {
    const client = createDbClient()
    await client.connect()

    try {
      const conditions = []
      const values = []
      let paramIndex = 1

      // --- ADDED DEBUG LOG HERE ---
      console.log("DEBUG: pcapFileDb.findFirst received 'where' object:", where);
      // --- END ADDED DEBUG LOG ---

      // Ensure analysisId is a non-empty string before adding to conditions
      if (typeof where.analysisId === 'string' && where.analysisId.length > 0) {
        conditions.push(`analysis_id = $${paramIndex++}`)
        values.push(where.analysisId)
      } else {
        console.log("DEBUG: where.analysisId is not a valid non-empty string."); // Added debug log
      }

      // Ensure userId is a non-empty string before adding to conditions
      if (typeof where.userId === 'string' && where.userId.length > 0) {
        conditions.push(`user_id = $${paramIndex++}`)
        values.push(where.userId)
      } else {
        console.log("DEBUG: where.userId is not a valid non-empty string."); // Added debug log
      }

      if (conditions.length === 0) {
        console.log("❌ No search conditions provided for findFirst (after explicit checks).") // Modified log message
        return null
      }

      const query = `SELECT * FROM pcap_files WHERE ${conditions.join(" AND ")} LIMIT 1`
      console.log(`🔍 Executing findFirst query: ${query} with values:`, values)

      const result = await client.query(query, values)
      console.log(`📊 Query returned ${result.rows.length} rows`)

      if (result.rows.length === 0) {
        console.log(`❌ No PCAP file found with conditions:`, where)

        // Debug: Let's see what records exist for this user
        if (typeof where.userId === 'string' && where.userId.length > 0) { // Ensure userId is valid for this debug query
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

  // ... (rest of the pcapFileDb object and other exports as is)
}
