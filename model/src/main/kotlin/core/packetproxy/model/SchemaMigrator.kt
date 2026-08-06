/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.model

import com.j256.ormlite.dao.BaseDaoImpl
import com.j256.ormlite.dao.Dao
import com.j256.ormlite.field.FieldType
import com.j256.ormlite.field.SqlType
import javax.swing.JOptionPane
import packetproxy.common.i18nString
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

/**
 * Soft-migrates ORMLite entity tables by adding missing columns via ALTER TABLE. Falls back to a
 * backed-up recreate only when expected columns are still missing after ALTER.
 */
object SchemaMigrator {
  fun <T, ID> ensureColumns(dao: Dao<T, ID>): List<String> {
    val tableInfo = tableInfo(dao)
    val tableName = tableInfo.tableName
    val existing = existingColumnNames(dao, tableName)
    val added = ArrayList<String>()
    for (fieldType in tableInfo.fieldTypes) {
      if (!shouldMigrate(fieldType)) {
        continue
      }
      val columnName = fieldType.columnName
      if (existing.contains(columnName.lowercase())) {
        continue
      }
      val sql = "ALTER TABLE `$tableName` ADD COLUMN ${columnDefinition(fieldType)}"
      try {
        dao.executeRaw(sql)
        added.add(columnName)
        existing.add(columnName.lowercase())
        log("SchemaMigrator: %s", sql)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    return added
  }

  fun <T, ID> hasAllExpectedColumns(dao: Dao<T, ID>): Boolean {
    val tableInfo = tableInfo(dao)
    val existing = existingColumnNames(dao, tableInfo.tableName)
    return tableInfo.fieldTypes
      .filter { shouldMigrate(it) }
      .all { existing.contains(it.columnName.lowercase()) }
  }

  /**
   * Adds missing columns first. If the table is still missing expected columns, backs up the DB and
   * asks the user whether to drop and recreate the table.
   */
  fun <T, ID> ensureCompatible(
    database: Database,
    dao: Dao<T, ID>,
    tableLabel: String,
    onRecreate: () -> Unit,
  ) {
    val added = ensureColumns(dao)
    if (added.isNotEmpty()) {
      log("SchemaMigrator: added columns to %s: %s", tableLabel, added.joinToString())
    }
    if (hasAllExpectedColumns(dao)) {
      return
    }
    val backupPath =
      try {
        database.backupCurrent()
      } catch (e: Exception) {
        errWithStackTrace(e)
        null
      }
    val backupMsg =
      if (backupPath != null) {
        "\n" + i18nString("Backup created:\n%s", backupPath)
      } else {
        "\n" + i18nString("Failed to create a backup.")
      }
    val headless =
      java.awt.GraphicsEnvironment.isHeadless() ||
        System.getProperty("java.awt.headless") == "true" ||
        System.getProperty("packetproxy.schema.autoRecreate") == "true"
    if (headless) {
      log("SchemaMigrator: headless/auto-recreate — recreating %s without dialog", tableLabel)
      onRecreate()
      return
    }
    val option =
      JOptionPane.showConfirmDialog(
        null,
        i18nString(
          "The %s table schema has been updated.\nIs it OK to delete the current table?%s",
          tableLabel,
          backupMsg,
        ),
        i18nString("Table update"),
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option != JOptionPane.YES_OPTION) {
      return
    }
    onRecreate()
  }

  private fun <T, ID> tableInfo(dao: Dao<T, ID>) =
    (dao as BaseDaoImpl<T, ID>).tableInfo
      ?: throw IllegalStateException("DAO has no TableInfo: ${dao.javaClass.name}")

  private fun shouldMigrate(fieldType: FieldType): Boolean {
    if (fieldType.isForeignCollection) {
      return false
    }
    if (fieldType.isGeneratedId) {
      return false
    }
    return true
  }

  private fun <T, ID> existingColumnNames(dao: Dao<T, ID>, tableName: String): MutableSet<String> {
    val rows = dao.queryRaw("PRAGMA table_info(`$tableName`)").results
    return rows.mapNotNull { it.getOrNull(1)?.lowercase() }.toMutableSet()
  }

  private fun columnDefinition(fieldType: FieldType): String {
    val sb = StringBuilder()
    sb.append('`').append(fieldType.columnName).append("` ")
    sb.append(sqlTypeName(fieldType))
    val defaultClause = defaultClause(fieldType)
    if (defaultClause != null) {
      sb.append(' ').append(defaultClause)
    }
    return sb.toString()
  }

  private fun sqlTypeName(fieldType: FieldType): String =
    when (fieldType.sqlType) {
      SqlType.STRING,
      SqlType.LONG_STRING,
      SqlType.CHAR -> "VARCHAR"
      SqlType.BOOLEAN -> "BOOLEAN"
      SqlType.DATE -> "TIMESTAMP"
      SqlType.BYTE,
      SqlType.SHORT,
      SqlType.INTEGER -> "INTEGER"
      SqlType.LONG -> "BIGINT"
      SqlType.FLOAT -> "FLOAT"
      SqlType.DOUBLE -> "DOUBLE PRECISION"
      SqlType.BYTE_ARRAY,
      SqlType.SERIALIZABLE -> "BLOB"
      SqlType.BIG_DECIMAL -> "NUMERIC"
      else -> "VARCHAR"
    }

  private fun defaultClause(fieldType: FieldType): String? {
    val explicit = fieldType.defaultValue
    if (explicit != null) {
      return if (fieldType.isEscapedDefaultValue) {
        "DEFAULT '${explicit.toString().replace("'", "''")}'"
      } else {
        "DEFAULT $explicit"
      }
    }
    if (fieldType.isCanBeNull) {
      return null
    }
    return when (fieldType.sqlType) {
      SqlType.BOOLEAN,
      SqlType.BYTE,
      SqlType.SHORT,
      SqlType.INTEGER,
      SqlType.LONG,
      SqlType.FLOAT,
      SqlType.DOUBLE -> "DEFAULT 0"
      SqlType.STRING,
      SqlType.LONG_STRING,
      SqlType.CHAR -> "DEFAULT ''"
      else -> null
    }
  }
}
