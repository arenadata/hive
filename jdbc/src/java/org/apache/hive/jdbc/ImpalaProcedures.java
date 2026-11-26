/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hive.jdbc;

import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import org.apache.hadoop.hive.metastore.api.FieldSchema;
import org.apache.hive.service.cli.TableSchema;

/**
 * Stored procedures exist on Impala, not on HiveServer2. Impala reports
 * {@code Impala} as the DBMS name. {@code SHOW PROCEDURES} is the listing
 * statement. Rows Impala adds to GetFunctions use {@link #PROCEDURE_MARKER}
 * as REMARKS so a tool that reads both metadata calls does not show each
 * procedure twice.
 */
final class ImpalaProcedures {
  static final String PRODUCT = "Impala";
  /** Matches {@code org.apache.impala.tsql.TsqlMetadata.REMARKS}. */
  static final String PROCEDURE_MARKER = "stored procedure";

  static final List<String> PROCEDURE_COLUMNS = Arrays.asList(
      "PROCEDURE_CAT", "PROCEDURE_SCHEM", "PROCEDURE_NAME", "RESERVERD", "RESERVERD",
      "RESERVERD", "REMARKS", "PROCEDURE_TYPE", "SPECIFIC_NAME");
  static final List<String> PROCEDURE_TYPES = Arrays.asList(
      "STRING", "STRING", "STRING", "STRING", "STRING",
      "STRING", "STRING", "SMALLINT", "STRING");
  static final List<String> FUNCTION_COLUMNS = Arrays.asList(
      "FUNCTION_CAT", "FUNCTION_SCHEM", "FUNCTION_NAME", "REMARKS",
      "FUNCTION_TYPE", "SPECIFIC_NAME");
  static final List<String> FUNCTION_TYPES = Arrays.asList(
      "STRING", "STRING", "STRING", "STRING", "INT", "STRING");

  private ImpalaProcedures() {}

  static boolean isImpala(String productName) {
    return PRODUCT.equalsIgnoreCase(productName);
  }

  static String showProceduresSql(String database) {
    return "SHOW PROCEDURES IN " + quoteIdent(database);
  }

  static String quoteIdent(String name) {
    return "`" + (name == null ? "" : name).replace("`", "``") + "`";
  }

  /**
   * JDBC pattern: {@code %} is any string, {@code _} is one character, and
   * {@code \} escapes either. Null, empty and {@code %} match every name.
   * Comparison is case-insensitive because Impala stores names in lowercase.
   */
  static boolean nameMatches(String jdbcPattern, String name) {
    if (name == null) return false;
    if (jdbcPattern == null || jdbcPattern.isEmpty() || "%".equals(jdbcPattern)) return true;
    String regex = jdbcRegex(jdbcPattern.toLowerCase(Locale.ROOT));
    return Pattern.compile(regex).matcher(name.toLowerCase(Locale.ROOT)).matches();
  }

  static String jdbcRegex(String pattern) {
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < pattern.length(); i++) {
      char c = pattern.charAt(i);
      if (c == '\\' && i + 1 < pattern.length()) {
        char next = pattern.charAt(i + 1);
        if (next == '%' || next == '_') {
          out.append(Pattern.quote(String.valueOf(next)));
          i++;
          continue;
        }
      }
      if (c == '%') out.append(".*");
      else if (c == '_') out.append(".");
      else out.append(Pattern.quote(String.valueOf(c)));
    }
    return out.toString();
  }

  static Object[] procedureRow(String schema, String name, String dialect) {
    return new Object[] {
      null,
      schema,
      name,
      null,
      null,
      null,
      dialect,
      Short.valueOf((short) DatabaseMetaData.procedureResultUnknown),
      name
    };
  }

  static ResultSet procedureResult(List<Object[]> rows) throws SQLException {
    return new LocalRows(PROCEDURE_COLUMNS, PROCEDURE_TYPES, rows);
  }

  static ResultSet functionResult(List<Object[]> rows) throws SQLException {
    return new LocalRows(FUNCTION_COLUMNS, FUNCTION_TYPES, rows);
  }

  /** Drops GetFunctions rows that are stored procedures. Closes {@code rs}. */
  static ResultSet withoutProcedureMarkers(ResultSet rs) throws SQLException {
    List<Object[]> kept = new ArrayList<Object[]>();
    try {
      while (rs.next()) {
        String remarks = rs.getString("REMARKS");
        if (PROCEDURE_MARKER.equals(remarks)) continue;
        kept.add(new Object[] {
          rs.getString("FUNCTION_CAT"),
          rs.getString("FUNCTION_SCHEM"),
          rs.getString("FUNCTION_NAME"),
          remarks,
          rs.getObject("FUNCTION_TYPE"),
          rs.getString("SPECIFIC_NAME")
        });
      }
    } finally {
      rs.close();
    }
    return functionResult(kept);
  }

  /**
   * In-memory metadata result. Same shape as
   * {@code HiveDatabaseMetaData.ClientInfoPropertiesResultSet}.
   */
  private static final class LocalRows extends HiveMetaDataResultSet<Object[]> {
    private int index = -1;

    LocalRows(List<String> columns, List<String> types, List<Object[]> rows)
        throws SQLException {
      super(columns, types, rows == null ? Collections.<Object[]>emptyList() : rows);
      columnAttributes = new ArrayList<JdbcColumnAttributes>(
          Collections.nCopies(columns.size(), (JdbcColumnAttributes) null));
      List<FieldSchema> fields = new ArrayList<FieldSchema>(columns.size());
      for (int i = 0; i < columns.size(); i++) {
        fields.add(new FieldSchema(columns.get(i), types.get(i), null));
      }
      setSchema(new TableSchema(fields));
    }

    @Override
    public boolean next() throws SQLException {
      if ((++index) >= data.size()) return false;
      Object[] current = data.get(index);
      row = Arrays.copyOf(current, current.length);
      return true;
    }

    // ResultSet declares these without a default in the JDBC stub this module
    // compiles against. Hive's other in-memory result sets implement them too.
    @Override
    public <T> T getObject(String columnLabel, Class<T> type) throws SQLException {
      return getObject(findColumn(columnLabel), type);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getObject(int columnIndex, Class<T> type) throws SQLException {
      return (T) getObject(columnIndex);
    }
  }
}
