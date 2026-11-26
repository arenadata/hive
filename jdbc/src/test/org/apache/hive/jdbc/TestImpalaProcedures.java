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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.apache.hive.service.rpc.thrift.TCLIService.Iface;
import org.apache.hive.service.rpc.thrift.TGetInfoReq;
import org.apache.hive.service.rpc.thrift.TGetInfoResp;
import org.apache.hive.service.rpc.thrift.TGetInfoValue;
import org.apache.hive.service.rpc.thrift.TProtocolVersion;
import org.apache.hive.service.rpc.thrift.TSessionHandle;
import org.apache.hive.service.rpc.thrift.TStatus;
import org.apache.hive.service.rpc.thrift.TStatusCode;
import org.apache.thrift.TException;
import org.junit.Test;

/** Procedure metadata that the Hive JDBC driver adds when the server is Impala. */
public class TestImpalaProcedures {

  @Test
  public void jdbcPatternMatchesCaseInsensitively() {
    assertTrue(ImpalaProcedures.nameMatches(null, "add_up"));
    assertTrue(ImpalaProcedures.nameMatches("", "add_up"));
    assertTrue(ImpalaProcedures.nameMatches("%", "add_up"));
    assertTrue(ImpalaProcedures.nameMatches("add%", "add_up"));
    assertTrue(ImpalaProcedures.nameMatches("ADD%", "add_up"));
    assertTrue(ImpalaProcedures.nameMatches("add_u_", "add_up"));
    assertTrue(ImpalaProcedures.nameMatches("add\\_up", "add_up"));
    assertFalse(ImpalaProcedures.nameMatches("add\\_up", "addXup"));
    assertFalse(ImpalaProcedures.nameMatches("other%", "add_up"));
    assertFalse(ImpalaProcedures.nameMatches("a.b", "axb"));
    assertFalse(ImpalaProcedures.nameMatches("%", null));
  }

  @Test
  public void showProceduresSqlQuotesTheDatabase() {
    assertEquals("SHOW PROCEDURES IN `default`", ImpalaProcedures.showProceduresSql("default"));
    assertEquals("SHOW PROCEDURES IN `a``b`", ImpalaProcedures.showProceduresSql("a`b"));
  }

  @Test
  public void procedureRowUsesTheJdbcColumns() throws SQLException {
    List<Object[]> rows = new ArrayList<Object[]>();
    rows.add(ImpalaProcedures.procedureRow("default", "add_up", "TSQL"));
    ResultSet rs = ImpalaProcedures.procedureResult(rows);
    assertEquals(9, rs.getMetaData().getColumnCount());
    assertEquals("PROCEDURE_CAT", rs.getMetaData().getColumnName(1));
    assertEquals("RESERVERD", rs.getMetaData().getColumnName(4));
    assertEquals("SPECIFIC_NAME", rs.getMetaData().getColumnName(9));
    assertTrue(rs.next());
    assertNull(rs.getString("PROCEDURE_CAT"));
    assertEquals("default", rs.getString("PROCEDURE_SCHEM"));
    assertEquals("add_up", rs.getString("PROCEDURE_NAME"));
    assertEquals("TSQL", rs.getString("REMARKS"));
    assertEquals(DatabaseMetaData.procedureResultUnknown, rs.getShort("PROCEDURE_TYPE"));
    assertEquals("add_up", rs.getString("SPECIFIC_NAME"));
    assertFalse(rs.next());
  }

  @Test
  public void functionListingDropsProcedureMarkerRows() throws SQLException {
    List<Object[]> raw = new ArrayList<Object[]>();
    raw.add(new Object[] {
      null, "_impala_builtins", "substring", "", Integer.valueOf(1), "substring(STRING)"});
    raw.add(new Object[] {
      null, "default", "add_up", ImpalaProcedures.PROCEDURE_MARKER,
      Integer.valueOf(0), "add_up"});
    ResultSet rs = ImpalaProcedures.withoutProcedureMarkers(
        ImpalaProcedures.functionResult(raw));
    assertTrue(rs.next());
    assertEquals("substring", rs.getString("FUNCTION_NAME"));
    assertEquals("", rs.getString("REMARKS"));
    assertFalse(rs.next());
  }

  @Test
  public void hiveServerReturnsNoProcedures() throws Exception {
    HiveDatabaseMetaData meta = metadata("Apache Hive");
    assertFalse(meta.supportsStoredProcedures());
    ResultSet rs = meta.getProcedures(null, null, null);
    assertEquals(9, rs.getMetaData().getColumnCount());
    assertFalse(rs.next());
  }

  @Test
  public void impalaReportsStoredProcedures() throws Exception {
    HiveDatabaseMetaData meta = metadata("Impala");
    assertTrue(meta.supportsStoredProcedures());
    assertTrue(ImpalaProcedures.isImpala("impala"));
    assertFalse(ImpalaProcedures.isImpala("Apache Hive"));
  }

  @Test
  public void storedProceduresStayFalseWhenTheServerCannotBeNamed() throws Exception {
    HiveConnection connection = mock(HiveConnection.class);
    Iface client = mock(Iface.class);
    when(client.GetInfo(any(TGetInfoReq.class))).thenThrow(new TException("down"));
    HiveDatabaseMetaData meta = new HiveDatabaseMetaData(
        connection, client, mock(TSessionHandle.class));
    assertFalse(meta.supportsStoredProcedures());
  }

  private static HiveDatabaseMetaData metadata(String product) throws Exception {
    HiveConnection connection = mock(HiveConnection.class);
    when(connection.getProtocol()).thenReturn(TProtocolVersion.HIVE_CLI_SERVICE_PROTOCOL_V11);
    Iface client = mock(Iface.class);
    TGetInfoResp resp = new TGetInfoResp();
    resp.setStatus(new TStatus(TStatusCode.SUCCESS_STATUS));
    TGetInfoValue value = new TGetInfoValue();
    value.setStringValue(product);
    resp.setInfoValue(value);
    when(client.GetInfo(any(TGetInfoReq.class))).thenReturn(resp);
    return new HiveDatabaseMetaData(connection, client, mock(TSessionHandle.class));
  }
}
