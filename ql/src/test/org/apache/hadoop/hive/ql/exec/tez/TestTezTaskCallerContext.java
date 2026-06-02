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
package org.apache.hadoop.hive.ql.exec.tez;

import org.apache.tez.client.CallerContext;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestTezTaskCallerContext {

  @Test
  public void testCreateCallerContextUsesHiveQueryId() {
    String queryId = "hive_20260601151408_438d1789-d603-412b-bb1d-5401effba17c";

    CallerContext callerContext = TezTask.createCallerContext(queryId, "select 1");

    assertEquals("HIVE", callerContext.getContext());
    assertEquals("HIVE_QUERY_ID", callerContext.getCallerType());
    assertEquals(queryId, callerContext.getCallerId());
    assertEquals("select 1", callerContext.getBlob());
  }
}
