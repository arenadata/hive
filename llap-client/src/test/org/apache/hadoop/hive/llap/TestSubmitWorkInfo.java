/**
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

package org.apache.hadoop.hive.llap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.yarn.api.records.ApplicationId;
import org.junit.Test;

import static org.junit.Assert.*;

public class TestSubmitWorkInfo {
  @Test
  public void testConfiguredTokenAlgorithmAndWritableRoundTrip() throws Exception {
    Configuration conf = new Configuration(false);
    conf.set("hadoop.security.secret-manager.key-generator.algorithm", "HmacSHA256");
    SubmitWorkInfo original = new SubmitWorkInfo(ApplicationId.newInstance(123L, 7),
        456L, 2, new byte[] {1, 2}, new byte[] {3, 4}, conf);
    assertEquals(32, original.getToken().getPassword().length);
    SubmitWorkInfo copy = SubmitWorkInfo.fromBytes(SubmitWorkInfo.toBytes(original));
    assertEquals(original.getToken(), copy.getToken());
    assertEquals(original.getFakeAppId(), copy.getFakeAppId());
    assertEquals(456L, copy.getCreationTime());
    assertEquals(2, copy.getVertexParallelism());
    assertArrayEquals(new byte[] {1, 2}, copy.getVertexBinary());
    assertArrayEquals(new byte[] {3, 4}, copy.getVertexSignature());
  }

  @Test
  public void testExistingConstructorRemainsUsable() {
    SubmitWorkInfo info = new SubmitWorkInfo(ApplicationId.newInstance(123L, 8),
        456L, 1, null, null);
    assertNotNull(info.getToken());
    assertEquals(info.getTokenIdentifier(), info.getToken().getService().toString());
  }
}
