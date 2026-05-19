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

package org.apache.hive.beeline;

import java.io.ByteArrayInputStream;

import org.jline.terminal.Terminal;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

public class TestBeeLineBuildTerminal {

  @Test
  public void testBuildTerminalWithoutTtyDoesNotThrow() throws Exception {
    Assume.assumeTrue("Requires no controlling TTY", System.console() == null);
    BeeLine beeLine = new BeeLine();
    try {
      Terminal terminal = beeLine.buildTerminal(null);
      Assert.assertNotNull("buildTerminal must return a Terminal without a TTY", terminal);
    } finally {
      beeLine.close();
    }
  }

  @Test
  public void testBuildTerminalWithInputStream() throws Exception {
    BeeLine beeLine = new BeeLine();
    try {
      Terminal terminal = beeLine.buildTerminal(new ByteArrayInputStream(new byte[0]));
      Assert.assertNotNull("buildTerminal must return a Terminal for a script input stream", terminal);
    } finally {
      beeLine.close();
    }
  }
}
