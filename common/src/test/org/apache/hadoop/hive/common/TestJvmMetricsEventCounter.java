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

package org.apache.hadoop.hive.common;

import org.apache.hadoop.hive.ql.log.HiveEventCounter;
import org.apache.hadoop.metrics2.MetricsCollector;
import org.apache.hadoop.metrics2.MetricsInfo;
import org.apache.hadoop.metrics2.MetricsRecordBuilder;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.junit.Test;

import static org.apache.hadoop.hive.common.JvmMetricsInfo.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

public class TestJvmMetricsEventCounter {
  @Test
  public void testMetricsUseHiveLog4j2EventCounter() {
    long fatal = HiveEventCounter.getFatal();
    long error = HiveEventCounter.getError();
    long warn = HiveEventCounter.getWarn();
    long info = HiveEventCounter.getInfo();
    HiveEventCounter counter = HiveEventCounter.createInstance("metrics-test", true, null, null);
    for (Level level : new Level[] {Level.FATAL, Level.ERROR, Level.WARN, Level.INFO}) {
      counter.append(Log4jLogEvent.newBuilder().setLevel(level).build());
    }

    MetricsCollector collector = mock(MetricsCollector.class);
    MetricsRecordBuilder builder = mock(MetricsRecordBuilder.class);
    when(collector.addRecord(JvmMetrics)).thenReturn(builder);
    when(builder.setContext(anyString())).thenReturn(builder);
    when(builder.tag(any(MetricsInfo.class), anyString())).thenReturn(builder);
    when(builder.addGauge(any(MetricsInfo.class), anyFloat())).thenReturn(builder);
    when(builder.addGauge(any(MetricsInfo.class), anyInt())).thenReturn(builder);
    when(builder.addCounter(any(MetricsInfo.class), anyLong())).thenReturn(builder);

    new org.apache.hadoop.hive.common.JvmMetrics("test", "session").getMetrics(collector, true);

    verify(builder).addCounter(LogFatal, fatal + 1);
    verify(builder).addCounter(LogError, error + 1);
    verify(builder).addCounter(LogWarn, warn + 1);
    verify(builder).addCounter(LogInfo, info + 1);
  }
}
