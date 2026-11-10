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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Tests the packaged artifact without Maven's dependency or test classpath in the child JVM. */
@RunWith(Parameterized.class)
public class StandaloneJdbcIT {
  @Rule
  public final TemporaryFolder temporaryFolder = new TemporaryFolder();

  private final String scenario;

  public StandaloneJdbcIT(String scenario) {
    this.scenario = scenario;
  }

  @Parameterized.Parameters(name = "{0}")
  public static String[][] scenarios() {
    return new String[][] {
        {"zookeeper"}, {"stax"}, {"validation-dtd"}, {"validation-relaxng"}, {"validation-w3c"}
    };
  }

  @Test
  public void testStandaloneJar() throws Exception {
    Path jar = Path.of(System.getProperty("standalone.jar")).toAbsolutePath();
    Path probe = Path.of(System.getProperty("standalone.probe")).toAbsolutePath();
    assertTrue("Missing standalone JAR: " + jar, Files.isRegularFile(jar));
    assertTrue("Missing source-launcher probe: " + probe, Files.isRegularFile(probe));

    String executable = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
    Path javaExecutable = Path.of(System.getProperty("java.home"), "bin", executable);
    File output = temporaryFolder.newFile("output.log");
    // Source launching keeps even the test classes and JUnit off the child's classpath.
    ProcessBuilder builder = new ProcessBuilder(javaExecutable.toString(), "-cp", jar.toString(),
        probe.toString(), scenario)
        .directory(temporaryFolder.getRoot())
        .redirectErrorStream(true)
        .redirectOutput(output);
    builder.environment().keySet().removeAll(
        Set.of("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"));
    Process process = builder.start();
    boolean finished;
    try {
      process.getOutputStream().close();
      finished = process.waitFor(60, TimeUnit.SECONDS);
    } finally {
      if (process.isAlive()) {
        process.destroyForcibly();
        process.waitFor(10, TimeUnit.SECONDS);
      }
    }
    String diagnostics = scenario + ":\n" + Files.readString(output.toPath());
    assertTrue("Timed out: " + diagnostics, finished);
    assertEquals(diagnostics, 0, process.exitValue());
    assertTrue(diagnostics, diagnostics.contains("PASS: " + scenario));
  }
}
