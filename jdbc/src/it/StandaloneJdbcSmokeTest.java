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

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.regex.Pattern;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.events.XMLEvent;

import org.apache.hive.org.codehaus.stax2.XMLStreamReader2;
import org.apache.hive.org.codehaus.stax2.validation.XMLValidationException;
import org.apache.hive.org.codehaus.stax2.validation.XMLValidationSchema;
import org.apache.hive.org.codehaus.stax2.validation.XMLValidationSchemaFactory;

/**
 * Runs in a separate JVM through the Java source launcher with only the standalone JDBC JAR.
 * Keeping this source outside src/test prevents Maven's test dependencies from hiding packaging gaps.
 */
public final class StandaloneJdbcSmokeTest {
  private static final String VALID_XML = "<root><value>ok</value></root>";
  private static final String INVALID_XML = "<root><unexpected>bad</unexpected></root>";

  private StandaloneJdbcSmokeTest() {
  }

  public static void main(String[] args) throws Exception {
    String[] classpath = System.getProperty("java.class.path").split(Pattern.quote(File.pathSeparator));
    require(classpath.length == 1 && classpath[0].endsWith(".jar")
        && Files.isRegularFile(Path.of(classpath[0])), "Expected only the standalone JDBC JAR on the classpath");
    require(args.length == 1, "Expected one smoke-test scenario");
    switch (args[0]) {
    case "zookeeper":
      testZooKeeper();
      break;
    case "stax":
      testStax();
      break;
    case "validation-dtd":
      testValidation(XMLValidationSchema.SCHEMA_ID_DTD,
          "<!ELEMENT root (value)>\n<!ELEMENT value (#PCDATA)>");
      break;
    case "validation-relaxng":
      testValidation(XMLValidationSchema.SCHEMA_ID_RELAXNG,
          "<element xmlns='http://relaxng.org/ns/structure/1.0' name='root'>"
              + "<element name='value'><text/></element></element>");
      break;
    case "validation-w3c":
      testValidation(XMLValidationSchema.SCHEMA_ID_W3C_SCHEMA,
          "<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'>"
              + "<xs:element name='root'><xs:complexType><xs:sequence>"
              + "<xs:element name='value' type='xs:string'/>"
              + "</xs:sequence></xs:complexType></xs:element></xs:schema>");
      break;
    default:
      throw new AssertionError("Unknown smoke-test scenario: " + args[0]);
    }
    System.out.println("PASS: " + args[0]);
  }

  private static void testZooKeeper() throws Exception {
    // CuratorFrameworkFactory reads these defaults when it is first initialized.
    System.setProperty("curator-default-connection-timeout", "1000");
    System.setProperty("curator-default-session-timeout", "2000");
    System.setProperty("zookeeper.sasl.client", "false");
    int port;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
      port = socket.getLocalPort();
    }
    String url = "jdbc:hive2://127.0.0.1:" + port
        + "/default;serviceDiscoveryMode=zooKeeper;zooKeeperNamespace=hiveserver2";
    try (Connection ignored = DriverManager.getConnection(url)) {
      throw new AssertionError("Connection to an unavailable ZooKeeper unexpectedly succeeded");
    } catch (SQLException expected) {
      Throwable root = expected;
      while (root.getCause() != null) {
        root = root.getCause();
      }
      require(root.getClass().getName().equals(
          "org.apache.hive.org.apache.zookeeper.KeeperException$ConnectionLossException"),
          "Expected ZooKeeper ConnectionLossException, got " + root);
    }
  }

  private static void testStax() throws Exception {
    XMLInputFactory input = XMLInputFactory.newFactory();
    XMLOutputFactory output = XMLOutputFactory.newFactory();
    XMLEventFactory events = XMLEventFactory.newFactory();
    require(input.getClass().getName().equals("org.apache.hive.com.ctc.wstx.stax.WstxInputFactory"),
        "Expected the relocated XMLInputFactory provider");
    require(output.getClass().getName().equals("org.apache.hive.com.ctc.wstx.stax.WstxOutputFactory"),
        "Expected the relocated XMLOutputFactory provider");
    require(events.getClass().getName().equals("org.apache.hive.com.ctc.wstx.stax.WstxEventFactory"),
        "Expected the relocated XMLEventFactory provider");

    StringWriter xml = new StringWriter();
    XMLEventWriter writer = output.createXMLEventWriter(xml);
    try {
      writer.add(events.createStartDocument());
      writer.add(events.createStartElement(new QName("root"), null, null));
      writer.add(events.createCharacters("text<&>"));
      writer.add(events.createEndElement(new QName("root"), null));
      writer.add(events.createEndDocument());
    } finally {
      writer.close();
    }

    XMLEventReader reader = input.createXMLEventReader(new StringReader(xml.toString()));
    int starts = 0;
    int ends = 0;
    StringBuilder text = new StringBuilder();
    try {
      while (reader.hasNext()) {
        XMLEvent event = reader.nextEvent();
        if (event.isStartElement()) {
          require(event.asStartElement().getName().equals(new QName("root")), "Unexpected root element");
          starts++;
        } else if (event.isEndElement()) {
          require(event.asEndElement().getName().equals(new QName("root")), "Unexpected closing element");
          ends++;
        } else if (event.isCharacters()) {
          text.append(event.asCharacters().getData());
        }
      }
    } finally {
      reader.close();
    }
    require(starts == 1 && ends == 1 && "text<&>".contentEquals(text), "StAX round trip changed the XML");
  }

  private static void testValidation(String schemaType, String schemaSource) throws Exception {
    XMLValidationSchemaFactory factory = XMLValidationSchemaFactory.newInstance(schemaType);
    require(factory.getClass().getName().startsWith("org.apache.hive.com.ctc.wstx."),
        "Expected a relocated XMLValidationSchemaFactory provider");
    XMLValidationSchema schema = factory.createSchema(new StringReader(schemaSource));
    validate(schema, VALID_XML);
    try {
      validate(schema, INVALID_XML);
      throw new AssertionError("Schema accepted an undeclared element for " + schemaType);
    } catch (XMLValidationException expected) {
      require(expected.getValidationProblem() != null, "Expected a schema validation problem");
    }
  }

  private static void validate(XMLValidationSchema schema, String xml) throws Exception {
    XMLStreamReader2 reader = (XMLStreamReader2) XMLInputFactory.newFactory()
        .createXMLStreamReader(new StringReader(xml));
    try {
      reader.validateAgainst(schema);
      while (reader.hasNext()) {
        reader.next();
      }
    } finally {
      reader.close();
    }
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}
