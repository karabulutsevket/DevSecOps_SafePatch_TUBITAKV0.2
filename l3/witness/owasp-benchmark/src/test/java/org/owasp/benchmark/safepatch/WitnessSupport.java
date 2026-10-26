package org.owasp.benchmark.safepatch;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * SafePatch L3 witness support for OWASP Benchmark cases (written by SafePatch, MIT).
 *
 * A Benchmark test case is a servlet that reads one input, named after the case, from a
 * cookie, a header, a parameter or the query string. Here the servlet runs in-process with a
 * request that carries the same value on every channel, and the witness looks at effects only:
 * what a fix does instead (refuse, sanitize, ignore) does not matter. Java 8 source level.
 */
public final class WitnessSupport {

  private WitnessSupport() {
  }

  /** Runs the servlet's doPost with `value` as input `name` and returns what it wrote. */
  public static String run(Class<?> servlet, String name, String value) throws Exception {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    PrintWriter writer = new PrintWriter(new OutputStreamWriter(body, StandardCharsets.UTF_8), true);
    Object instance = servlet.getDeclaredConstructor().newInstance();
    Method doPost = servlet.getMethod("doPost", HttpServletRequest.class, HttpServletResponse.class);
    try {
      doPost.invoke(instance, request(name, value), response(writer, body));
    }
    catch (InvocationTargetException e) {
      // A servlet that refuses the input by throwing has not been exploited.
      writer.println("THREW " + e.getCause().getClass().getName());
    }
    writer.flush();
    return new String(body.toByteArray(), StandardCharsets.UTF_8);
  }

  static String encoded(String value) {
    try {
      return URLEncoder.encode(value, "UTF-8");
    }
    catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  static Object fallback(Class<?> type) {
    if (type == boolean.class) {
      return Boolean.FALSE;
    }
    if (type == int.class || type == long.class || type == short.class || type == byte.class) {
      return type == long.class ? (Object) 0L : (Object) 0;
    }
    return null;
  }

  static HttpServletRequest request(final String name, final String value) {
    final Map<String, Object> attributes = new HashMap<String, Object>();
    final HttpSession session = session();
    // Some cases take the value of the input named after the case, others the name of the
    // first unusual header, or the name of the parameter whose value is the case's name:
    // the value travels both ways.
    final Map<String, String[]> parameters = new java.util.LinkedHashMap<String, String[]>();
    parameters.put(name, new String[] { value });
    parameters.put(value, new String[] { name });
    final Map<String, String> headers = new java.util.TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
    headers.put(name, value);
    headers.put(value, name);
    InvocationHandler handler = new InvocationHandler() {
      public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String m = method.getName();
        String key = args != null && args.length > 0 && args[0] instanceof String ? (String) args[0] : null;
        if (m.equals("getCookies")) {
          return new Cookie[] { new Cookie(name, encoded(value)) };
        }
        if (m.equals("getHeader")) {
          return key == null ? null : headers.get(key);
        }
        if (m.equals("getHeaders")) {
          String header = key == null ? null : headers.get(key);
          return Collections.enumeration(header != null ? Collections.singletonList(header) : Collections.<String>emptyList());
        }
        if (m.equals("getHeaderNames")) {
          return Collections.enumeration(java.util.Arrays.asList(value, name));
        }
        if (m.equals("getParameter")) {
          String[] values = parameters.get(key);
          return values == null ? null : values[0];
        }
        if (m.equals("getParameterValues")) {
          return parameters.get(key);
        }
        if (m.equals("getParameterMap")) {
          return parameters;
        }
        if (m.equals("getParameterNames")) {
          return Collections.enumeration(parameters.keySet());
        }
        if (m.equals("getQueryString")) {
          return name + "=" + encoded(value);
        }
        if (m.equals("getMethod")) {
          return "POST";
        }
        if (m.equals("getCharacterEncoding")) {
          return "UTF-8";
        }
        if (m.equals("getContextPath")) {
          return "/benchmark";
        }
        if (m.equals("getRequestURI")) {
          return "/benchmark/" + name;
        }
        if (m.equals("getRequestURL")) {
          return new StringBuffer("https://localhost:8443/benchmark/" + name);
        }
        if (m.equals("getRemoteAddr") || m.equals("getRemoteHost")) {
          return "127.0.0.1";
        }
        if (m.equals("getSession")) {
          return session;
        }
        if (m.equals("getAttribute")) {
          return attributes.get(key);
        }
        if (m.equals("setAttribute")) {
          attributes.put(key, args[1]);
          return null;
        }
        if (m.equals("getInputStream")) {
          return input();
        }
        if (m.equals("getReader")) {
          return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(new byte[0]), StandardCharsets.UTF_8));
        }
        if (m.equals("toString")) {
          return "SafePatchRequest[" + name + "]";
        }
        return fallback(method.getReturnType());
      }
    };
    return (HttpServletRequest) Proxy.newProxyInstance(WitnessSupport.class.getClassLoader(), new Class<?>[] { HttpServletRequest.class }, handler);
  }

  static HttpSession session() {
    final Map<String, Object> attributes = new HashMap<String, Object>();
    return (HttpSession) Proxy.newProxyInstance(WitnessSupport.class.getClassLoader(), new Class<?>[] { HttpSession.class }, new InvocationHandler() {
      public Object invoke(Object proxy, Method method, Object[] args) {
        String m = method.getName();
        if (m.equals("getAttribute") || m.equals("getValue")) {
          return attributes.get(args[0]);
        }
        if (m.equals("setAttribute") || m.equals("putValue")) {
          attributes.put((String) args[0], args[1]);
          return null;
        }
        if (m.equals("getId")) {
          return "safepatch-session";
        }
        return fallback(method.getReturnType());
      }
    });
  }

  static ServletInputStream input() {
    final ByteArrayInputStream empty = new ByteArrayInputStream(new byte[0]);
    return new ServletInputStream() {
      public int read() {
        return empty.read();
      }

      public boolean isFinished() {
        return true;
      }

      public boolean isReady() {
        return true;
      }

      public void setReadListener(ReadListener listener) {
      }
    };
  }

  static HttpServletResponse response(final PrintWriter writer, final ByteArrayOutputStream body) {
    final ServletOutputStream stream = new ServletOutputStream() {
      public void write(int b) {
        writer.flush();
        body.write(b);
      }

      public boolean isReady() {
        return true;
      }

      public void setWriteListener(WriteListener listener) {
      }
    };
    return (HttpServletResponse) Proxy.newProxyInstance(WitnessSupport.class.getClassLoader(), new Class<?>[] { HttpServletResponse.class },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) {
            String m = method.getName();
            if (m.equals("getWriter")) {
              return writer;
            }
            if (m.equals("getOutputStream")) {
              return stream;
            }
            if (m.equals("getCharacterEncoding")) {
              return "UTF-8";
            }
            return fallback(method.getReturnType());
          }
        });
  }

  // ---- path traversal (CWE-22) ----

  /** Benchmark's file area: user.dir/testfiles/, created if missing. */
  public static File testfiles() {
    File dir = new File(System.getProperty("user.dir"), "testfiles");
    dir.mkdirs();
    return dir;
  }

  /**
   * An empty file area. Some cases answer whether a fixed file exists there, and earlier tests
   * in the same JVM or workspace may have written one: each check starts from nothing.
   */
  static File emptyArea() throws IOException {
    File dir = testfiles();
    File[] entries = dir.listFiles();
    for (File entry : entries == null ? new File[0] : entries) {
      remove(entry);
    }
    return dir;
  }

  static void remove(File file) throws IOException {
    File[] children = file.isDirectory() ? file.listFiles() : null;
    for (File child : children == null ? new File[0] : children) {
      remove(child);
    }
    if (!file.delete() && file.exists()) {
      throw new IOException("cannot clear " + file);
    }
  }

  /**
   * What inputs reaching outside the file area achieved, empty when nothing did. Benchmark
   * cases join the input to the area ("../x"), use it as a path of its own (absolute), or as
   * the directory of a fixed file name ("Test.txt"); each shape is tried.
   */
  public static String traversal(Class<?> servlet, String name) throws Exception {
    return effects(servlet, name, "climb") + effects(servlet, name, "absolute") + effects(servlet, name, "directory");
  }

  /** The climb from a subdirectory of the area ("sub/../../x"); hidden tests only. */
  public static String nested(Class<?> servlet, String name) throws Exception {
    return effects(servlet, name, "nested");
  }

  /**
   * One shape: a secret file is put outside the area; the servlet runs with an input that
   * names it while it exists and again after it is gone. Reading it, writing it, or answering
   * differently depending on whether it exists all count.
   */
  static String effects(Class<?> servlet, String name, String shape) throws Exception {
    String token = "safepatch-" + UUID.randomUUID().toString().replace("-", "");
    File parent = emptyArea().getParentFile();
    // On Linux a climb through a missing directory fails before it escapes.
    new File(testfiles(), "sub").mkdirs();
    File directory = new File(parent, token);
    File outside = shape.equals("directory") ? new File(directory, "Test.txt") : new File(parent, token + ".txt");
    String input = shape.equals("climb") ? "../" + token + ".txt"
        : shape.equals("nested") ? "sub/../../" + token + ".txt"
        : shape.equals("absolute") ? outside.getAbsolutePath()
        : directory.getAbsolutePath();
    String secret = "SECRET-" + token;
    outside.getParentFile().mkdirs();
    Files.write(outside.toPath(), secret.getBytes(StandardCharsets.UTF_8));
    try {
      String withFile = run(servlet, name, input);
      String after = new String(Files.readAllBytes(outside.toPath()), StandardCharsets.UTF_8);
      outside.delete();
      String withoutFile = run(servlet, name, input);
      StringBuilder found = new StringBuilder();
      if (withFile.contains(secret)) {
        found.append(shape).append(": read the file outside; ");
      }
      if (!after.equals(secret) || outside.exists()) {
        found.append(shape).append(": wrote the file outside; ");
      }
      if (!withFile.equals(withoutFile)) {
        found.append(shape).append(": told whether the file outside exists; ");
      }
      return found.toString();
    }
    finally {
      outside.delete();
      directory.delete();
    }
  }

  /** Benign file names inside the area: one the verifier's behaviour test uses, one only hidden tests use. */
  public static final String BENIGN = "safepatch-benign.txt";
  public static final String DOTS = "safepatch..dots.txt";

  /**
   * SHA-256 of what the servlet answers for a benign file inside the area. Behaviour tests
   * compare it with the vulnerable revision's answer, recorded once; only the digest is kept.
   */
  public static String benign(Class<?> servlet, String name, String file) throws Exception {
    File target = new File(emptyArea(), file);
    Files.write(target.toPath(), ("SafePatch benign content of " + file + "\n").getBytes(StandardCharsets.UTF_8));
    try {
      return sha256(run(servlet, name, file));
    }
    finally {
      target.delete();
    }
  }

  static String sha256(String text) throws Exception {
    byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
    StringBuilder hex = new StringBuilder();
    for (byte b : hash) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }

  /** The answer with the input's echoes (raw, URL- and HTML-encoded) replaced: two inputs compare on their effect. */
  static String normalized(String answer, String input) {
    String html = org.owasp.esapi.ESAPI.encoder().encodeForHTML(input);
    return answer.replace(html, "{INPUT}").replace(encoded(input), "{INPUT}").replace(input, "{INPUT}");
  }

  // ---- SQL injection (CWE-89) ----

  private static boolean database;

  /**
   * Benchmark's database as Tomcat would provide it: an HSQLDB server on the loopback address
   * (Spring's data source connects to hsql://localhost) and the JNDI name DatabaseHelper looks up.
   */
  static synchronized void database() throws Exception {
    if (database) {
      return;
    }
    // DatabaseHelper also starts Hibernate, which wants a Bean Validation provider an
    // application server would supply; none is on the test classpath and none is needed here.
    System.setProperty("javax.persistence.validation.mode", "none");
    org.hsqldb.server.Server server = new org.hsqldb.server.Server();
    server.setDatabaseName(0, "benchmarkDataBase");
    server.setDatabasePath(0, "mem:benchmarkDataBase");
    server.setAddress("127.0.0.1");
    server.setSilent(true);
    server.setLogWriter(null);
    server.setErrWriter(null);
    server.start();
    System.setProperty("java.naming.factory.initial", Naming.class.getName());
    database = true;
  }

  /** JNDI with the one name Benchmark needs, java:comp/env/jdbc/BenchmarkDB. */
  public static final class Naming implements javax.naming.spi.InitialContextFactory {
    public javax.naming.Context getInitialContext(java.util.Hashtable<?, ?> environment) {
      final org.hsqldb.jdbc.JDBCDataSource source = new org.hsqldb.jdbc.JDBCDataSource();
      source.setUrl("jdbc:hsqldb:hsql://127.0.0.1/benchmarkDataBase");
      source.setUser("sa");
      source.setPassword("");
      return (javax.naming.Context) Proxy.newProxyInstance(WitnessSupport.class.getClassLoader(), new Class<?>[] { javax.naming.Context.class },
          new InvocationHandler() {
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
              if (method.getName().equals("lookup") && String.valueOf(args[0]).equals("java:comp/env/jdbc/BenchmarkDB")) {
                return source;
              }
              if (method.getName().equals("lookup")) {
                throw new javax.naming.NameNotFoundException(String.valueOf(args[0]));
              }
              return fallback(method.getReturnType());
            }
          });
    }
  }

  /** The servlet's answer to `value` on freshly initialised tables. */
  static String sqlRun(Class<?> servlet, String name, String value) throws Exception {
    database();
    org.owasp.benchmark.helpers.DatabaseHelper.initDataBase();
    return run(servlet, name, value);
  }

  static String differs(Class<?> servlet, String name, String probe, String first, String second) throws Exception {
    String a = normalized(sqlRun(servlet, name, first), first);
    String b = normalized(sqlRun(servlet, name, second), second);
    return a.equals(b) ? "" : probe + ": answers differ; ";
  }

  /**
   * What SQL text built from the input achieved, empty when nothing: a tautology answering
   * otherwise than its false twin, a lone quote answering otherwise than a word, a row the
   * input added, or a procedure call steered by the input. A parameterised query treats each
   * input as a value and answers both twins alike.
   */
  public static String sqlInjection(Class<?> servlet, String name) throws Exception {
    StringBuilder found = new StringBuilder();
    found.append(differs(servlet, name, "tautology", "' OR 'a'='a", "' OR 'a'='b"));
    // A distinctive input: blanking a lone quote would also blank the quotes of Benchmark's own SQL text.
    found.append(differs(servlet, name, "quote", "safepatch'", "safepatch"));
    found.append(differs(servlet, name, "call", "verifyUserPassword('foo','bar')", "verifyUserPassword('foo','nobody')"));
    String user = "SPX" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    sqlRun(servlet, name, "x'),('" + user + "','x");
    java.sql.ResultSet rows = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement()
        .executeQuery("SELECT COUNT(*) FROM USERS WHERE USERNAME = '" + user + "'");
    if (rows.next() && rows.getInt(1) > 0) {
      found.append("insert: the input added a row; ");
    }
    return found.toString();
  }

  /** A comment-terminated tautology; hidden tests only. */
  public static String sqlHidden(Class<?> servlet, String name) throws Exception {
    return differs(servlet, name, "comment tautology", "' OR 1=1 --", "' OR 1=2 --");
  }

  /** SHA-256 of the answer to a benign value on freshly initialised tables. */
  public static String sqlAnswer(Class<?> servlet, String name, String value) throws Exception {
    return sha256(sqlRun(servlet, name, value));
  }

  // ---- OS command injection (CWE-78) ----

  /**
   * Whether a shell ran a command of the input's: the input asks for an arithmetic expansion
   * that only a shell turns into "42", either after a separator or as the variable Benchmark's
   * script evaluates (insecureCmd.sh runs eval $FOO). Echoing the input literally shows "$((6*7))".
   */
  public static String commandInjection(Class<?> servlet, String name) throws Exception {
    return command(servlet, name, "separator", "x; echo SPX$((6*7))") + command(servlet, name, "variable", "FOO=echo SPX$((6*7))");
  }

  /** A pipe instead of a separator; hidden tests only. */
  public static String commandHidden(Class<?> servlet, String name) throws Exception {
    return command(servlet, name, "pipe", "x | echo SPX$((6*7))");
  }

  static String command(Class<?> servlet, String name, String shape, String input) throws Exception {
    String token = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    return run(servlet, name, input + token).contains("SPX42" + token) ? shape + ": a shell ran the input; " : "";
  }

  /** SHA-256 of the answer to a benign value. */
  public static String commandAnswer(Class<?> servlet, String name, String value) throws Exception {
    return sha256(run(servlet, name, value));
  }
}
