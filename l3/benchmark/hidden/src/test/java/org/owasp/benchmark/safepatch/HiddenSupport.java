package org.owasp.benchmark.safepatch;

import java.util.regex.Pattern;

/**
 * SafePatch L3 hidden-test support for OWASP Benchmark cases (written by SafePatch, MIT).
 *
 * Hidden tests only: it travels with them (l3/hidden/owasp-benchmark), never in the
 * evaluation repository the verifier builds. Benchmark's SQL servlets write the query they ran
 * into some answers ("No results returned for query: ...", "Update complete for query: ...",
 * "For query: ..."). A parameterised query necessarily reads otherwise there, so a benign
 * answer is compared with that text replaced; the rows, messages and refusals around it still
 * count. Java 8 source level.
 */
public final class HiddenSupport {

  // The echo ends where Benchmark's markup or the line does; ESAPI's HTML encoding leaves no '<' in it.
  private static final Pattern QUERY_ECHO = Pattern.compile("(?i)(query: )[^<\\r\\n]*");

  private HiddenSupport() {
  }

  /** The answer with the query text Benchmark echoes replaced by {QUERY}. */
  static String withoutQuery(String answer) {
    return QUERY_ECHO.matcher(answer).replaceAll("$1{QUERY}");
  }

  /** SHA-256 of the answer to a benign value on freshly initialised tables, the echoed query aside. */
  public static String sqlAnswer(Class<?> servlet, String name, String value) throws Exception {
    return WitnessSupport.sha256(withoutQuery(WitnessSupport.sqlRun(servlet, name, value)));
  }
}
