package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01315 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01315 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("a7d6a5b482d46ce516afed30d5021a27002c11a8d23a746bce857a3a8fd3c5d8", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01315.class, "BenchmarkTest01315", "User01"), "HIDDEN_BEHAVIOR");
  }
}
