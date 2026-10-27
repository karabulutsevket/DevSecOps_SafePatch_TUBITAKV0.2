package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest00331 (generated, MIT); the verifier never runs it. */
class SafePatchHidden00331 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("61e2ea576c9e506a24575511dd8fd6265c5038f7c0ee97d59a73f40368f04492", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00331.class, "BenchmarkTest00331", "User01"), "HIDDEN_BEHAVIOR");
  }
}
