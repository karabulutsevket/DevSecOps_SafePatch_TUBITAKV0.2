package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01620 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01620 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("9589277d12af61ade72f3ef6f0476b5c099f71585e24babb3f5ceef748e1fbd8", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01620.class, "BenchmarkTest01620", "User01"), "HIDDEN_BEHAVIOR");
  }
}
