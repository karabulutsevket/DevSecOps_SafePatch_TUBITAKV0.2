package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest00196 (generated, MIT); the verifier never runs it. */
class SafePatchHidden00196 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("1bc8042b44b6f246cbc911c90aa09ba01c4fa595ca4ab308594143088a2728cf", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00196.class, "BenchmarkTest00196", "User01"), "HIDDEN_BEHAVIOR");
  }
}
