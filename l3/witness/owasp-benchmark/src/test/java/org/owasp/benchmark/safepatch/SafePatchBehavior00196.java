package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00196 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00196 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("1bc8042b44b6f246cbc911c90aa09ba01c4fa595ca4ab308594143088a2728cf", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00196.class, "BenchmarkTest00196", "bar"), "BEHAVIOR_REGRESSION");
  }
}
