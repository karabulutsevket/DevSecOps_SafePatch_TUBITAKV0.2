package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00306 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00306 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("820ae69b5cba45217161d4fb155874f43521ce931edcaac4b1690c056b608713", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest00306.class, "BenchmarkTest00306", "safepatch"), "BEHAVIOR_REGRESSION");
  }
}
