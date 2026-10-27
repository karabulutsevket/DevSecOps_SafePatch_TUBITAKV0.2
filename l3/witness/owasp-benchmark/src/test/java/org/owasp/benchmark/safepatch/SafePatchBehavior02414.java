package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02414 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior02414 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("1ef3ead44bead11dc6cb75212c979feee9981a49a01f805bc0b14f783407a42b", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest02414.class, "BenchmarkTest02414", "safepatch"), "BEHAVIOR_REGRESSION");
  }
}
