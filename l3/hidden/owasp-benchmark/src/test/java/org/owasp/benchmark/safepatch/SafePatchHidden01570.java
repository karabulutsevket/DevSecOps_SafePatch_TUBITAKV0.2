package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01570 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01570 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("0b90acfb6406d310abcedb3cdeb3ec18c09877f2bd83dbb77f3a00be6be4a377", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01570.class, "BenchmarkTest01570", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR");
  }
}
