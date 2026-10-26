package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02518 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02518 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("820ae69b5cba45217161d4fb155874f43521ce931edcaac4b1690c056b608713", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest02518.class, "BenchmarkTest02518", "hello world"), "HIDDEN_BEHAVIOR");
  }
}
