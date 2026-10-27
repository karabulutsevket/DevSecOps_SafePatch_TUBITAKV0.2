/*
 * SafePatch sandbox test (MIT). Hostile on purpose (ROADMAP.md week 8): it never ends. The runner
 * must stop it at the descriptor's time limit and remove its container.
 */
package demo;

import org.junit.jupiter.api.Test;

class HangTest {

    @Test
    void neverEnds() throws Exception {
        Thread.sleep(3_600_000);
    }
}
