package org.eclipse.rdf4j.common.io;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.zip.ZipFile;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * SafePatch L3 hidden evaluation test for VUL4J-43 (written by SafePatch, MIT). The verifier
 * never runs it. The upstream fix checks every entry before deciding between directory and
 * file; a fix in the file branch only passes the witness and creates directories outside.
 * Legitimate nested names with dots must still extract.
 */
public class SafePatchHiddenTraversalTest {

	@Rule
	public TemporaryFolder dir = new TemporaryFolder();

	private void extract(File archive, File destination) {
		try (ZipFile zip = new ZipFile(archive)) {
			ZipUtil.extract(zip, destination);
		}
		catch (IOException | RuntimeException expected) {
			// refusing the archive is fine; writing outside is not
		}
	}

	@Test
	public void directoryEntryOutsideTheDestinationIsNotCreated() throws IOException {
		extract(SafePatchZipSlipWitnessTest.zip(dir.newFile("dir.zip"), "a/../../evil-dir/"), dir.newFolder("extract"));
		assertFalse("HIDDEN_TRAVERSAL_DIRECTORY", new File(dir.getRoot(), "evil-dir").exists());
	}

	@Test
	public void deepEntryOutsideTheDestinationIsNotWritten() throws IOException {
		extract(SafePatchZipSlipWitnessTest.zip(dir.newFile("deep.zip"), "../../../evil.txt"), dir.newFolder("a", "b", "extract"));
		assertFalse("HIDDEN_TRAVERSAL_DEEP", new File(dir.getRoot(), "evil.txt").exists());
	}

	@Test
	public void namesWithDotsInsideTheDestinationStillExtract() throws IOException {
		File destination = dir.newFolder("extract");
		try (ZipFile zip = new ZipFile(SafePatchZipSlipWitnessTest.zip(dir.newFile("ok.zip"), "sub/", "sub/a..b.txt", "..hidden.txt"))) {
			ZipUtil.extract(zip, destination);
		}
		assertTrue("HIDDEN_BEHAVIOR_DOTS", new File(destination, "sub/a..b.txt").isFile());
		assertTrue("HIDDEN_BEHAVIOR_DOTS", new File(destination, "..hidden.txt").isFile());
	}
}
