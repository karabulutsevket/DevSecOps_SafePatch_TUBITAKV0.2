package org.eclipse.rdf4j.common.io;

import static org.junit.Assert.assertFalse;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * SafePatch L3 security witness for VUL4J-43 (written by SafePatch, MIT). The Vul4J
 * proof-of-vulnerability also asserts the human fix's exception type and message; this
 * witness checks only the effect: an entry that climbs out of the destination is not written.
 */
public class SafePatchZipSlipWitnessTest {

	@Rule
	public TemporaryFolder dir = new TemporaryFolder();

	static File zip(File file, String... names) throws IOException {
		try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(file))) {
			for (String name : names) {
				out.putNextEntry(new ZipEntry(name));
				if (!name.endsWith("/")) {
					out.write("content".getBytes("UTF-8"));
				}
				out.closeEntry();
			}
		}
		return file;
	}

	@Test
	public void entryOutsideTheDestinationIsNotWritten() throws IOException {
		File destination = dir.newFolder("extract");
		try (ZipFile zip = new ZipFile(zip(dir.newFile("slip.zip"), "hello/../../world.txt"))) {
			ZipUtil.extract(zip, destination);
		}
		catch (IOException | RuntimeException expected) {
			// refusing the entry is fine; writing outside is not
		}
		assertFalse("PATH_TRAVERSAL_REGRESSION", new File(dir.getRoot(), "world.txt").exists());
	}
}
