package com.b3xal.headeranalyzer.persistence;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ExternalEvidenceArchiveTest {
    @TempDir Path temporaryDirectory;

    @Test
    void roundTripsBinaryEvidenceWithoutExposingMutableArrays() throws Exception {
        ExternalEvidenceArchive archive = new ExternalEvidenceArchive();
        byte[] request = new byte[]{'G', 'E', 'T', 0, (byte) 0xff};
        byte[] response = new byte[]{'H', 'T', 'T', 'P', '/', '2', 0, 1, 2, (byte) 0xfe};
        ExternalEvidenceArchive.Evidence original = evidence(request, response);

        ExternalEvidenceArchive.ArchiveReference reference = archive.write(temporaryDirectory, original);
        request[0] = 'X';
        response[0] = 'X';

        ExternalEvidenceArchive.Evidence restored = archive.read(temporaryDirectory, reference);
        assertEquals("project-1", restored.projectId());
        assertEquals("row-1", restored.resultId());
        assertEquals("https://example.test/path?q=1", restored.url());
        assertEquals("example.test", restored.serviceHost());
        assertEquals(443, restored.servicePort());
        assertTrue(restored.secure());
        assertArrayEquals(new byte[]{'G', 'E', 'T', 0, (byte) 0xff}, restored.requestBytes());
        assertArrayEquals(new byte[]{'H', 'T', 'T', 'P', '/', '2', 0, 1, 2, (byte) 0xfe}, restored.responseBytes());

        byte[] escaped = restored.requestBytes();
        escaped[0] = 'X';
        assertEquals('G', restored.requestBytes()[0]);
    }

    @Test
    void identicalEvidenceIsStoredOnlyOnce() throws Exception {
        ExternalEvidenceArchive archive = new ExternalEvidenceArchive();
        ExternalEvidenceArchive.ArchiveReference first = archive.write(temporaryDirectory,
                evidence("request".getBytes(), "response".getBytes()));
        ExternalEvidenceArchive.ArchiveReference second = archive.write(temporaryDirectory,
                evidence("request".getBytes(), "response".getBytes()));

        assertEquals(first, second);
        try (var files = Files.walk(temporaryDirectory)) {
            assertEquals(1, files.filter(p -> p.getFileName().toString().endsWith(".qev.gz")).count());
        }
        try (var files = Files.walk(temporaryDirectory)) {
            assertEquals(0, files.filter(p -> p.getFileName().toString().endsWith(".tmp")).count());
        }
    }

    @Test
    void rejectsTruncatedOrCorruptedObjectsInsteadOfReturningPartialEvidence() throws Exception {
        ExternalEvidenceArchive archive = new ExternalEvidenceArchive();
        ExternalEvidenceArchive.ArchiveReference reference = archive.write(temporaryDirectory,
                evidence("request".getBytes(), "response".getBytes()));
        Path object = objectPath(reference);
        byte[] bytes = Files.readAllBytes(object);
        Files.write(object, Arrays.copyOf(bytes, bytes.length - 3));

        assertThrows(IOException.class, () -> archive.read(temporaryDirectory, reference));
    }

    @Test
    void refusesInvalidReferencesAndDoesNotEscapeTheArchiveDirectory() {
        assertThrows(IllegalArgumentException.class,
                () -> new ExternalEvidenceArchive.ArchiveReference("../../outside", 1));
        assertThrows(IllegalArgumentException.class,
                () -> new ExternalEvidenceArchive.Evidence("p", "r", "u", "h", 0, true,
                        new byte[0], new byte[0]));
    }

    @Test
    void concurrentWritersPublishOneCompleteObject() throws Exception {
        ExternalEvidenceArchive archive = new ExternalEvidenceArchive();
        ExternalEvidenceArchive.Evidence evidence = evidence("request".getBytes(), "response".getBytes());
        var workers = Executors.newFixedThreadPool(8);
        try {
            List<Callable<ExternalEvidenceArchive.ArchiveReference>> jobs = java.util.stream.IntStream.range(0, 32)
                    .<Callable<ExternalEvidenceArchive.ArchiveReference>>mapToObj(i ->
                            () -> archive.write(temporaryDirectory, evidence)).toList();
            List<ExternalEvidenceArchive.ArchiveReference> references = workers.invokeAll(jobs).stream()
                    .map(future -> {
                        try { return future.get(); }
                        catch (Exception ex) { throw new AssertionError(ex); }
                    }).toList();
            assertEquals(1, references.stream().distinct().count());
            assertDoesNotThrow(() -> archive.read(temporaryDirectory, references.get(0)));
        } finally {
            workers.shutdownNow();
        }
        try (var files = Files.walk(temporaryDirectory)) {
            assertEquals(1, files.filter(p -> p.getFileName().toString().endsWith(".qev.gz")).count());
        }
    }

    @Test
    void doesNotAcceptAnAlreadyExistingCorruptObjectAsAValidArchive() throws Exception {
        ExternalEvidenceArchive writer = new ExternalEvidenceArchive();
        ExternalEvidenceArchive.Evidence evidence = evidence("request".getBytes(), "response".getBytes());
        ExternalEvidenceArchive.ArchiveReference reference = writer.write(temporaryDirectory, evidence);
        Path object = objectPath(reference);
        byte[] bytes = Files.readAllBytes(object);
        bytes[bytes.length / 2] ^= 1;
        Files.write(object, bytes);

        ExternalEvidenceArchive freshProcess = new ExternalEvidenceArchive();
        assertThrows(IOException.class, () -> freshProcess.write(temporaryDirectory, evidence));
    }

    @Test
    void clearingTheMemoryCacheDropsSensitiveEvidenceImmediately() throws Exception {
        ExternalEvidenceArchive archive = new ExternalEvidenceArchive();
        ExternalEvidenceArchive.ArchiveReference reference = archive.write(temporaryDirectory,
                evidence("request".getBytes(), "response".getBytes()));
        assertDoesNotThrow(() -> archive.read(temporaryDirectory, reference));
        Files.delete(objectPath(reference));
        // This succeeds only from the bounded decoded cache, proving the next assertion checks
        // cache eviction rather than disk parsing.
        assertDoesNotThrow(() -> archive.read(temporaryDirectory, reference));

        archive.clearMemoryCache();

        assertThrows(IOException.class, () -> archive.read(temporaryDirectory, reference));
    }

    @Test
    void handlesARepresentativeLargeBinaryResponseWithoutPartialOutput() throws Exception {
        byte[] response = new byte[4 * 1024 * 1024];
        new Random(42).nextBytes(response); // deliberately incompressible enough to exercise real I/O
        ExternalEvidenceArchive archive = new ExternalEvidenceArchive();

        ExternalEvidenceArchive.ArchiveReference reference = archive.write(temporaryDirectory,
                evidence("GET /large HTTP/1.1\r\n\r\n".getBytes(), response));
        ExternalEvidenceArchive.Evidence restored = archive.read(temporaryDirectory, reference);

        assertArrayEquals(response, restored.responseBytes());
        try (var files = Files.walk(temporaryDirectory)) {
            assertEquals(0, files.filter(p -> p.getFileName().toString().endsWith(".tmp")).count());
        }
    }

    private ExternalEvidenceArchive.Evidence evidence(byte[] request, byte[] response) {
        return new ExternalEvidenceArchive.Evidence("project-1", "row-1", "https://example.test/path?q=1",
                "example.test", 443, true, request, response);
    }

    private Path objectPath(ExternalEvidenceArchive.ArchiveReference reference) {
        return temporaryDirectory.resolve("objects").resolve(reference.objectId().substring(0, 2))
                .resolve(reference.objectId() + ".qev.gz");
    }
}
