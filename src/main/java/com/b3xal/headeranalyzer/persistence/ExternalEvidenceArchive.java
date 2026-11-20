package com.b3xal.headeranalyzer.persistence;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Dependency-free, on-disk store for complete finding evidence.
 *
 * <p>This class deliberately has no Montoya, UI, settings, queue or thread dependency. It is
 * the small, testable persistence primitive beneath the optional external-evidence feature. An
 * object is immutable, gzip-compressed, versioned and content addressed by its SHA-256 digest.
 * Writers publish only after a completed temporary file has been atomically moved into place.
 * Callers decide when and where work is scheduled; this class must never be called from an HTTP
 * callback or the Swing event thread.</p>
 */
public final class ExternalEvidenceArchive {
    private static final int MAGIC = 0x51455631; // "QEV1"
    private static final int FORMAT_VERSION = 1;
    private static final String OBJECTS_DIRECTORY = "objects";
    private static final String EXTENSION = ".qev.gz";
    private static final Pattern OBJECT_ID = Pattern.compile("[0-9a-f]{64}");

    // Archive files are untrusted whenever they are reopened. Bounds prevent a corrupt or
    // malicious file from turning its declared length into an unbounded allocation.
    private static final int MAX_TEXT_BYTES = 1_048_576;
    private static final int MAX_MESSAGE_BYTES = 256 * 1024 * 1024;
    private static final int VERIFIED_OBJECT_CACHE_SIZE = 512;
    // Reopening a project can contain thousands of responses. Keep only a small LRU of decoded
    // messages: warm-up makes normal selection instant without turning the disk archive into an
    // unbounded heap archive.
    private static final long DECODED_EVIDENCE_CACHE_BYTES = 64L * 1024 * 1024;

    // Re-reading and hashing an object for every repeated response would defeat deduplication on
    // common assets. Verify each pre-existing object once per bounded LRU window; a newly written
    // object is known-good because it is published only after its write completed and was forced.
    private final Map<Path, Boolean> verifiedObjects = new LinkedHashMap<>(64, .75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Path, Boolean> eldest) {
            return size() > VERIFIED_OBJECT_CACHE_SIZE;
        }
    };
    private final Map<Path, CachedEvidence> decodedEvidence = new LinkedHashMap<>(32, .75f, true);
    private long decodedEvidenceBytes;

    private record CachedEvidence(Evidence evidence, long bytes) { }

    /** Immutable exchange payload. Byte arrays are copied at both API boundaries. */
    public record Evidence(String projectId, String resultId, String url, String serviceHost,
                           int servicePort, boolean secure, byte[] requestBytes, byte[] responseBytes) {
        public Evidence {
            projectId = required(projectId, "projectId");
            resultId = required(resultId, "resultId");
            url = required(url, "url");
            serviceHost = required(serviceHost, "serviceHost");
            if (servicePort < 1 || servicePort > 65_535) {
                throw new IllegalArgumentException("servicePort must be between 1 and 65535");
            }
            requestBytes = copyAndCheck(requestBytes, "requestBytes");
            responseBytes = copyAndCheck(responseBytes, "responseBytes");
            checkText(projectId, "projectId");
            checkText(resultId, "resultId");
            checkText(url, "url");
            checkText(serviceHost, "serviceHost");
        }

        @Override public byte[] requestBytes() { return requestBytes.clone(); }
        @Override public byte[] responseBytes() { return responseBytes.clone(); }
    }

    /** Compact, project-persistable reference. It never embeds HTTP content. */
    public record ArchiveReference(String objectId, long uncompressedBytes) {
        public ArchiveReference {
            if (objectId == null || !OBJECT_ID.matcher(objectId).matches()) {
                throw new IllegalArgumentException("Invalid external evidence object id");
            }
            if (uncompressedBytes < 0) throw new IllegalArgumentException("Negative evidence size");
        }
    }

    /** Writes an evidence object once. An identical object is safely reused without duplication. */
    public ArchiveReference write(Path projectArchiveDirectory, Evidence evidence) throws IOException {
        Objects.requireNonNull(projectArchiveDirectory, "projectArchiveDirectory");
        Objects.requireNonNull(evidence, "evidence");
        byte[] digest = digest(evidence);
        String objectId = HexFormat.of().formatHex(digest);
        long size = encodedSize(evidence);
        Path objects = objectsDirectory(projectArchiveDirectory);
        Files.createDirectories(objects);
        Path target = objectPath(objects, objectId);
        Files.createDirectories(target.getParent());
        ArchiveReference reference = new ArchiveReference(objectId, size);
        if (Files.exists(target)) {
            verifyExisting(projectArchiveDirectory, target, reference);
            return reference;
        }

        Path temporary = Files.createTempFile(objects, ".quimera-", ".tmp");
        boolean published = false;
        try {
            writeFile(temporary, evidence);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
                published = true;
            } catch (AtomicMoveNotSupportedException unsupported) {
                // Same-directory rename is still atomic on the supported local filesystems even
                // where Java cannot request ATOMIC_MOVE. Never replace an existing object.
                try {
                    Files.move(temporary, target);
                    published = true;
                } catch (java.nio.file.FileAlreadyExistsException duplicate) {
                    verifyExisting(projectArchiveDirectory, target, reference);
                    published = true;
                }
            } catch (java.nio.file.FileAlreadyExistsException duplicate) {
                // A concurrent writer completed the exact same content-addressed object first.
                verifyExisting(projectArchiveDirectory, target, reference);
                published = true;
            }
            markVerified(target);
            return reference;
        } finally {
            if (!published || Files.exists(temporary)) Files.deleteIfExists(temporary);
        }
    }

    /** Reads and verifies one evidence object. A checksum mismatch is always an IOException. */
    public Evidence read(Path projectArchiveDirectory, ArchiveReference reference) throws IOException {
        Objects.requireNonNull(projectArchiveDirectory, "projectArchiveDirectory");
        Objects.requireNonNull(reference, "reference");
        Path path = objectPath(objectsDirectory(projectArchiveDirectory), reference.objectId());
        synchronized (decodedEvidence) {
            CachedEvidence cached = decodedEvidence.get(path);
            if (cached != null) return cached.evidence();
        }
        Evidence evidence;
        try (var input = new DataInputStream(new GZIPInputStream(Files.newInputStream(path)))) {
            if (input.readInt() != MAGIC) throw new IOException("Not a Quimera evidence object");
            int version = input.readInt();
            if (version != FORMAT_VERSION) throw new IOException("Unsupported evidence format version: " + version);
            evidence = new Evidence(readText(input), readText(input), readText(input), readText(input),
                    input.readInt(), input.readBoolean(), readBytes(input), readBytes(input));
            if (input.read() != -1) throw new IOException("Unexpected trailing evidence data");
        }
        String actual = HexFormat.of().formatHex(digest(evidence));
        if (!actual.equals(reference.objectId())) throw new IOException("Evidence checksum mismatch");
        if (encodedSize(evidence) != reference.uncompressedBytes()) {
            throw new IOException("Evidence size metadata mismatch");
        }
        markVerified(path);
        cacheDecoded(path, evidence, reference.uncompressedBytes());
        return evidence;
    }

    public boolean exists(Path projectArchiveDirectory, ArchiveReference reference) {
        if (projectArchiveDirectory == null || reference == null) return false;
        return Files.isRegularFile(objectPath(objectsDirectory(projectArchiveDirectory), reference.objectId()));
    }

    /** Discards decoded sensitive material retained solely as a performance cache. */
    public void clearMemoryCache() {
        synchronized (decodedEvidence) {
            decodedEvidence.clear();
            decodedEvidenceBytes = 0;
        }
        synchronized (verifiedObjects) {
            verifiedObjects.clear();
        }
    }

    private static Path objectsDirectory(Path projectArchiveDirectory) {
        return projectArchiveDirectory.toAbsolutePath().normalize().resolve(OBJECTS_DIRECTORY);
    }

    private static Path objectPath(Path objects, String objectId) {
        return objects.resolve(objectId.substring(0, 2)).resolve(objectId + EXTENSION);
    }

    private void verifyExisting(Path projectArchiveDirectory, Path target, ArchiveReference reference)
            throws IOException {
        if (!Files.isRegularFile(target)) throw new IOException("Evidence object path is not a regular file");
        synchronized (verifiedObjects) {
            if (verifiedObjects.containsKey(target)) return;
        }
        read(projectArchiveDirectory, reference);
    }

    private void markVerified(Path path) {
        synchronized (verifiedObjects) {
            verifiedObjects.put(path, Boolean.TRUE);
        }
    }

    private void cacheDecoded(Path path, Evidence evidence, long bytes) {
        // One giant response must never evict the whole cache only to remain resident itself.
        if (bytes > DECODED_EVIDENCE_CACHE_BYTES) return;
        synchronized (decodedEvidence) {
            CachedEvidence previous = decodedEvidence.put(path, new CachedEvidence(evidence, bytes));
            if (previous != null) decodedEvidenceBytes -= previous.bytes();
            decodedEvidenceBytes += bytes;
            var iterator = decodedEvidence.entrySet().iterator();
            while (decodedEvidenceBytes > DECODED_EVIDENCE_CACHE_BYTES && iterator.hasNext()) {
                CachedEvidence evicted = iterator.next().getValue();
                decodedEvidenceBytes -= evicted.bytes();
                iterator.remove();
            }
        }
    }

    private static void writeFile(Path temporary, Evidence evidence) throws IOException {
        // Keep the channel open until after gzip.finish(), then force the completed temporary
        // object before publishing it. The wrapper deliberately does not close the channel early.
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            OutputStream raw = new NonClosingOutputStream(Channels.newOutputStream(channel));
            try (GZIPOutputStream gzip = new GZIPOutputStream(raw);
                 DataOutputStream output = new DataOutputStream(gzip)) {
                output.writeInt(MAGIC);
                output.writeInt(FORMAT_VERSION);
                writeText(output, evidence.projectId());
                writeText(output, evidence.resultId());
                writeText(output, evidence.url());
                writeText(output, evidence.serviceHost());
                output.writeInt(evidence.servicePort());
                output.writeBoolean(evidence.secure());
                writeBytes(output, evidence.requestBytes());
                writeBytes(output, evidence.responseBytes());
            }
            channel.force(true);
        }
    }

    private static byte[] digest(Evidence evidence) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            updateInt(digest, MAGIC);
            updateInt(digest, FORMAT_VERSION);
            updateText(digest, evidence.projectId());
            updateText(digest, evidence.resultId());
            updateText(digest, evidence.url());
            updateText(digest, evidence.serviceHost());
            updateInt(digest, evidence.servicePort());
            digest.update((byte) (evidence.secure() ? 1 : 0));
            updateBytes(digest, evidence.requestBytes());
            updateBytes(digest, evidence.responseBytes());
            return digest.digest();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required by the JRE", impossible);
        }
    }

    private static long encodedSize(Evidence evidence) {
        return 8L + textSize(evidence.projectId()) + textSize(evidence.resultId()) + textSize(evidence.url())
                + textSize(evidence.serviceHost()) + 5L + 4L + evidence.requestBytes().length
                + 4L + evidence.responseBytes().length;
    }

    private static long textSize(String text) {
        return 4L + text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static void writeText(DataOutputStream output, String value) throws IOException {
        writeBytes(output, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static String readText(DataInputStream input) throws IOException {
        return new String(readBytes(input, MAX_TEXT_BYTES), StandardCharsets.UTF_8);
    }

    private static byte[] readBytes(DataInputStream input) throws IOException {
        return readBytes(input, MAX_MESSAGE_BYTES);
    }

    private static byte[] readBytes(DataInputStream input, int limit) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > limit) throw new IOException("Invalid evidence field length");
        byte[] value = new byte[length];
        input.readFully(value);
        return value;
    }

    private static void updateText(MessageDigest digest, String value) {
        updateBytes(digest, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void updateBytes(MessageDigest digest, byte[] value) {
        updateInt(digest, value.length);
        digest.update(value);
    }

    private static void updateInt(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    private static byte[] copyAndCheck(byte[] value, String name) {
        if (value == null) throw new IllegalArgumentException(name + " is required");
        if (value.length > MAX_MESSAGE_BYTES) throw new IllegalArgumentException(name + " exceeds archive limit");
        return value.clone();
    }

    private static void checkText(String value, String name) {
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException(name + " exceeds archive limit");
        }
    }

    /** Lets gzip finish without closing the FileChannel before {@link FileChannel#force(boolean)}. */
    private static final class NonClosingOutputStream extends FilterOutputStream {
        NonClosingOutputStream(OutputStream output) { super(output); }
        @Override public void close() throws IOException { flush(); }
    }
}
