package com.vitalsshield.server.arch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * DECISIONS #54: the WebAuthn library's Jackson 2 stays inside the library. No main source file may import a
 * com.fasterxml.jackson package other than the annotations, which Jackson 3 itself uses.
 */
class NoJackson2ImportsTest {

    @Test
    void noApplicationClassImportsJackson2() throws IOException {
        Path root = Path.of(System.getProperty("vitalsshield.repoRoot", "..")).resolve("server/src/main/java");
        List<String> offenders;
        try (Stream<Path> files = Files.walk(root)) {
            offenders = files.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> {
                        try {
                            return Files.readAllLines(p).stream().anyMatch(l -> l.startsWith("import com.fasterxml.jackson")
                                    && !l.startsWith("import com.fasterxml.jackson.annotation."));
                        } catch (IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    })
                    .map(Path::toString).toList();
        }
        assertThat(root).isDirectory();
        assertThat(offenders).isEmpty();
    }
}
