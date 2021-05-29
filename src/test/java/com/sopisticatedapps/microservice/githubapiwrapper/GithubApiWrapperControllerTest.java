package com.sopisticatedapps.microservice.githubapiwrapper;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GithubApiWrapperControllerTest {

    private static EmbeddedServer server;
    private static GithubApiWrapperClient client;

    @BeforeAll
    public static void setup() {

        server = ApplicationContext.run(EmbeddedServer.class);
        client = server.getApplicationContext().getBean(GithubApiWrapperClient.class);
    }

    @AfterAll
    public static void cleanup() {

        server.stop();
    }

    @Test
    void latestReleaseTag() {

        String tmpResponse = client.latestReleaseTag(
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver").blockingGet();
        assertEquals("v2.1.0", tmpResponse);
    }

    @Test
    void latestReleaseTag_with_exception() {

        HttpClientResponseException tmpException = assertThrows(HttpClientResponseException.class, (() ->
                client.latestReleaseTag(
                        "Document-Archiver", "../../../../../../../etc/passwd").blockingGet()));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, tmpException.getResponse().getStatus());
    }

    @Test
    void latestReleaseAssetDownloadUrl() {

        String tmpResponse = client.latestReleaseAssetDownloadUrl(
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver", null).blockingGet();
        assertEquals("https://github.com/Document-Archiver/com.sophisticatedapps.archiving.document-archiver/releases/download/v2.1.0/DocumentArchiver_macos_2_1_0.dmg", tmpResponse);

        tmpResponse = client.latestReleaseAssetDownloadUrl("" +
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver", "unix").blockingGet();
        assertEquals("https://github.com/Document-Archiver/com.sophisticatedapps.archiving.document-archiver/releases/download/v2.1.0/DocumentArchiver_unix_2_1_0.sh", tmpResponse);
    }

}
