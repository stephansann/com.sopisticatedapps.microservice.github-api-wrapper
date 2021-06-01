package com.sopisticatedapps.microservice.githubapiwrapper;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpResponse;
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

        HttpResponse<String> tmpResponse = client.latestReleaseTag(
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver");
        assertEquals("v2.2.0", tmpResponse.body());
    }

    @Test
    void testLatestReleaseTag_with_exception() {

        HttpClientResponseException tmpException = assertThrows(HttpClientResponseException.class, (() ->
                client.latestReleaseTag(
                        "Document-Archiver", "../../../../../../../etc/passwd")));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, tmpException.getResponse().getStatus());
    }

    @Test
    void testLatestReleaseAssetDownloadUrl() {

        HttpResponse<String> tmpResponse = client.latestReleaseAssetDownloadUrl(
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver", null, null);
        assertEquals("https://github.com/Document-Archiver/com.sophisticatedapps.archiving.document-archiver/releases/download/v2.2.0/DocumentArchiver_macos_2_2_0.dmg",
                tmpResponse.body());

        tmpResponse = client.latestReleaseAssetDownloadUrl("" +
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver", "unix", null);
        assertEquals("https://github.com/Document-Archiver/com.sophisticatedapps.archiving.document-archiver/releases/download/v2.2.0/DocumentArchiver_unix_2_2_0.sh",
                tmpResponse.body());
    }


    //@Test
    void xtestLatestReleaseAssetDownloadUrl_with_redirect() {

        HttpResponse<String> tmpResponse= client.latestReleaseAssetDownloadUrl("" +
                "Document-Archiver", "com.sophisticatedapps.archiving.document-archiver", "unix", "true");
        assertEquals(HttpStatus.TEMPORARY_REDIRECT, tmpResponse.getStatus());
        assertEquals("gg", tmpResponse.getHeaders().get("Location"));
    }

}
