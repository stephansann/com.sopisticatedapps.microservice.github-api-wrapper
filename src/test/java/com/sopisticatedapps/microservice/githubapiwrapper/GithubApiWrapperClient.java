package com.sopisticatedapps.microservice.githubapiwrapper;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.annotation.Client;

import javax.validation.constraints.NotBlank;

@Client("/githubApiWrapper")
public interface GithubApiWrapperClient {

    @Get("/{anOrganization}/{aRepository}/latestReleaseTag")
    HttpResponse<String> latestReleaseTag(@NotBlank String anOrganization, @NotBlank String aRepository);

    @Get("/{anOrganization}/{aRepository}/latestReleaseAssetDownloadUrl{?aRecognizer,aRedirectToUrl}")
    HttpResponse<String> latestReleaseAssetDownloadUrl(@NotBlank String anOrganization, @NotBlank String aRepository,
                                                       @Nullable String aRecognizer, @Nullable String aRedirectToUrl);

}
