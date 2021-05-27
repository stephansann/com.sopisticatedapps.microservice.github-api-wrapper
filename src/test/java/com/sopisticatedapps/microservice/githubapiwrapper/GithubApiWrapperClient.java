package com.sopisticatedapps.microservice.githubapiwrapper;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.annotation.Client;
import io.reactivex.Single;

import javax.validation.constraints.NotBlank;

@Client("/githubApiWrapper")
public interface GithubApiWrapperClient {

    @Get("/{aRepository}/latestReleaseTag")
    Single<String> latestReleaseTag(@NotBlank String aRepository);

    @Get("/{aRepository}/latestReleaseAssetDownloadUrl{?aRecognizer}")
    Single<String> latestReleaseAssetDownloadUrl(@NotBlank String aRepository, @Nullable String aRecognizer);

}
