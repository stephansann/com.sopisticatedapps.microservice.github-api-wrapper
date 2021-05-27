package com.sopisticatedapps.microservice.githubapiwrapper;

import com.republicate.json.Json;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Controller("/githubApiWrapper")
public class GithubApiWrapperController {

    @Get("/{aRepository}/latestReleaseTag")
    public String latestReleaseTag(@NotBlank String aRepository) {

        try {

            URL tmpURL = new URL("https://api.github.com/repos/" + aRepository + "/releases/latest");

            try (InputStream tmpInputStream = tmpURL.openStream()) {

                Json tmpJsonContainer = Json.parse(new String(tmpInputStream.readAllBytes(), StandardCharsets.UTF_8));
                Json.Object tmpJsonObject = tmpJsonContainer.asObject();

                return tmpJsonObject.get("tag_name").toString();
            }
        }
        catch (IOException e) {

            return ("Exception: " + e.getMessage());
        }
    }

    @Get("/{aRepository}/latestReleaseAssetDownloadUrl{?aRecognizer}")
    public String latestReleaseAssetDownloadUrl(@NotBlank String aRepository, @Nullable String aRecognizer) {

        try {

            URL tmpURL = new URL("https://api.github.com/repos/" + aRepository + "/releases/latest");

            try (InputStream tmpInputStream = tmpURL.openStream()) {

                Json tmpJsonContainer = Json.parse(new String(tmpInputStream.readAllBytes(), StandardCharsets.UTF_8));
                Json.Object tmpJsonObject = tmpJsonContainer.asObject();

                Json.Array tmpAssets = (Json.Array)tmpJsonObject.get("assets");

                if ((!Objects.isNull(tmpAssets)) && (!tmpAssets.isEmpty())) {

                    if (Objects.isNull(aRecognizer)) {

                        return ((Json.Object)tmpAssets.get(0)).get("browser_download_url").toString();
                    }
                    else {

                        for (Serializable tmpCurrentAsset : tmpAssets) {

                            String tmpUrl = ((Json.Object)tmpCurrentAsset).get("browser_download_url").toString();

                            if (tmpUrl.contains(aRecognizer)) {

                                return tmpUrl;
                            }
                        }
                    }
                }

                return "";
            }
        }
        catch (IOException e) {

            return ("Exception: " + e.getMessage());
        }
    }

}
