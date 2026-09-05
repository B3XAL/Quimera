package com.b3xal.headeranalyzer.analyzer;

import java.util.*;

/** Passive provider attribution for credential assignments. KeyHacks is used only as an inventory
 * of families worth considering; aliases, context rules and references here are Quimera's own.
 * Generic names such as apiKey/accessToken are attributed only when the surrounding response
 * contains a provider-specific marker, avoiding made-up technology labels. */
final class CredentialProviderCatalog {
    private CredentialProviderCatalog() {}

    record Provider(String technology, String reference, List<String> fieldMarkers,
                    List<String> contextMarkers) {}

    private static Provider p(String technology, String reference, String fields, String contexts) {
        return new Provider(technology, reference, words(fields), words(contexts));
    }
    private static List<String> words(String text) {
        return text.isBlank() ? List.of() : Arrays.asList(text.toLowerCase(Locale.ROOT).split("\\s+"));
    }

    // Specific entries precede broad platform families. Markers are normalized (letters/digits)
    // for fields, lowercase literal fragments for surrounding body context.
    private static final List<Provider> PROVIDERS = List.of(
        p("AB Tasty", "https://developers.abtasty.com/", "abtasty", "abtasty.com"),
        p("Algolia", "https://www.algolia.com/doc/rest-api/search/", "algolia", "algolia.com algolianet.com x-algolia-api-key"),
        p("Amplitude", "https://amplitude.com/docs/apis", "amplitude", "amplitude.com api.amplitude.com"),
        p("Asana", "https://developers.asana.com/docs/authentication", "asana", "asana.com api.asana.com"),
        // Auth0/Okta/OneLogin are identity-as-a-service providers: field/context-only (no safe
        // bare value-shape signature for Auth0/OneLogin secrets, arbitrary-length opaque strings
        // with no distinctive prefix), Okta additionally gets its own value-shape signature below
        // (the "00"+40-char token is only safe to regex when anchored to its mandatory "SSWS "
        // auth scheme prefix, see CredentialBodyAnalyzer.SIGNATURES).
        p("Auth0", "https://auth0.com/docs/secure/tokens/access-tokens", "auth0 auth0domain auth0clientid auth0clientsecret auth0managementtoken", "auth0.com"),
        p("AWS IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html", "aws amazon", "aws_access_key_id aws_secret_access_key amazonaws.com"),
        p("Azure Application Insights", "https://learn.microsoft.com/azure/azure-monitor/app/api-custom-events-metrics", "applicationinsights appinsights", "applicationinsights.io application insights"),
        p("Bazaarvoice", "https://developer.bazaarvoice.com/conversations-api/getting-started", "bazaarvoice conversationspasskey", "bazaarvoice.com conversationspasskey"),
        p("Bing Maps", "https://learn.microsoft.com/bingmaps/getting-started/bing-maps-dev-center-help/getting-a-bing-maps-key", "bingmaps", "virtualearth.net bing maps"),
        p("Bitly", "https://dev.bitly.com/docs/getting-started/authentication/", "bitly", "bitly.com api-ssl.bitly.com"),
        p("Branch.io", "https://help.branch.io/developers-hub/docs/branch-api", "branchio branchsecret branchkey", "api2.branch.io branch_secret"),
        p("BrowserStack", "https://www.browserstack.com/docs/iaam-security/manage-access-keys", "browserstack", "browserstack.com"),
        p("Buildkite", "https://buildkite.com/docs/apis/managing-api-tokens", "buildkite", "api.buildkite.com buildkite.com"),
        p("ButterCMS", "https://buttercms.com/docs/api/", "buttercms butter", "api.buttercms.com"),
        p("Calendly", "https://developer.calendly.com/how-to-authenticate-with-personal-access-tokens", "calendly", "api.calendly.com calendly.com/api"),
        p("Contentful", "https://www.contentful.com/developers/docs/references/authentication/", "contentful", "contentful.com cdn.contentful.com"),
        p("CircleCI", "https://circleci.com/docs/managing-api-tokens/", "circleci circletoken", "circleci.com circle-token"),
        p("Cloudflare", "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/", "cloudflare cfapitoken", "api.cloudflare.com cloudflare.com/client/v4"),
        p("Cloudinary", "https://cloudinary.com/documentation/solution_overview", "cloudinary cloudinaryurl", "cloudinary.com res.cloudinary.com"),
        p("Cypress Cloud", "https://docs.cypress.io/cloud/account-management/projects", "cypress recordkey", "api.cypress.io cypress_record_key"),
        p("Datadog", "https://docs.datadoghq.com/account_management/api-app-keys/", "datadog ddapikey ddapplicationkey", "api.datadoghq.com datadog"),
        p("Delighted", "https://app.delighted.com/docs/api", "delighted", "api.delighted.com"),
        p("DeviantArt", "https://www.deviantart.com/developers/authentication", "deviantart deviant", "deviantart.com/oauth2"),
        p("Digital Ocean", "https://docs.digitalocean.com/reference/api/create-personal-access-token/", "digitalocean digitaloceantoken dotoken", "digitalocean.com api.digitalocean.com"),
        p("Discord", "https://discord.com/developers/docs/topics/oauth2", "discord discordbottoken discordwebhook discordclientsecret", "discord.com/api discordapp.com"),
        p("Docker Hub", "https://docs.docker.com/security/access-tokens/", "dockerhub dockerpat", "hub.docker.com index.docker.io"),
        p("Dropbox", "https://developers.dropbox.com/oauth-guide", "dropbox", "dropboxapi.com dropbox.com/oauth"),
        p("Facebook / Meta", "https://developers.facebook.com/docs/facebook-login/guides/access-tokens/", "facebook fbappsecret meta", "graph.facebook.com facebook.com/oauth"),
        p("Firebase Cloud Messaging", "https://firebase.google.com/docs/cloud-messaging/auth-server", "fcm firebasecloudmessaging", "fcm.googleapis.com firebase cloud messaging"),
        p("Firebase", "https://firebase.google.com/docs/projects/api-keys", "firebase", "firebaseio.com identitytoolkit.googleapis.com firebaseapp.com"),
        p("Freshdesk", "https://developers.freshdesk.com/api/#authentication", "freshdesk", "freshdesk.com/api"),
        p("GitHub", "https://docs.github.com/authentication/keeping-your-account-and-data-secure/about-authentication-to-github", "github", "api.github.com github.com/login/oauth"),
        p("GitLab", "https://docs.gitlab.com/security/tokens/", "gitlab", "gitlab.com/api private-token job-token"),
        p("Google Cloud service account", "https://cloud.google.com/iam/docs/keys-create-delete", "gcpserviceaccount googleapplicationcredentials", "service_account gserviceaccount.com private_key_id"),
        p("Google reCAPTCHA", "https://developers.google.com/recaptcha/docs/verify", "recaptcha", "google.com/recaptcha recaptcha/api"),
        p("Google Maps Platform", "https://developers.google.com/maps/api-security-best-practices", "googlemaps gmaps", "maps.googleapis.com maps/embed"),
        p("YouTube Data API", "https://developers.google.com/youtube/v3/getting-started", "youtube", "youtube.googleapis.com googleapis.com/youtube"),
        p("Google APIs / OAuth", "https://cloud.google.com/docs/authentication/api-keys", "google gcp", "accounts.google.com/oauth oauth2.googleapis.com googleapis.com"),
        p("Grafana", "https://grafana.com/docs/grafana/latest/administration/service-accounts/", "grafana", "/api/user grafana"),
        p("Help Scout", "https://developer.helpscout.com/mailbox-api/overview/authentication/", "helpscout", "api.helpscout.net"),
        p("Heroku", "https://devcenter.heroku.com/articles/platform-api-reference#authentication", "heroku", "api.heroku.com"),
        p("HubSpot", "https://developers.hubspot.com/docs/api/private-apps", "hubspot hapikey", "api.hubapi.com hapikey"),
        p("Infura", "https://docs.metamask.io/services/how-to/secure-your-api-key/", "infura", "infura.io/v3"),
        p("Figma", "https://developers.figma.com/docs/rest-api/personal-access-tokens/", "figma figmatoken", "api.figma.com figma.com"),
        p("Instagram", "https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/business-login", "instagram", "graph.instagram.com instagram.com/oauth"),
        p("IPstack", "https://ipstack.com/documentation", "ipstack", "api.ipstack.com access_key"),
        p("Iterable", "https://support.iterable.com/hc/en-us/articles/360043464871-API-Keys", "iterable", "api.iterable.com"),
        p("JumpCloud", "https://jumpcloud.com/support/jumpcloud-apis", "jumpcloud", "console.jumpcloud.com x-api-key"),
        p("Keen.io", "https://keen.io/docs/api/", "keenio keen", "api.keen.io"),
        p("LinkedIn OAuth", "https://learn.microsoft.com/linkedin/shared/authentication/authorization-code-flow", "linkedin", "linkedin.com/oauth"),
        p("Lokalise", "https://developers.lokalise.com/reference/api-authentication", "lokalise", "api.lokalise.com x-api-token"),
        p("Loqate", "https://www.loqate.com/developers/api/", "loqate addressy", "api.addressy.com loqate.com"),
        p("Mailchimp", "https://mailchimp.com/developer/marketing/guides/quick-start/", "mailchimp", "api.mailchimp.com"),
        p("Mailgun", "https://documentation.mailgun.com/docs/mailgun/api-reference/mg-auth", "mailgun", "api.mailgun.net"),
        p("Mapbox", "https://docs.mapbox.com/help/getting-started/access-tokens/", "mapbox", "api.mapbox.com mapbox.com"),
        p("Microsoft Azure Storage SAS", "https://learn.microsoft.com/azure/storage/common/storage-sas-overview", "azuresas sastoken sharedaccesssignature", "blob.core.windows.net sig= sv="),
        p("Microsoft Teams webhook", "https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook", "teamswebhook microsoftteamswebhook", "webhook.office.com outlook.office.com/webhook logic.azure.com/workflows"),
        p("Microsoft Azure / Entra ID", "https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow", "azure entra aad microsofttenant", "login.microsoftonline.com tenant_id"),
        p("New Relic", "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/", "newrelic nrak nerdgraph", "api.newrelic.com nerdgraph"),
        p("Notion", "https://developers.notion.com/docs/authorization", "notion notiontoken", "api.notion.com notion.so"),
        p("npm registry", "https://docs.npmjs.com/about-access-tokens/", "npm npmtoken", "registry.npmjs.org _authtoken"),
        // Okta/OneLogin are identity-as-a-service providers, same "field/context catalog entry"
        // reasoning as Auth0 above. Okta additionally gets its own value-shape signature (the
        // "00"+40-char token, only safe to regex anchored to its mandatory "SSWS " scheme prefix).
        p("Okta", "https://developer.okta.com/docs/guides/create-an-api-token/main/", "okta oktaapitoken oktaclientsecret oktadomain", "okta.com oktapreview.com"),
        p("OneLogin", "https://developers.onelogin.com/api-docs/2/getting-started/dev-overview", "onelogin oneloginclientid oneloginclientsecret", "onelogin.com"),
        p("Opsgenie", "https://support.atlassian.com/opsgenie/docs/api-key-management/", "opsgenie geniekey", "api.opsgenie.com geniekey"),
        p("OpenAI API", "https://platform.openai.com/docs/api-reference/authentication", "openai", "api.openai.com openai_api_key"),
        p("PagerDuty", "https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTgx-authentication", "pagerduty", "api.pagerduty.com"),
        p("PayPal", "https://developer.paypal.com/api/rest/authentication/", "paypal", "api.paypal.com api.sandbox.paypal.com"),
        p("Pendo", "https://engageapi.pendo.io/", "pendo", "app.pendo.io x-pendo-integration-key"),
        p("Pivotal Tracker", "https://www.pivotaltracker.com/help/api/rest/v5", "pivotaltracker trackertoken", "pivotaltracker.com x-trackertoken"),
        p("PlanetScale", "https://planetscale.com/docs/concepts/planetscale-connect", "planetscale planetscaletoken", "planetscale.com"),
        p("Razorpay", "https://razorpay.com/docs/api/authentication/", "razorpay", "api.razorpay.com"),
        p("Salesforce", "https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_flows.htm", "salesforce sfdc", "salesforce.com/services/data login.salesforce.com"),
        p("Sauce Labs", "https://docs.saucelabs.com/basics/acct-team-mgmt/managing-user-info/", "saucelabs sauceaccesskey", "saucelabs.com/rest"),
        p("Sentry", "https://docs.sentry.io/account/auth-tokens/", "sentry sentryauthtoken sentrydsn", "sentry.io ingest.sentry.io"),
        p("Shopify", "https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens", "shopify shpat shpss shpca", "myshopify.com admin.shopify.com/admin/api"),
        p("SendGrid", "https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication", "sendgrid", "api.sendgrid.com"),
        p("Shodan", "https://developer.shodan.io/api/requirements", "shodan", "api.shodan.io"),
        p("Slack", "https://api.slack.com/authentication/token-types", "slack", "slack.com/api hooks.slack.com slack-gov.com"),
        p("SonarCloud", "https://docs.sonarsource.com/sonarqube-cloud/advanced-setup/web-api/", "sonarcloud sonar", "sonarcloud.io/api"),
        p("Spotify", "https://developer.spotify.com/documentation/web-api/concepts/access-token", "spotify", "api.spotify.com accounts.spotify.com"),
        // Legacy anon/service_role keys are JWTs (no independently distinctive shape of their
        // own, any JWT starts with "eyJ"), so this stays context/field-only. The severity is why
        // it's worth cataloguing despite that: a leaked service_role key bypasses Row Level
        // Security entirely, one of the most common high-impact leaks in Supabase-backed apps.
        p("Supabase", "https://supabase.com/docs/guides/getting-started/api-keys", "supabase supabaseurl supabaseanonkey supabaseservicerolekey supabasekey", "supabase.co supabase.in"),
        p("Square", "https://developer.squareup.com/docs/build-basics/access-tokens", "square squareup", "connect.squareup.com squareup.com/oauth"),
        p("Stripe", "https://docs.stripe.com/keys", "stripe", "api.stripe.com"),
        p("Telegram Bot API", "https://core.telegram.org/bots/api#authorizing-your-bot", "telegram telegrambot", "api.telegram.org/bot"),
        p("Travis CI", "https://docs.travis-ci.com/user/triggering-builds/", "travis travisci", "api.travis-ci.com api.travis-ci.org"),
        p("Twilio", "https://www.twilio.com/docs/usage/secure-credentials", "twilio", "api.twilio.com twilio_account_sid"),
        p("X / Twitter API", "https://developer.x.com/en/docs/authentication/overview", "twitter", "api.twitter.com oauth2/token"),
        p("Visual Studio App Center", "https://learn.microsoft.com/appcenter/api-docs/", "appcenter visualstudioappcenter", "api.appcenter.ms x-api-token"),
        p("WakaTime", "https://wakatime.com/developers", "wakatime", "wakatime.com/api"),
        p("Weglot", "https://developers.weglot.com/api/reference/authentication", "weglot", "api.weglot.com"),
        p("WP Engine", "https://wpengineapi.com/", "wpengine wpeapikey", "api.wpengine.com wpe_apikey"),
        p("Zapier webhook", "https://help.zapier.com/hc/en-us/articles/8496292548877", "zapier zapierwebhook", "hooks.zapier.com/hooks/catch"),
        p("Zendesk", "https://developer.zendesk.com/documentation/api-basics/authentication/", "zendesk", "zendesk.com/api")
    );

    static Optional<Provider> identify(String field, String body) {
        String normalized = normalize(field);
        List<String> fieldTokens = tokens(field);
        String lcBody = body == null ? "" : body.toLowerCase(Locale.ROOT);
        for (Provider provider : PROVIDERS) {
            for (String marker : provider.fieldMarkers)
                if (fieldHasMarker(normalized, fieldTokens, marker)) return Optional.of(provider);
        }
        for (Provider provider : PROVIDERS) {
            for (String marker : provider.contextMarkers)
                // Context attribution is deliberately limited to structural markers (domains,
                // paths, header/variable names). Plain words such as "application", "maps" or
                // "token" occur routinely in bundles and caused misleading technology labels.
                if (isDistinctiveContextMarker(marker) && lcBody.contains(marker))
                    return Optional.of(provider);
        }
        return Optional.empty();
    }

    static boolean isCredentialField(String field, String body) {
        String n = normalize(field);
        if (n.isBlank()) return false;
        boolean sensitive = n.equals("secret") || n.equals("token") || n.equals("password")
                || n.equals("passwd") || n.equals("pwd") || n.equals("bearer")
                || n.endsWith("apikey") || n.endsWith("apisecret") || n.endsWith("accesstoken")
                || n.endsWith("refreshtoken") || n.endsWith("authtoken") || n.endsWith("idtoken")
                || n.endsWith("clientsecret") || n.endsWith("appsecret") || n.endsWith("secretkey")
                || n.endsWith("privatekey") || n.endsWith("accesskey") || n.endsWith("integrationkey")
                || n.endsWith("applicationkey") || n.endsWith("recordkey") || n.endsWith("passkey")
                || n.endsWith("serverkey") || n.endsWith("customtoken") || n.endsWith("registrationtoken")
                || n.endsWith("webhookurl") || n.endsWith("webhooktoken") || n.endsWith("readkey");
        Optional<Provider> provider = identify(field, body);
        return sensitive || (provider.isPresent()
                && (n.endsWith("key") || n.endsWith("secret") || n.endsWith("token")
                    || (n.equals("sig") && provider.get().technology.equals("Microsoft Azure Storage SAS"))));
    }

    static Optional<String> referenceForTechnology(String technology) {
        return PROVIDERS.stream().filter(p -> p.technology.equals(technology))
                .map(Provider::reference).findFirst();
    }

    private static String normalize(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static boolean isDistinctiveContextMarker(String marker) {
        if (Set.of("x-api-key", "x-api-token", "oauth2/token", "access_key", "private-token",
                "job-token", "sig=", "sv=").contains(marker)) return false;
        return marker.indexOf('.') >= 0 || marker.indexOf('/') >= 0 || marker.indexOf('_') >= 0
                || marker.indexOf('-') >= 0 || marker.indexOf('=') >= 0;
    }

    private static boolean fieldHasMarker(String normalizedField, List<String> fieldTokens,
                                          String rawMarker) {
        String marker = normalize(rawMarker);
        if (marker.isBlank()) return false;
        // Short brand names are collision-prone (aws in "draws", meta in "metadata", npm in
        // "pnpm"). Require a real camelCase/delimiter token. Longer compound aliases are unique
        // enough to allow exact prefix/suffix composition such as branchSecret or cfApiToken.
        int tokenIndex = fieldTokens.indexOf(marker);
        if (tokenIndex >= 0) return adjacentToCredentialWord(fieldTokens, tokenIndex);
        if (normalizedField.equals(marker)) return true;
        // Brands commonly consist of several camel-case tokens (browserStack,
        // applicationInsights). Join only complete adjacent tokens; never use arbitrary
        // substrings, which confused telegrammatic with Telegram and herokuapp with Heroku.
        for (int start = 0; start < fieldTokens.size(); start++) {
            StringBuilder joined = new StringBuilder();
            for (int end = start; end < Math.min(fieldTokens.size(), start + 4); end++) {
                joined.append(fieldTokens.get(end));
                if (joined.toString().equals(marker)
                        && adjacentToCredentialSpan(fieldTokens, start, end)) return true;
            }
        }
        return false;
    }

    private static boolean adjacentToCredentialWord(List<String> words, int index) {
        Set<String> credentialWords = Set.of("api", "key", "secret", "token", "access", "auth",
                "application", "integration", "record", "pass", "server", "custom",
                "registration", "webhook", "read", "password", "credential", "credentials");
        return (index > 0 && credentialWords.contains(words.get(index - 1)))
                || (index + 1 < words.size() && credentialWords.contains(words.get(index + 1)));
    }

    private static boolean adjacentToCredentialSpan(List<String> words, int start, int end) {
        Set<String> credentialWords = Set.of("api", "key", "secret", "token", "access", "auth",
                "application", "integration", "record", "pass", "server", "custom",
                "registration", "webhook", "read", "password", "credential", "credentials");
        return (start > 0 && credentialWords.contains(words.get(start - 1)))
                || (end + 1 < words.size() && credentialWords.contains(words.get(end + 1)));
    }

    private static List<String> tokens(String value) {
        if (value == null || value.isBlank()) return List.of();
        String separated = value.replaceAll("([a-z0-9])([A-Z])", "$1 $2")
                .toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", " ").trim();
        return separated.isBlank() ? List.of() : Arrays.asList(separated.split("\\s+"));
    }
}
