package com.b3xal.headeranalyzer.analyzer;

import java.util.Set;

/**
 * Hostnames known to host JSONP endpoints or AngularJS library files, ported from Google's
 * csp-evaluator (github.com/google/csp-evaluator, allowlist_bypasses/json/{jsonp,angular}.json),
 * see CREDITS.md for what was and wasn't taken from that project.
 *
 * Why this matters: a CSP like {@code script-src 'self' https://www.googletagmanager.com} LOOKS
 * safe (only two trusted-looking origins), but a JSONP endpoint on that domain reflects a
 * caller-controlled callback parameter into executable JavaScript, or an AngularJS library file
 * hosted there enables the well-known Angular sandbox-escape gadgets, either way an attacker can
 * execute arbitrary script despite the policy looking restrictive. This is a completely different,
 * much higher-confidence class of finding than "you used a wildcard", it names an exact,
 * exploitable bypass technique against an exact domain the policy already trusts.
 *
 * Deliberately hostname-only, not full URL-path matching like upstream: real-world CSP entries
 * almost always allowlist a bare origin with no path restriction, so hostname matching already
 * covers the common case, and a scanner erring toward flagging-for-manual-verification is safer
 * than silently missing a bypass due to path-matching nuance this tool can't fully replicate.
 */
public final class CspBypassDomains {

    private CspBypassDomains() {}

    /** Hosts confirmed to serve a JSONP endpoint reachable with an attacker-controlled callback. */
    public static final Set<String> JSONP_HOSTS = Set.of(
        "9.chart.apis.google.com", "a.config.skype.com", "a.tiles.mapbox.com",
        "a248.e.akamai.net", "accounts.google.com", "afpeng.alimama.com",
        "ajax.googleapis.com", "an.yandex.ru", "api.facebook.com",
        "api.flickr.com", "api.instagram.com", "api.map.baidu.com",
        "api.mixpanel.com", "api.userlike.com", "api.vk.com",
        "autocomplete.travelpayouts.com", "awaps.yandex.ru", "bebezoo.1688.com",
        "beta.gismeteo.ru", "books.google.com", "c.tiles.mapbox.com",
        "c1n2.hypercomments.com", "c1n3.hypercomments.com", "catalog.api.2gis.ru",
        "cbks0.googleapis.com", "ccrprod.alipay.com", "cdn.syndication.twimg.com",
        "cdn.syndication.twitter.com", "client.siteheart.com", "clients1.google.com",
        "community.adobe.com", "connect.mail.ru", "count.tbcdn.cn",
        "cse.google.com", "d1f69o4buvlrj5.cloudfront.net", "data.gongchang.com",
        "de.blog.newrelic.com", "detector.alicdn.com", "dev.virtualearth.net",
        "fast.wistia.com", "fellowes.ugc.bazaarvoice.com", "gdata.youtube.com",
        "google.ru", "googleads.g.doubleclick.net", "googletagmanager.com",
        "graph.facebook.com", "group.aliexpress.com", "gum.criteo.com",
        "gupiao.baidu.com", "h.cackle.me", "i.cackle.me",
        "ib.adnxs.com", "id.rambler.ru", "kecngantang.blogspot.com",
        "links.services.disqus.com", "m.addthis.com", "maps.beeline.ru",
        "maps.google.com", "maps.google.de", "maps.google.lv",
        "maps.google.ru", "maps.googleapis.com", "mc.yandex.ru",
        "mt1.googleapis.com", "mts0.googleapis.com", "mts1.googleapis.com",
        "nominatim.openstreetmap.org", "offer.alibaba.com", "ok.go.mail.ru",
        "pagead2.googlesyndication.com", "partner.googleadservices.com", "pass.yandex.com",
        "pass.yandex.ru", "pass.yandex.ua", "passport.ngs.ru",
        "pin.aliyun.com", "pipes.yahooapis.com", "plugins.mozilla.org",
        "pro.netrox.sc", "publish.twitter.com", "pubsub.pubnub.com",
        "query.yahooapis.com", "rec.ydf.yandex.ru", "relap.io",
        "rexchange.begun.ru", "se.wikipedia.org", "securepubads.g.doubleclick.net",
        "share.yandex.net", "ssl.google-analytics.com", "suggest.taobao.com",
        "syndication.twitter.com", "target.ukr.net", "tj.gongchang.com",
        "tr.indeed.com", "translate.google.com", "translate.googleapis.com",
        "translate.yandex.net", "ulogin.ru", "video.media.yql.yahoo.com",
        "vimeo.com", "wb.amap.com", "widget.admitad.com",
        "widgets.pinterest.com", "wpd.b.qq.com", "wslocker.ru",
        "www-onepick-opensocial.googleusercontent.com", "www.blogger.com", "www.facebook.com",
        "www.google-analytics.com", "www.google.com", "www.google.de",
        "www.googleadservices.com", "www.googleapis.com", "www.googletagmanager.com",
        "www.meteoprog.ua", "www.panoramio.com", "www.sharethis.com",
        "www.travelpayouts.com", "www.youku.com", "www.youtube.com",
        "yandex.ru", "ynuf.alipay.com"
    );

    /**
     * Subset of JSONP_HOSTS whose bypass gadget specifically requires 'unsafe-eval' to also be
     * present in script-src to actually work, so a match here alone isn't exploitable, only flag
     * it when unsafe-eval is also allowed.
     */
    public static final Set<String> JSONP_NEEDS_EVAL = Set.of(
        "googletagmanager.com", "www.googletagmanager.com", "www.googleadservices.com",
        "google-analytics.com", "ssl.google-analytics.com", "www.google-analytics.com"
    );

    /** Hosts confirmed to serve an AngularJS library build, enabling the Angular CSP-bypass gadgets. */
    public static final Set<String> ANGULAR_HOSTS = Set.of(
        "96fe3ee995e96e922b6b-d10c35bd0a0de2c718b252bc575fdb73.ssl.cf1.rackcdn.com", "ajax.googleapis.com", "andors-trail.googlecode.com",
        "art.jobs.netease.com", "askgithub.com", "ayicommon-a.akamaihd.net",
        "cdn.bootcss.com", "cdn.jsdelivr.net", "cdn.shopify.com",
        "cdn.walkme.com", "cdn2-casinoroom.global.ssl.fastly.net", "cdnjs.cloudflare.com",
        "collade.demo.stswp.com", "csu-c45.kxcdn.com", "dl.dropboxusercontent.com",
        "eb2883ede55c53e09fd5-9c145fb03d93709ea57875d307e2d82e.ssl.cf3.rackcdn.com", "elysiumwebsite.s3.amazonaws.com", "eternal-sunset.herokuapp.com",
        "gift-talk.kakao.com", "gstatic.com", "inno.blob.core.windows.net",
        "laundrymail.com", "master-sumok.ru", "mrfishie.github.io",
        "oss.maxcdn.com", "pangxiehaitao.com", "parademanagement.com.s3-website-ap-southeast-1.amazonaws.com",
        "prb-resume.appspot.com", "raw.githubusercontent.com", "reports.zemanta.com",
        "s3-eu-west-1.amazonaws.com", "services.amazon.com", "static.tumblr.com",
        "storage.googleapis.com", "twitter.github.io", "www.adobe.com",
        "www.googleadservices.com", "www.gstatic.com", "yandex.st",
        "yastatic.net", "yuedust.yuedu.126.net"
    );

    /**
     * True if any hostname in `set` is exactly `domain` or a subdomain of it. Used for CSP
     * wildcard sources like "*.googleapis.com" (domain = "googleapis.com"): the wildcard covers
     * every subdomain, so it's a bypass if ANY known bypass host falls under that domain, e.g.
     * "cbks0.googleapis.com" is in JSONP_HOSTS and is a subdomain of "googleapis.com".
     */
    public static boolean coversWildcardDomain(Set<String> set, String domain) {
        if (domain == null || domain.isBlank()) return false;
        String d = domain.toLowerCase(java.util.Locale.ROOT);
        String suffix = "." + d;
        for (String h : set) {
            if (h.equals(d) || h.endsWith(suffix)) return true;
        }
        return false;
    }
}
