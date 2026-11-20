package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ParameterInfluenceProbeTest {

    @Test
    void changesOnlyTheSelectedQueryFieldAndBoundsCandidates() {
        HttpRequest request = request("a=one&token=two&empty=");
        var candidates = ParameterInfluenceProbe.candidates(request);

        assertEquals(3, candidates.size());
        assertEquals("/page?a=one&token=marker&empty=", ParameterInfluenceProbe.mutatedPath(
                "/page?a=one&token=two&empty=", candidates.get(1), "marker"));
    }

    @Test
    void requiresBothMarkersInSameHeaderAndCleanControls() {
        String first = "qpi-first-marker-value";
        String second = "qpi-second-marker-value";
        var candidate = new ParameterInfluenceProbe.Candidate("next", 0);
        var complete = response("X-Route", first);
        var secondComplete = response("X-Route", second);
        var controls = response("X-Route", "stable");
        var observations = List.of(observation(controls), observation(controls), observation(complete),
                observation(controls), observation(secondComplete), observation(controls));

        var findings = ParameterInfluenceProbe.confirm(candidate, first, second, observations);

        assertEquals(1, findings.size());
        assertEquals(Severity.LOW, findings.get(0).severity);
        assertTrue(findings.get(0).evidence.contains("Value A: " + first));
        var contaminated = List.of(observation(response("X-Route", first)), observation(controls), observation(complete),
                observation(controls), observation(secondComplete), observation(controls));
        assertFalse(ParameterInfluenceProbe.confirm(candidate, first, second, contaminated).iterator().hasNext());
    }

    private static ParameterInfluenceProbe.Observation observation(HeaderInfluenceResponse response) {
        return new ParameterInfluenceProbe.Observation(null, response);
    }

    private static HeaderInfluenceResponse response(String name, String value) {
        return new HeaderInfluenceResponse(200, Map.of(name.toLowerCase(), List.of(value)), "", true);
    }

    @SuppressWarnings("unchecked")
    private static HttpRequest request(String query) {
        return (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "query" -> query;
                    case "url" -> "https://example.test/page?" + query;
                    case "method" -> "GET";
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> method.getReturnType() == boolean.class ? false : null;
                });
    }
}
