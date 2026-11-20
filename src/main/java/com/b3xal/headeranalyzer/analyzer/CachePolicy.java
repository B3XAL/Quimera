package com.b3xal.headeranalyzer.analyzer;

import java.util.*;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/** RFC 9111 response policy; quoted commas are field-name lists, not directive separators. */
final class CachePolicy {
    private final Map<String,List<String>> directives=new HashMap<>();
    private final Map<String,String> headers;
    private CachePolicy(Map<String,String> headers){this.headers=headers;}
    static CachePolicy parse(Map<String,String> headers) {
        CachePolicy policy=new CachePolicy(headers);
        String value=HeaderReportContext.get(headers,"Cache-Control");
        for(String token:HeaderReportContext.splitList(value)) {
            String[] pair=token.trim().split("=",2);
            if(pair[0].isBlank())continue;
            policy.directives.computeIfAbsent(pair[0].trim().toLowerCase(Locale.ROOT),k->new ArrayList<>())
                    .add(pair.length==1?"":pair[1].trim());
        }
        return policy;
    }
    boolean has(String name){return directives.containsKey(name);}
    boolean unqualified(String name){return directives.getOrDefault(name,List.of()).stream().anyMatch(String::isEmpty);}
    boolean fresh(String name) {
        List<String> values=directives.get(name);
        if(values==null||values.size()!=1)return false;
        String value=HeaderReportContext.decodeDirectiveValue(values.get(0));
        return value!=null&&value.matches("[0-9]+")&&new java.math.BigInteger(value).signum()>0;
    }
    boolean sharedReuseAllowed(Map<String,String> request) {
        if(has("no-store")||unqualified("private")||unqualified("no-cache"))return false;
        if(HeaderReportContext.splitList(HeaderReportContext.get(headers,"Vary")).stream()
                .anyMatch(v -> v.trim().equals("*")))return false;
        if(has("s-maxage")&&!fresh("s-maxage"))return false;
        if(!has("s-maxage")&&has("max-age")&&!fresh("max-age"))return false;
        if(!HeaderReportContext.get(request,"Authorization").isBlank()
                &&!(has("public")||has("s-maxage")||has("must-revalidate")))return false;
        return true;
    }
    boolean mayStore(int status,Map<String,String> request) {
        if(has("no-store")||status<200||status==304)return false;
        if(has("public")||fresh("max-age")||fresh("s-maxage"))return true;
        try {
            if(ZonedDateTime.parse(HeaderReportContext.get(headers,"Expires"),DateTimeFormatter.RFC_1123_DATE_TIME)
                    .isAfter(ZonedDateTime.parse(HeaderReportContext.get(headers,"Date"),DateTimeFormatter.RFC_1123_DATE_TIME)))return true;
        }catch(java.time.DateTimeException ignored){}
        return Set.of(200,203,204,206,300,301,308,404,405,410,414,501).contains(status);
    }
}
