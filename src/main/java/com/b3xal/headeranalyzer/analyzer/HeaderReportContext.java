package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;
import java.util.regex.*;

/** Header-specific evidence boundaries; null body means unavailable, empty means observed empty. */
final class HeaderReportContext {
    private HeaderReportContext() {}
    static boolean owns(String h) { return Set.of("x-frame-options","strict-transport-security",
            "x-content-type-options","referrer-policy","x-xss-protection","cache-control",
            "server-timing","timing-allow-origin","allow").contains(h); }
    static String get(Map<String,String> h,String name) {
        if(h==null)return "";
        return h.entrySet().stream().filter(e->e.getKey().equalsIgnoreCase(name))
                .map(e->Objects.toString(e.getValue(),"")).findFirst().orElse("");
    }
    static boolean isProbe(Map<String,String> h) {
        return h!=null && h.keySet().stream().anyMatch(k->k.equalsIgnoreCase("X-Quimera-Internal-Probe")&&!get(h,k).equals("baseline")
                ||k.equalsIgnoreCase("X-Quimera-Trace-Probe")||k.equalsIgnoreCase(JwtActiveProbe.MARKER_HEADER)
                ||k.equalsIgnoreCase(GoogleApiKeyProbe.MARKER_HEADER)||k.equalsIgnoreCase(HeaderInfluenceProbe.MARKER_HEADER));
    }
    static String mime(Map<String,String> h) { return get(h,"Content-Type").split(";",2)[0].trim().toLowerCase(Locale.ROOT); }
    static boolean noDocument(int status,String method,String body,Map<String,String> h) {
        return status<200||status==204||status==205||status>=300&&status<400
                ||Set.of("HEAD","OPTIONS","TRACE","CONNECT").contains(Objects.toString(method,"").toUpperCase(Locale.ROOT))
                ||body!=null&&body.isBlank()||get(h,"Content-Length").trim().equals("0")
                ||get(h,"Content-Disposition").split(";",2)[0].trim().equalsIgnoreCase("attachment");
    }
    static boolean html(String body) {
        if(body==null)return false;
        int start=0;
        while(start<body.length()) {
            while(start<body.length() && Character.isWhitespace(body.charAt(start)))start++;
            if(!body.startsWith("<!--",start))break;
            int end=body.indexOf("-->",start+4);if(end<0)return false;
            start=end+3;
        }
        return Pattern.compile("(?is)^<(?:!doctype\\s+html|html|head|body|form|button|input)\\b")
                .matcher(body.substring(start)).find();
    }
    static boolean interfaceBody(String body) {
        return activeTags(body).stream().anyMatch(tag -> Pattern.compile("(?is)^<(?:form|button|input|select|textarea)(?=[\\t\\n\\f\\r />])").matcher(tag).find());
    }
    static boolean document(Map<String,String> h,String body,String url) {
        String type=mime(h);
        if(type.equals("text/html")||type.equals("application/xhtml+xml"))return true;
        if(type.equals("image/svg+xml"))return interfaceBody(body);
        if(!type.isEmpty())return false;
        if(html(body))return true;
        // XFO03 was not selected: retain the existing unknown-MIME fallback.
        try { return !Objects.toString(URI.create(url).getPath(),"").matches("(?i).*\\.(?:js|mjs|cjs|css|map|png|jpe?g|svg|pdf|woff2?|ttf|otf|eot|gif|ico|webp|bmp|avif|mp4|mp3|wav|ogg|webm)$"); }
        catch(IllegalArgumentException e){return false;}
    }
    static List<HeaderFinding> apply(List<HeaderFinding> input,Map<String,String> h,Map<String,String> req,
            String url,int status,String body,String method) {
        List<HeaderFinding> out=new ArrayList<>();
        if(status<100)return out;
        for(HeaderFinding original:input) {
            HeaderFinding f=original;
            String name=f.headerName.toLowerCase(Locale.ROOT);
            if (f.isUserDefined()) { out.add(f); continue; }
            // 4xx/5xx handlers and rejected methods are not representative application
            // documents. Preserve real disclosures/leaks, but never infer hardening policy from
            // them (for example XFO/HSTS on a 405 Method Not Allowed response).
            if (status >= 400 && f.category != HeaderFinding.Category.INFORMATION_DISCLOSURE
                    && f.category != HeaderFinding.Category.AUTH
                    && f.category != HeaderFinding.Category.COOKIE
                    && f.category != HeaderFinding.Category.STORAGE) continue;
            if (isFramingFinding(f) && !framingContext(h,req,url,status,body,method)) continue;
            switch(name) {
                case "strict-transport-security":
                    if(!url.toLowerCase(Locale.ROOT).startsWith("https://")||status<200)continue;
                    if(!get(h,name).isBlank())break;
                    f=copy(f,f.issueName,"This HTTPS response did not include HSTS. Compare other responses on this host. "
                            +"Browser stored, parent-domain and preload coverage have not been established.",f.evidence,
                            // A secure redirect can itself establish HSTS, but absence on that
                            // one hop does not establish that the host's final HTTPS response or
                            // stored/preloaded policy is unprotected. Keep it as context in
                            // Quimera, not an actionable MEDIUM/native issue.
                            status>=300&&status<400||status>=400||status==204||status==205
                                    ?Severity.INFORMATION:f.severity,Confidence.CERTAIN,f.category);
                    break;
                case "x-frame-options":
                    if(noDocument(status,method,body,h)||!document(h,body,url)||status>=400&&!interfaceBody(body)
                            ||restrictiveFrameAncestors(get(h,"Content-Security-Policy"),url)
                            ||!hasFrameAncestors(get(h,"Content-Security-Policy"))&&protectiveXfo(get(h,name)))continue;
                    break;
                case "x-xss-protection":
                    if(noDocument(status,method,body,h)||!document(h,body,url))continue;
                    break;
                case "x-content-type-options":
                    if(!mimeRelevant(h,req,url,status,body,method))continue;
                    f=copy(f,f.issueName,"An ambiguous MIME type was observed in a potentially active context. "
                            +"Verify the loader, response content and attacker control before claiming execution. "
                            +"Use a correct MIME type and nosniff. File suffixes alone do not identify module/worker loaders.",
                            f.evidence+" Destination: "+get(req,"Sec-Fetch-Dest")+"; MIME: "+mime(h),Severity.LOW,Confidence.TENTATIVE,f.category);
                    break;
                case "cache-control":
                    if(isProbe(req)||body==null||body.isBlank())continue;
                    break;
                case "referrer-policy":
                    if("HEAD".equalsIgnoreCase(method)||status==304||status<200||"OPTIONS".equalsIgnoreCase(method)||"TRACE".equalsIgnoreCase(method))continue;
                    boolean redirect=Set.of(301,302,303,307,308).contains(status)&&!get(h,"Location").isBlank();
                    if(!redirect&&(noDocument(status,method,body,h)||!(document(h,body,url)||mime(h).equals("text/css"))))continue;
                    if(f.issueName.equals("Referrer-Policy set to unsafe-url"))
                        f=copy(f,f.issueName,f.description,f.evidence,Severity.LOW,f.confidence,f.category);
                    f=referrer(f,body,h,redirect);
                    try {
                        String query=Objects.toString(URI.create(url).getRawQuery(), "");
                        Matcher sensitive=Pattern.compile("(?i)(?:^|&)(access_token|refresh_token|api_key|password|session_id)=[^&]+").matcher(query);
                        List<String> names=new ArrayList<>();while(sensitive.find())names.add(sensitive.group(1));
                        if(!names.isEmpty())f=copy(f,f.issueName,f.description,f.evidence
                                +" Credential-labelled URL query fields: "+names+"; outgoing transmission is unverified.",f.severity,f.confidence,f.category);
                    } catch(IllegalArgumentException ignored) {}
                    break;
                case "server":
                    if(f.issueName.equals("Server exact version disclosure")&&!serverVersion(get(h,name)))
                        f=copy(f,"Server identifier observed","Digits in a node label do not identify a software version.",
                                f.evidence,Severity.INFORMATION,Confidence.CERTAIN,HeaderFinding.Category.INFORMATION_DISCLOSURE);
                    break;
                case "timing-allow-origin":
                    List<String> origins = Arrays.stream(get(h,name).split("[,\\n]",-1))
                            .map(String::trim).filter(v->!v.isEmpty()).distinct().toList();
                    f=copy(f,f.issueName,f.description,"Observed timing origins: "+origins
                            +". Every relevant redirect needs its own timing-allow check.",f.severity,f.confidence,f.category);
                    break;
                case "via":
                    List<String> via=new ArrayList<>();
                    for(String entry:get(h,name).split(",")) {
                        String[] parts=entry.trim().split("\\s+",3);
                        via.add(parts.length>=2?"protocol="+parts[0]+", intermediary="+parts[1]
                                +(parts.length==3?", comment="+parts[2]:""):"unparsed="+entry.trim());
                    }
                    f=copy(f,f.issueName,f.description,String.join("; ",via),f.severity,f.confidence,f.category);
                    break;
                case "x-envoy-upstream-service-time":
                    String duration=get(h,name).trim();
                    f=copy(f,f.issueName,f.description,duration.matches("[0-9]+")?"Reported upstream duration: "+duration+" ms"
                            :"Unvalidated timing value: "+duration,f.severity,f.confidence,f.category);
                    break;
                case "x-version":
                    String v=get(h,name).trim();
                    String kind=v.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}.*")?"date-shaped identifier"
                            :v.matches("[a-fA-F0-9]{7,64}")?"hash-shaped identifier"
                            :v.matches("[vV]?[0-9]+(?:\\.[0-9]++)*+(?:[-+][\\w.-]+)?")?"version-shaped identifier":"application-defined identifier";
                    f=copy(f,f.issueName,f.description,kind+": "+v,f.severity,f.confidence,f.category);
                    break;
                case "server-timing":
                    if(Pattern.compile("(?i)(?:password|client_secret|access_token)\\s*[=:]\\s*[a-z0-9_./+-]{8,}").matcher(get(h,name)).find())
                        f=copy(f,"Potential credential in Server-Timing metadata","A metric contains a credential-labelled non-empty value. "
                                +"Verify that it is live sensitive data; generic metric names or high durations do not establish a leak.",
                                f.evidence,Severity.LOW,Confidence.TENTATIVE,f.category);
                    break;
                case "x-sourcefiles":
                    String path=sourcePath(get(h,name));
                    f=copy(f,path==null?"Unvalidated X-SourceFiles value":f.issueName,
                            path==null?"No valid local path could be decoded. Presence does not establish a public development server."
                            :"The header decodes to an absolute local path. A local capture or an intervening proxy can explain its presence; "
                            +"public development-server exposure has not been established.",
                            path==null?f.evidence:"Decoded path: "+path,path==null?Severity.INFORMATION:f.severity,f.confidence,f.category);
                    break;
                default:break;
            }
            out.add(f);
        }
        return out;
    }
    static boolean isFramingFinding(HeaderFinding f) {
        return f.headerName.equalsIgnoreCase("X-Frame-Options") || f.issueName.equals("CSP: frame-ancestors directive missing");
    }
    private static boolean framingContext(Map<String,String> h,Map<String,String> req,String url,int status,String body,String method) {
        String dest=get(req,"Sec-Fetch-Dest").trim();
        return (dest.isEmpty() || Set.of("document","iframe","frame").contains(dest))
                && !noDocument(status,method,body,h) && document(h,body,url)
                && (status<400 || interfaceBody(body));
    }
    static HeaderFinding copy(HeaderFinding f,String name,String desc,String evidence,Severity s,Confidence c,HeaderFinding.Category category) {
        return new HeaderFinding(name,f.headerName,f.headerValue,desc,evidence,s,c,category,f.referenceUrl,f.userDefinedRule);
    }
    static boolean serverVersion(String v) {
        return Pattern.compile("(?i)(?:^|[\\s(])(?:Apache|nginx|Microsoft-IIS|OpenResty|LiteSpeed|Caddy|Jetty|Tomcat|gunicorn|uvicorn|Werkzeug)/[0-9]+(?:\\.[0-9]++)++").matcher(v).find();
    }
    static List<String> splitList(String value) { return splitQuoted(value, ','); }
    static List<String> splitQuoted(String value, char separator) {
        List<String> tokens=new ArrayList<>();
        boolean quoted=false,escaped=false; int start=0;
        for(int i=0;i<value.length();i++) {
            char c=value.charAt(i);
            if(escaped){escaped=false;continue;}
            if(quoted&&c=='\\'){escaped=true;continue;}
            if(c=='"')quoted=!quoted;
            else if(c==separator&&!quoted){tokens.add(value.substring(start,i));start=i+1;}
        }
        tokens.add(value.substring(start));return tokens;
    }
    static boolean protectiveXfo(String v) {
        if(v==null||v.isBlank())return false;
        Set<String> tokens=new HashSet<>();
        for(String t:splitList(v.replace('\n',',')))tokens.add(t.trim().toLowerCase(Locale.ROOT));
        return tokens.contains("deny")||tokens.contains("sameorigin")||tokens.size()>1&&tokens.contains("allowall");
    }
    static boolean hasFrameAncestors(String csp) {
        return csp!=null&&Pattern.compile("(?i)(?:^|[;,\\n])\\s*frame-ancestors(?:\\s|;|,|$)").matcher(csp).find();
    }
    static boolean restrictiveFrameAncestors(String csp,String url) {
        if(csp==null)return false;
        URI origin;try{origin=URI.create(url);}catch(IllegalArgumentException e){return false;}
        for(String policy:csp.split("[,\\n]"))for(String directive:policy.split(";")) {
            String[] parts=directive.trim().split("\\s+");
            if(!parts[0].equalsIgnoreCase("frame-ancestors"))continue;
            if(parts.length==1||parts.length==2&&parts[1].equalsIgnoreCase("'none'"))return true;
            boolean safe=true;
            for(int i=1;i<parts.length;i++) {
                if(parts[i].equalsIgnoreCase("'self'")||parts[i].equalsIgnoreCase("'none'"))continue;
                try { URI source=URI.create(parts[i]);
                    if(source.getHost()==null||!source.getHost().equalsIgnoreCase(origin.getHost())
                            ||!Objects.equals(source.getScheme(),origin.getScheme())||port(source)!=port(origin))safe=false;
                }catch(IllegalArgumentException e){safe=false;}
            }
            if(safe)return true;
            break;
        }
        return false;
    }
    private static int port(URI u){return u.getPort()>=0?u.getPort():"https".equals(u.getScheme())?443:80;}
    /** Linear token/quoted-string decoding; recursive regexes can overflow on long header values. */
    static String decodeDirectiveValue(String value) {
        if(value==null||value.isEmpty())return null;
        if(value.charAt(0)!='"')return value.chars().allMatch(HeaderReportContext::tokenChar)?value:null;
        if(value.length()<2||value.charAt(value.length()-1)!='"')return null;
        StringBuilder decoded=new StringBuilder();
        for(int i=1;i<value.length()-1;i++) {
            char c=value.charAt(i);
            if(c=='\\') {
                if(++i>=value.length()-1)return null;
                c=value.charAt(i);
            } else if(c=='"')return null;
            if(c<32||c==127)return null;
            decoded.append(c);
        }
        return decoded.toString();
    }
    private static boolean tokenChar(int c) {
        return c>='0'&&c<='9'||c>='A'&&c<='Z'||c>='a'&&c<='z'||"!#$%&'*+-.^_`|~".indexOf(c)>=0;
    }
    static HeaderFinding hsts(String v) {
        if(v==null||v.isBlank())return null;
        String first=v.split("\\n",2)[0],age=null;boolean invalid=false,preload=false;Set<String> seen=new HashSet<>();
        for(String raw:splitQuoted(first,';')) {
            if(raw.isBlank())continue;
            String[] pair=raw.trim().split("=",2);String name=pair[0].trim().toLowerCase(Locale.ROOT);
            if(!name.matches("[!#$%&'*+.^_`|~0-9a-z-]+")||!seen.add(name))invalid=true;
            String val=pair.length==2?pair[1].trim():null;
            if(val!=null) {
                val=decodeDirectiveValue(val);
                if(val==null)invalid=true;
            }
            if(name.equals("max-age")){age=val;if(val==null||!val.matches("[0-9]+"))invalid=true;}
            if(name.equals("includesubdomains")&&val!=null)invalid=true;
            if(name.equals("preload")&&val==null)preload=true;
        }
        String title,desc;Severity severity;
        if(invalid||age==null) {
            title="Invalid HSTS policy";severity=Severity.MEDIUM;
            desc="The first HSTS field has missing/invalid max-age or duplicate/invalid directives and is ignored. "
                    +"Later field lines do not replace it. A previously stored or inherited policy may still protect this host.";
        }else if(new java.math.BigInteger(age).signum()==0) {
            title="HSTS policy explicitly disabled (max-age=0)";severity=Severity.MEDIUM;
            desc="This removes the host's dynamic policy. Parent includeSubDomains and preload coverage are not removed; "
                    +"total browser downgrade exposure is not proven.";
        }else if(preload&&new java.math.BigInteger(age).compareTo(java.math.BigInteger.valueOf(31536000))<0) {
            title="HSTS preload max-age requirement not met";severity=Severity.INFORMATION;
            desc="This valid policy declares preload with max-age below 31536000 seconds. This is an eligibility observation. "
                    +"Short policy lifetimes can be intentional deployment choices.";
        }else return null;
        return new HeaderFinding(title,"Strict-Transport-Security",v,desc,"First HSTS field: "+first,severity,Confidence.CERTAIN,
                severity==Severity.INFORMATION?HeaderFinding.Category.ADVISABLE:HeaderFinding.Category.SECURITY_MISCONFIGURED,
                "https://www.rfc-editor.org/rfc/rfc6797.html#section-8.1");
    }
    static boolean mimeRelevant(Map<String,String> h,Map<String,String> req,String url,int status,String body,String method) {
        if(noDocument(status,method,body,h)||status>=400)return false;
        String dest=get(req,"Sec-Fetch-Dest").trim().toLowerCase(Locale.ROOT),type=mime(h);
        if(Set.of("worker","sharedworker","serviceworker","audioworklet","paintworklet").contains(dest))return false;
        if(dest.equals("style")&&!get(req,"Origin").isBlank()&&!sameOrigin(url,get(req,"Origin"))&&!type.equals("text/css"))return false;
        if(body!=null&&html(body)&&(dest.equals("script")||dest.equals("style")))return false;
        if(dest.equals("document")&&type.isBlank()&&html(body))return true;
        return HeaderAnalysisEngine.isMimeSniffingRelevant(h,req,url,method);
    }
    private static HeaderFinding referrer(HeaderFinding f,String body,Map<String,String> h,boolean redirect) {
        String evidence=f.evidence;
        if(!redirect&&body!=null&&mime(h).contains("html")) {
            List<String> tags=activeTags(body);
            String policy=null;
            for(String tag:tags) {
                if(!tag.matches("(?is)<meta(?=[\\t\\n\\f\\r />]).*"))continue;
                Map<String,String> attrs=attributes(tag);
                if("referrer".equalsIgnoreCase(attrs.get("name"))&&validReferrer(attrs.get("content")))policy=attrs.get("content");
            }
            if(policy!=null) {
                if(HeaderAnalysisEngine.analyzeReferrerPolicy(policy)==null)
                    return copy(f,"Referrer policy overridden in document","A meta policy changes subsequent requests. "
                            +"Earlier loads and element-level policies require individual review.",evidence+" Meta policy: "+policy,
                            Severity.INFORMATION,Confidence.FIRM,f.category);
                evidence+=" Meta policy: "+policy;
            }
            int overrides=0;
            for(String tag:tags) {
                if(!tag.matches("(?is)<(?:a|area|img|iframe|link|script)(?=[\\t\\n\\f\\r />]).*"))continue;
                Map<String,String> attrs=attributes(tag);
                boolean anchor=tag.matches("(?is)<(?:a|area)(?=[\\t\\n\\f\\r />]).*");
                if(validReferrer(attrs.get("referrerpolicy")) || anchor && Arrays.asList(attrs.getOrDefault("rel","")
                        .toLowerCase(Locale.ROOT).split("\\s+")).contains("noreferrer")) overrides++;
            }
            evidence+=" Per-element referrer overrides observed: "+overrides+". These affect only their own requests, not every load.";
        }
        return copy(f,f.issueName,f.description+" No sensitive URL disclosure has been verified. "
                +(redirect?"This redirect policy affects the next request in its chain.":"Evaluate each outgoing request's effective policy."),
                evidence,f.severity,f.confidence,f.category);
    }
    private static boolean sameOrigin(String left,String right) {
        try {
            URI a=URI.create(left),b=URI.create(right);
            return a.getHost()!=null && b.getHost()!=null && a.getHost().equalsIgnoreCase(b.getHost())
                    && Objects.equals(a.getScheme(),b.getScheme()) && port(a)==port(b);
        } catch(IllegalArgumentException e) { return false; }
    }

    /** Conservative lexical HTML context: quoted attributes, raw text and inert templates do
     * not expose their embedded strings as active tags. This is not a DOM execution claim. */
    private static List<String> activeTags(String body) {
        List<String> tags=new ArrayList<>();
        if(body==null)return tags;
        int i=0,templateDepth=0;
        while(i<body.length()) {
            int start=body.indexOf('<',i);if(start<0)break;
            if(body.startsWith("<!--",start)) {
                int end=body.indexOf("-->",start+4);if(end<0)break;
                i=end+3;continue;
            }
            int cursor=start+1;
            boolean closing=cursor<body.length()&&body.charAt(cursor)=='/';if(closing)cursor++;
            int nameStart=cursor;
            if(cursor>=body.length() || !((body.charAt(cursor)>='A'&&body.charAt(cursor)<='Z')
                    || (body.charAt(cursor)>='a'&&body.charAt(cursor)<='z'))) {i=start+1;continue;}
            while(cursor<body.length()&&!htmlSpace(body.charAt(cursor))&&body.charAt(cursor)!='/'&&body.charAt(cursor)!='>')cursor++;
            String name=body.substring(nameStart,cursor).toLowerCase(Locale.ROOT);
            char quote=0;
            while(cursor<body.length()) {
                char c=body.charAt(cursor);
                if(quote!=0){if(c==quote)quote=0;}
                else if(c=='\"'||c=='\'')quote=c;
                else if(c=='>')break;
                cursor++;
            }
            if(cursor==body.length())break;
            i=cursor+1;
            if(name.equals("template")) {
                templateDepth=closing?Math.max(0,templateDepth-1):templateDepth+1;continue;
            }
            if(!closing&&templateDepth==0)tags.add(body.substring(start,i));
            if(!closing&&name.equals("plaintext"))break;
            if(!closing&&Set.of("script","style","textarea","title","xmp","iframe","noembed","noframes","noscript").contains(name)) {
                Matcher end=Pattern.compile("(?is)</"+name+"\\s*>").matcher(body);
                if(!end.find(i))break;
                i=end.end();
            }
        }
        return tags;
    }
    private static boolean validReferrer(String value) {
        return value != null && Set.of("no-referrer","no-referrer-when-downgrade","origin","origin-when-cross-origin",
                "same-origin","strict-origin","strict-origin-when-cross-origin","unsafe-url").contains(value.toLowerCase(Locale.ROOT));
    }
    private static boolean htmlSpace(char c) {
        return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\f';
    }
    private static Map<String,String> attributes(String tag) {
        Map<String,String> out=new HashMap<>();
        int i=1;
        while(i<tag.length()&&!htmlSpace(tag.charAt(i))&&tag.charAt(i)!='>')i++;
        while(i<tag.length()) {
            while(i<tag.length()&&(htmlSpace(tag.charAt(i))||tag.charAt(i)=='/'))i++;
            if(i>=tag.length()||tag.charAt(i)=='>')break;
            int start=i;
            while(i<tag.length()&&!htmlSpace(tag.charAt(i))&&tag.charAt(i)!='='&&tag.charAt(i)!='>'&&tag.charAt(i)!='/')i++;
            if(start==i){i++;continue;}
            String name=tag.substring(start,i).toLowerCase(Locale.ROOT);
            while(i<tag.length()&&htmlSpace(tag.charAt(i)))i++;
            String value="";
            if(i<tag.length()&&tag.charAt(i)=='=') {
                i++;
                while(i<tag.length()&&htmlSpace(tag.charAt(i)))i++;
                if(i<tag.length()&&(tag.charAt(i)=='\"'||tag.charAt(i)=='\'')) {
                    char quote=tag.charAt(i++);start=i;
                    while(i<tag.length()&&tag.charAt(i)!=quote)i++;
                    value=tag.substring(start,i);if(i<tag.length())i++;
                } else {
                    start=i;
                    while(i<tag.length()&&!htmlSpace(tag.charAt(i))&&tag.charAt(i)!='>')i++;
                    value=tag.substring(start,i);
                }
            }
            // HTML keeps the first attribute, even if it has no explicit value.
            out.putIfAbsent(name,value);
        }
        return out;
    }
    static String sourcePath(String v) {
        if(v==null||v.length()>16384)return null;
        try {String path=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Base64.getDecoder().decode(v.trim()))).toString();
            if(path.chars().anyMatch(c->c<32||c==127))return null;
            return path.matches("(?s)(?:[A-Za-z]:[\\\\/].+|/[^/].+|\\\\\\\\[^\\\\]+\\\\.+)")?path:null;
        }catch(IllegalArgumentException|CharacterCodingException e){return null;}
    }
}
