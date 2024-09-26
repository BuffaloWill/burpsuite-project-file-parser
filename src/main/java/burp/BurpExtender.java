package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.issues.*;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import com.google.gson.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private Proxy proxy;
    private Scanner scanner;
    private SiteMap siteMap;
    private UserInterface userInterface;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.proxy = api.proxy();
        this.scanner = api.scanner();
        this.siteMap = api.siteMap();
        this.userInterface = api.userInterface();

        api.extension().setName("BurpSuite Project File Parser");

        String[] args = api.burpSuite().commandLineArguments().toArray(new String[0]);
        logging.logToOutput(String.join(" ", args));

        boolean proceed = false;

        if (containsAny(args, "auditItems", "proxyHistory", "siteMap", "responseHeader", "responseBody")) {
            proceed = true;
        } else {
            logging.logToOutput("{\"Message\":\"No flags provided, assuming the initial load of extension.\"}");
            return;
        }

        if (contains(args, "proxyHistory")) {
            printProxyHistory(proxy.history(), args);
        }

        if (contains(args, "auditItems")) {
            printAuditItems();
        }

        if (contains(args, "siteMap")) {
            printHistory(siteMap.requestResponses(), args);
        }

        boolean responseHeader = false;
        boolean responseBody = false;
        String regex = "";

        for (String arg : args) {
            if (arg.startsWith("responseHeader=")) {
                responseHeader = true;
                regex = arg.split("=")[1];
            } else if (arg.startsWith("responseBody=")) {
                responseBody = true;
                regex = arg.split("=")[1];
            }
        }

        if (responseHeader || responseBody) {
            processResponses(responseHeader, responseBody, regex);
        }

        if (proceed) {
            logging.logToOutput("{\"Message\":\"Project File Parsing Complete\"}");
            api.extension().unload();
            api.burpSuite().shutdown();
        }
    }

    private void printHistory(List<HttpRequestResponse> history, String[] args) {
        for (HttpRequestResponse reqRes : history) {
            try {
                JsonObject jsonOutput = new JsonObject();

                HttpRequest request = reqRes.request();
                JsonObject jsonRequest = new JsonObject();
                jsonRequest.addProperty("url", request.url());
                jsonRequest.add("headers", headersToJsonArray(request.headers()));
                jsonRequest.addProperty("body", request.bodyToString());
                jsonOutput.add("request", jsonRequest);

                if ((args.toString().contains("response") || args.toString().contains("both")) && reqRes.response() != null) {
                    HttpResponse response = reqRes.response();
                    JsonObject jsonResponse = new JsonObject();
                    jsonResponse.add("headers", headersToJsonArray(response.headers()));
                    jsonResponse.addProperty("body", response.bodyToString());
                    jsonOutput.add("response", jsonResponse);
                }

                if (!jsonOutput.entrySet().isEmpty()) {
                    logging.logToOutput(jsonOutput.toString());
                }
            } catch (Exception e) {
                logging.logToOutput("Error processing request/response: " + e.getMessage());
            }
        }
    }

    private void printProxyHistory(List<ProxyHttpRequestResponse> history, String[] args) {
        for (ProxyHttpRequestResponse reqRes : history) {
            try {
                JsonObject jsonOutput = new JsonObject();

                HttpRequest request = reqRes.request();
                JsonObject jsonRequest = new JsonObject();
                jsonRequest.addProperty("url", request.url()+request.query());
                jsonRequest.add("headers", headersToJsonArray(request.headers()));
                jsonRequest.addProperty("body", request.bodyToString());
                jsonOutput.add("request", jsonRequest);

                boolean containsResponse = false;
                for (String arg : args) {
                    if (arg.contains("response") || arg.contains("both")) {
                        containsResponse = true;
                    }
                }

                if (containsResponse && reqRes.response() != null) {
                    HttpResponse response = reqRes.response();
                    JsonObject jsonResponse = new JsonObject();
                    jsonResponse.add("response-headers", headersToJsonArray(response.headers()));
                    jsonResponse.addProperty("response-body", response.bodyToString());
                    jsonOutput.add("response", jsonResponse);
                }

                if (!jsonOutput.entrySet().isEmpty()) {
                    logging.logToOutput(jsonOutput.toString());
                }
            } catch (Exception e) {
                logging.logToOutput("Error processing request/response: " + e.getMessage());
            }
        }
    }

    private JsonElement headersToJsonArray(List<HttpHeader> headers) {
        JsonArray jsonHeaders = new JsonArray();
        for (HttpHeader header : headers) {
            jsonHeaders.add(header.toString());
        }
        return jsonHeaders;
    }

    private void printAuditItems() {
        List<AuditIssue> issues = siteMap.issues();

        for (AuditIssue issue : issues) {
            issueToJson(issue);
        }
    }

    private void processResponses(boolean responseHeader, boolean responseBody, String regex) {
        Pattern pattern = Pattern.compile(regex);
        List<ProxyHttpRequestResponse> allProxyRequests = new ArrayList<>(proxy.history());

        for (ProxyHttpRequestResponse reqRes : allProxyRequests) {
            try {
                if (reqRes.response() == null) continue;

                String url = reqRes.request().url();
                List<HttpHeader> responseHeaders = reqRes.response().headers();
                String responseBodyStr = reqRes.response().bodyToString();

                if (responseHeader) {
                    for (HttpHeader header : responseHeaders) {
                        if (pattern.matcher(header.toString()).find()) {
                            logging.logToOutput("{\"url\":\"" + url + "\",\"header\":\"" + header.toString() + "\"}");
                        }
                    }
                }

                if (responseBody) {
                    if (pattern.matcher(responseBodyStr).find()) {
                        logging.logToOutput("{\"url\":\"" + url + "\",\"body\":" + responseBodyStr + "}");
                    }
                }

            } catch (Exception e) {
                logging.logToError(e);
            }
        }
    }

    private void issueToJson(AuditIssue auditIssue) {
        Map<String, Object> issueMap = new HashMap<>();

        issueMap.put("name", auditIssue.name());
        issueMap.put("severity", auditIssue.severity().toString());
        issueMap.put("confidence", auditIssue.confidence().toString());
        issueMap.put("host", auditIssue.httpService().host());
        issueMap.put("port", auditIssue.httpService().port());
        issueMap.put("protocol", auditIssue.httpService().secure() ? "https" : "http");
        issueMap.put("url", auditIssue.baseUrl());

        Gson gson = new Gson();

        String json = gson.toJson(issueMap);
        logging.logToOutput(json);
    }

    private boolean contains(String[] args, String flag) {
        for (String arg : args) {
            if (arg.contains(flag)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAny(String[] args, String... flags) {
        for (String flag : flags) {
            if (contains(args, flag)) {
                return true;
            }
        }
        return false;
    }

}