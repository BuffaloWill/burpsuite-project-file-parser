package burp;

import com.google.gson.Gson;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientURI;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoCollection;
import org.bson.Document;

public class BurpExtender implements IBurpExtender
{
    public class jsonRequest {
        String url;
        List<String> headers;
        String uri;
        String method;
        String httpVersion;
        String body;
    }

    public class jsonResponse {
        String url;
        List<String> headers;
        String code;
        String uri;
        String body;
    }

    public class jsonRequestResponse {
        jsonRequest request;
        jsonResponse response;
    }

    public class auditItem {
        String issueName;
        String url;
        String confidence;
        String severity;
    }

    public jsonRequest requestToJson(String url, List<String> headers, String body){
        jsonRequest jr = new jsonRequest();
        jr.url = url;

        jr.method = headers.get(0).split(" ")[0];
        jr.uri = headers.get(0).split(" ")[1];
        jr.httpVersion = headers.get(0).split(" ")[2];

        headers.remove(0);
        jr.headers = headers;

        jr.body = body;

        return jr;
    }

    public jsonResponse responseToJson(String url, List<String> headers, String body){
        jsonResponse jr = new jsonResponse();
        jr.url = url;

        jr.code = headers.get(0).split(" ")[1];

        headers.remove(0);
        jr.headers = headers;

        jr.body = body;

        return jr;
    }

    public String issueToJson(String url, String confidence, String severity, String issueName){
        auditItem ai = new auditItem();
        ai.url = url;
        ai.confidence = confidence;
        ai.severity = severity;
        ai.issueName = issueName;

        Gson gson = new Gson();
        String reqJson = gson.toJson(ai);

        return reqJson;
    }

    // gather all auditItems and print them to the cli
    public void printAuditItems(PrintWriter stdout, IBurpExtenderCallbacks callbacks){
        IScanIssue[] history = callbacks.getScanIssues(null);

        for (IScanIssue issue : history) {
            stdout.println(issueToJson(issue.getUrl().toString(), issue.getConfidence(), issue.getSeverity(), issue.getIssueName()));
        }
    }

    // taken in a request response history and print out the results
    public void printHistory(PrintWriter stdout, IBurpExtenderCallbacks callbacks, IHttpRequestResponse[] history){
        for (IHttpRequestResponse req : history) {
            try {
                IRequestInfo rInfo = callbacks.getHelpers().analyzeRequest(req.getRequest());

                // URL from request
                String url = req.getHttpService().getProtocol() + "://" + req.getHttpService().getHost() + ":" + req.getHttpService().getPort();
                String uriR = rInfo.getHeaders().get(0).split(" ")[1];
                url = url+uriR;

                // Headers from request
                List<String> headers = rInfo.getHeaders();

                // Body from request
                byte[] bodyl = Arrays.copyOfRange(req.getRequest(), rInfo.getBodyOffset(), req.getRequest().length);
                String body = callbacks.getHelpers().bytesToString(bodyl);

                jsonRequest gr = requestToJson(url, headers, body);

                //get the response
                IResponseInfo rResp = callbacks.getHelpers().analyzeResponse(req.getResponse());

                // Headers from response
                List<String> headers1 = rResp.getHeaders();

                // Body from response
                byte[] bodyR = Arrays.copyOfRange(req.getResponse(), rResp.getBodyOffset(), req.getResponse().length);
                String bodyR1 = callbacks.getHelpers().bytesToString(bodyR);

                jsonResponse gr1 = responseToJson(url, headers1, bodyR1);
                jsonRequestResponse jrr = new jsonRequestResponse();
                jrr.request = gr;
                jrr.response = gr1;

                Gson gson = new Gson();
                String reqJson = gson.toJson(jrr);

                stdout.println(reqJson);
            } catch (Exception e) {
                stdout.println(e.getMessage());
            }
        }

    }

    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("BurpSuite Project File Parser");

        // obtain our output and error streams
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        // write a message to our output stream
        stdout.println("{\"Message\":\"Loaded project file parser.\"}");

        // get CLI args
        List<String> cli = Arrays.asList(callbacks.getCommandLineArguments());

        // check if one of the possible flags is used and shutdown burp when done, otherwise ignore
        boolean proceed = false;

        // print the proxyHistory to stdout
        if(cli.contains("--proxyHistory")) {
            proceed = true;
            IHttpRequestResponse[] history = callbacks.getProxyHistory();
            printHistory(stdout, callbacks, history);
        }

        // print the auditItems to stdout
        if(cli.contains("--auditItems")) {
            proceed = true;
            printAuditItems(stdout, callbacks);
        }

        // print the siteMap to stdout
        if(cli.contains("--siteMap")) {
            proceed = true;
            IHttpRequestResponse[] history = callbacks.getSiteMap(null);
            printHistory(stdout, callbacks, history);
        }

        // search all responseHeaders or responseBodies with a regex
        //      e.g. responseHeader=/nginx/

        boolean responseHeader = false;
        boolean responseBody = false;
        boolean storeData = false;
        String regex="";
        String mongoConnector="";

        for (String temp : cli) {
            if(temp.contains("responseHeader")){
                proceed = true;
                responseHeader = true;
                regex = temp.split("=")[1];
            }else if(temp.contains("responseBody")){
                proceed = true;
                responseBody = true;
                regex = temp.split("=")[1];
            }else if(temp.contains("storeData")){
                proceed = true;
                storeData = true;
                mongoConnector = temp.split("=")[1];
            }
        }

        if(responseHeader || responseBody || storeData) {
            // grab the siteMap
            IHttpRequestResponse[] history = callbacks.getSiteMap(null);
            // grab the proxyHistory
            IHttpRequestResponse[] prHistory = callbacks.getProxyHistory();
            // combine them
            IHttpRequestResponse[] total = Stream.concat(Arrays.stream(history), Arrays.stream(prHistory))
                    .toArray(IHttpRequestResponse[]::new);

            for (IHttpRequestResponse req : total) {
                try {
                    //get the request
                    IRequestInfo rInfo = callbacks.getHelpers().analyzeRequest(req.getRequest());
                    // get response
                    IResponseInfo rResp = callbacks.getHelpers().analyzeResponse(req.getResponse());

                    // URL
                    String uriR = rInfo.getHeaders().get(0).split(" ")[1];
                    String urlR = req.getHttpService().getProtocol() + "://" + req.getHttpService().getHost() + ":" + req.getHttpService().getPort() + uriR;

                    // Request Header
                    List<String> headersReq = rInfo.getHeaders();

                    // Request Body
                    byte[] bodyl = Arrays.copyOfRange(req.getRequest(), rInfo.getBodyOffset(), req.getRequest().length);
                    String bodyReq = callbacks.getHelpers().bytesToString(bodyl);

                    // Response Headers
                    List<String> headers1 = rResp.getHeaders();

                    // ResponseBody
                    byte[] bodyR = Arrays.copyOfRange(req.getResponse(), rResp.getBodyOffset(), req.getResponse().length);
                    String bodyR1 = callbacks.getHelpers().bytesToString(bodyR);

                    // for searching response headers
                    if (responseHeader) {
                        for (String header : headers1) {
                            if (header.length() > 0) {
                                Pattern p = Pattern.compile(regex);
                                Matcher match = p.matcher(header);
                                if (match.matches()) {
                                    stdout.println("{\"url\":\"" + urlR + "\",\"header\":\"" + header + "\"}");
                                }
                            }
                        }
                    }
                    // for searching response body
                    if (responseBody) {
                        if (bodyR1.length() > 0) {
                            Pattern p = Pattern.compile(regex);
                            Matcher match = p.matcher(bodyR1);
                            if (match.matches()) {
                                stdout.println("{\"url\":\"" + urlR + "\",\"body\":" + bodyR1 + "}");
                            }
                        }
                    }

                    if(storeData) {
                        // todo: this is going to create a new mongodb connection for every record
                        // todo: this harcodes the mongo timeout at 1500ms;
                        // todo: no ssl support for mongo?

                        MongoClientOptions.Builder optionsBuilder = MongoClientOptions.builder();
                        optionsBuilder.connectTimeout(1500);
                        optionsBuilder.socketTimeout(1500);
                        MongoClientOptions options = optionsBuilder.build();

                        MongoClientURI connectionString = new MongoClientURI("mongodb://" + mongoConnector.split("/")[0]);
                        MongoClient mongoClient = new MongoClient(mongoConnector.split("/")[0], options);
                        MongoDatabase database = mongoClient.getDatabase(mongoConnector.split("/")[1]);
                        MongoCollection<Document> collection = database.getCollection("httpResponses");
                        MongoCollection<Document> urlCollection = database.getCollection("urls");
                        MongoCollection<Document> collectionReq = database.getCollection("httpRequests");

                        try {
                            // store the url
                            URL urlS = new URL(urlR);
                            Document inurl = new Document("url", urlR);

                            // a duplicate URL will throw an error, catch here
                            urlCollection.insertOne(inurl);
                        }catch (Exception e) {
                            if (e.getMessage().contains("duplicate key error collection") || e.getMessage().contains("key too large to index")){
                                // supress the error
                            }else {
                                stdout.println(e.getMessage());
                            }
                        }

                        // store the request
                        if(bodyReq.length() < 1000000){
                            MessageDigest m = MessageDigest.getInstance("MD5");
                            m.reset();
                            String pt = String.join("\n", headersReq) + "\n\n" + bodyReq;
                            m.update(pt.getBytes());

                            byte[] digest = m.digest();
                            BigInteger bigInt = new BigInteger(1,digest);
                            String hashtext = bigInt.toString(16);

                            while(hashtext.length() < 32 ){
                                hashtext = "0"+hashtext;
                            }

                            Document doc = new Document("url", urlR)
                                    .append("request", pt)
                                    .append("hash", hashtext);
                            try {
                                collectionReq.insertOne(doc);
                            }catch (Exception e) {
                                if (e.getMessage().contains("duplicate key error collection")) {
                                    // supress the error
                                } else {
                                    stdout.println(e.getMessage());
                                }
                            }
                        }

                        // store the response
                        if(bodyR1.length() < 1000000){
                            // check extension not in blacklist
                            int i = urlR.lastIndexOf('.');
                            String ext = "deny";
                            if (i > 0) {
                                ext = urlR.substring(i+1);
                            }

                            final List<String> blackList = Arrays.asList("deny", "png", "jpg", "pdf", "gif", "jpeg");

                            if(!blackList.contains(ext)) {
                                MessageDigest m = MessageDigest.getInstance("MD5");
                                m.reset();
                                String pt = String.join("\n", headers1) + "\n\n" + bodyR1;
                                m.update(pt.getBytes());
                                byte[] digest = m.digest();
                                BigInteger bigInt = new BigInteger(1,digest);
                                String hashtext = bigInt.toString(16);
                                while(hashtext.length() < 32 ){
                                    hashtext = "0"+hashtext;
                                }

                                Document doc = new Document("url", urlR)
                                        .append("response", pt)
                                        .append("hash", hashtext);

                                try {
                                    collection.insertOne(doc);
                                }catch (Exception e) {
                                    if (e.getMessage().contains("duplicate key error collection")){
                                        // supress the error
                                    }else {
                                        stdout.println(e.getMessage());
                                    }
                                }
                            }
                        }
                        mongoClient.close();
                    }
                }catch (Exception e) {
                    if(e.getMessage() == "Response cannot be null"){
                        // todo: suppressing errors caused by empty HTTP responses in project, handle more gracefully
                    }else {
                        e.printStackTrace();
                    }
                }
            }
        }

        if(proceed) {
            stdout.println("{\"Message\":\"Project File Parsing Complete\"}");
            // Close down burpsuite only if this extension was used
            callbacks.exitSuite(false);
        }
    }
}
