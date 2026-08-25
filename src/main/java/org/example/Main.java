// SPAM EMAIL DETECTOR PROGRAM
// Main.java by Scott Mattera
 // Signature Detector by Daniel Eltz
 //
 // This program will ask for a file containing email contents
 // Add this file to the resources folder in order for it to be used.
 // A spam likeliness score will be given to the file.
 // a 20 or higher will be flagged as spam.
 //
//
package org.example;


import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.github.cdimascio.dotenv.Dotenv;
import org.apache.commons.codec.DecoderException;


import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;

import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;





public class Main {

    public static String cleanContent(String page){
        page = page.replaceAll("=\\r?\\n", "");
        //use this to get rid of encoding from email txt files
        page = page.replaceAll("(?:=[0-9A-Fa-f]{2})+$", "");
        page = page.replaceAll("[\"'>]+$", "");
        page = page.replaceAll("[;\\]]+$", "");
        return page;
    }

    public static int readEmail(InputStream email) throws IOException, DecoderException {

        int spamScore = 0;
        boolean unsubscribeStatus = false;


        String content = new String(email.readAllBytes(), StandardCharsets.UTF_8);

        //-------signature detection
        boolean checkHash = SignatureDetector.isSpam(content);
        if (checkHash){
            System.out.println("WARNING: signature match, email is known spam.");
            return 100;
        }


        content = content.replaceAll("=\\r?\\n", "");
        content = content.replace("=3D", "=");



        //------------URL DETECTION-----------
        long httpCount = 0;
        if (content.contains("http://")){
            httpCount = Pattern.compile(Pattern.quote("http://")).matcher(content).results().count();
            System.out.println("WARNING: " + httpCount + " http link(s) found, no certificates possible with this protocol.");
            spamScore += (int) httpCount * 3;
        }
        //this matcher stuff is for finding urls in the email file.
        Pattern urlPattern = Pattern.compile("https://[^\\s<>\"')\\]]+");
        Matcher matcher = urlPattern.matcher(content);
        ArrayList<String> urls = new ArrayList<>();
        while (matcher.find()) {

            var urlTypes = Set.of(".com", ".net", ".edu", ".org", ".co", ".io", ".eu", ".us", ".blog", ".biz",
                    ".int", ".gov", ".mil", ".fr", ".de", ".es", ".jp");
            if (urlTypes.stream().anyMatch(t -> matcher.group().contains(t))){
                String url = matcher.group();
                url = cleanContent(url);
                urls.add(url);

            }
        }



        //--------------AI DETECTION----------------


        Gson gson = new Gson();
        String json = new Gson().toJson(content);

        String aiPrompt = """
                {
                "model": "gpt-5.4-nano",
                "input": %s,
                 "prompt": {
                    "id": "pmpt_69ea1128affc8196a8802b3041601d45023e92ea52c92e63",   
                    "version": ""
                  }
                }
                
                
                """.formatted(json);
        HttpClient httpGPT = HttpClient.newHttpClient();
        Dotenv dotenv = Dotenv.load();
        String API_KEY = dotenv.get("API_KEY");
        HttpRequest gptRequest = HttpRequest.newBuilder()
                .uri(URI.create("https://api.openai.com/v1/responses"))
                .header("Authorization", "Bearer " + API_KEY)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(aiPrompt))
                .build();
        try {
            HttpResponse<String> response = httpGPT.send(gptRequest, HttpResponse.BodyHandlers.ofString());

            JsonObject root = gson.fromJson(response.body(), JsonObject.class);
            JsonArray output = root.getAsJsonArray("output");
            String decision = "";
            for (JsonElement e : output){
                JsonObject outputObj = e.getAsJsonObject();
                if (outputObj.has("content")){
                    JsonArray returnContent = outputObj.getAsJsonArray("content");
                    for (JsonElement ee : returnContent){
                        JsonObject contentObj = ee.getAsJsonObject();
                        if (contentObj.get("type").getAsString().equals("output_text")){
                            decision = contentObj.get("text").getAsString();
                            break;
                        }
                    }
                }
            }
            if(decision.equals("spam")){
                System.out.println("WARNING: AI Detects spam");
                spamScore += 30;
            } else if (decision.equals("not spam")){
                spamScore -= 10;
                System.out.println("AI Declares not spam.");
            } else if (!decision.isEmpty()){
                spamScore += 10;
                System.out.println("WARNING: AI Detects possible spam");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }



        //---------CERTIFICATE DETECTION---------
        System.out.println(urls.size() + " HTTPS protocol URLs found.");
        for (String url : urls){
            try {
                URL link = new URL(url);
                try {
                    //if this connection fails, the website had an invalid certificate.
                    // can be tested with email.txt, which has a bad cert link in it.
                    HttpsURLConnection connection = (HttpsURLConnection) link.openConnection();
                    connection.connect();
                } catch (SSLHandshakeException e){
                    System.out.println("WARNING: LINK WITH NO CERTIFICATES FOUND!");
                    spamScore += 40;
                } catch (UnknownHostException e){
                    System.out.println("WARNING: INVALID LINK FOUND");
                    spamScore += 10;
                } catch (ConnectException e){
                    System.out.println("Connection timeout");
                }
            } catch (Exception e) {

                e.printStackTrace();
            }
        }
        //-----CHECK FOR UNSUBSCRIBE OPTION-----
        var unsubscribeOptions = Set.of("list-unsubscribe", "mailto:unsubscribe", "list-unsubscribe-post");
        if (unsubscribeOptions.stream().anyMatch(content.toLowerCase()::contains)){
            unsubscribeStatus = true;
        }

        if (unsubscribeStatus){
            System.out.println("Unsubscribe found, email less likely to be spam.");
            spamScore -= 10;
        } else{
            System.out.println("WARNING: No unsubscribe option found, increased odds of being spam.");
            spamScore += 20;
        }
        if (httpCount > urls.size()){
            System.out.println("More HTTP links than HTTPS, spam suspected.");
            spamScore += 20;
        }

        if (spamScore < 0){
            spamScore = 0;
        }
        return spamScore;
    }

    public static void main(String[] args) throws IOException, DecoderException {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter email filename: ");
            String emailName = "/" + scanner.nextLine();
            InputStream email = Main.class.getResourceAsStream(emailName);
            int score = readEmail(email);
            if (score >= 20) {
                System.out.println("WARNING: SPAM EMAIL DETECTED WITH A SCORE OF " + score);
                if (score <= 30) {
                    System.out.println("Note: Score is less than or equal to 30, audit for false flag recommended.");
                }
            } else {
                System.out.println("Email is clear, spam score of " + score);
            }
        }



}