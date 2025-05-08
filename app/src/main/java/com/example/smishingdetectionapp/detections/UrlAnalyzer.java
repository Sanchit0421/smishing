package com.example.smishingdetectionapp.detections;

import android.util.Log;

import org.json.JSONObject;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import okhttp3.*;

public class UrlAnalyzer {

    private static final String VIRUSTOTAL_API_KEY = "e02aa771b39881b01a39696594554735363695dc088e53240bbb74c864be75cc";
    private static final String SCAN_URL = "https://www.virustotal.com/api/v3/urls";
    private static final String REPORT_BASE_URL = "https://www.virustotal.com/api/v3/analyses/";

    private static final OkHttpClient client = new OkHttpClient();

    public interface UrlAnalysisCallback {
        void onResult(boolean isSuspicious);
    }

    public static List<String> extractUrls(String message) {
        List<String> urls = new ArrayList<>();
        Pattern urlPattern = Pattern.compile("(https?://[\\w-]+(\\.[\\w-]+)+[/#?]?.*)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = urlPattern.matcher(message);

        while (matcher.find()) {
            urls.add(matcher.group());
        }
        return urls;
    }

    public static void isSuspiciousUrl(String url, UrlAnalysisCallback callback) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }

        boolean localSuspicion = url.contains("bit.ly") ||
                url.contains("@") ||
                url.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*") ||
                containsMaliciousKeywords(url);

        if (localSuspicion) {
            callback.onResult(true); // early return
        } else {
            checkWithVirusTotal(url, callback);
        }
    }

    private static void checkWithVirusTotal(String url, UrlAnalysisCallback callback) {
        try {
            RequestBody formBody = new FormBody.Builder()
                    .add("url", url)
                    .build();

            Request request = new Request.Builder()
                    .url(SCAN_URL)
                    .addHeader("x-apikey", VIRUSTOTAL_API_KEY)
                    .post(formBody)
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Log.e("VirusTotal", "Scan POST failed", e);
                    callback.onResult(false); // fallback safe
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    if (!response.isSuccessful()) {
                        callback.onResult(false);
                        return;
                    }

                    try {
                        String body = response.body().string();
                        JSONObject json = new JSONObject(body);
                        String analysisId = json.getJSONObject("data").getString("id");

                        fetchScanResults(analysisId, callback);
                    } catch (Exception e) {
                        Log.e("VirusTotal", "JSON parsing error", e);
                        callback.onResult(false);
                    }
                }
            });

        } catch (Exception e) {
            Log.e("VirusTotal", "Scan error", e);
            callback.onResult(false);
        }
    }

    private static void fetchScanResults(String analysisId, UrlAnalysisCallback callback) {
        Request request = new Request.Builder()
                .url(REPORT_BASE_URL + analysisId)
                .addHeader("x-apikey", VIRUSTOTAL_API_KEY)
                .get()
                .build();

        // Delay before requesting report (VirusTotal might take a moment to scan)
        client.dispatcher().executorService().submit(() -> {
            try {
                Thread.sleep(3000); // Optional wait
            } catch (InterruptedException ignored) {}

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Log.e("VirusTotal", "Report GET failed", e);
                    callback.onResult(false);
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    if (!response.isSuccessful()) {
                        callback.onResult(false);
                        return;
                    }

                    try {
                        String resultBody = response.body().string();
                        JSONObject resultJson = new JSONObject(resultBody);
                        JSONObject stats = resultJson.getJSONObject("data")
                                .getJSONObject("attributes")
                                .getJSONObject("stats");

                        int malicious = stats.optInt("malicious", 0);
                        callback.onResult(malicious > 0);
                    } catch (Exception e) {
                        Log.e("VirusTotal", "JSON parsing failed", e);
                        callback.onResult(false);
                    }
                }
            });
        });
    }

    private static boolean containsMaliciousKeywords(String url) {
        List<String> keywords = List.of(
                "login", "secure", "account", "verify", "password",
                "update", "bank", "paypal", "free", "reward"
        );
        for (String keyword : keywords) {
            if (url.toLowerCase().contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}

