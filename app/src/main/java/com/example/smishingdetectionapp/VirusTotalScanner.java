package com.example.smishingdetectionapp;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;

public class VirusTotalScanner extends AppCompatActivity {

    private static final String VT_API_KEY = "e02aa771b39881b01a39696594554735363695dc088e53240bbb74c864be75cc";
    private static final String GSB_API_KEY = "AIzaSyBlU6Oza2_spFW7apJ3Nw_QMQZ3hUNgU2k";

    private EditText editTextDomain;
    private Button buttonScan, buttonVTDetails, buttonGSBDetails;
    private ProgressBar progressBar;
    private TextView verdictTextView;
    private ImageView verdictIcon;
    private ImageButton backButton;

    private String vtVerdict = "Unknown";
    private String gsbVerdict = "Unknown";

    private String vtFullJson = "";
    private String gsbFullJson = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_virustotal_scanner);

        bindViews();
        setupListeners();
        resetUI();
    }

    private void bindViews() {
        editTextDomain = findViewById(R.id.editTextDomain);
        buttonScan = findViewById(R.id.buttonScan);
        buttonVTDetails = findViewById(R.id.buttonVTDetails);
        buttonGSBDetails = findViewById(R.id.buttonGSBDetails);
        progressBar = findViewById(R.id.progressBar);
        verdictTextView = findViewById(R.id.verdictTextView);
        verdictIcon = findViewById(R.id.verdictIcon);
        backButton = findViewById(R.id.backbuton);
    }

    private void setupListeners() {
        buttonScan.setOnClickListener(v -> startScan());
        buttonVTDetails.setOnClickListener(v -> openReport("VirusTotal Report", vtFullJson));
        buttonGSBDetails.setOnClickListener(v -> openReport("Google Safe Browsing Report", gsbFullJson));
        backButton.setOnClickListener(v -> finish());
    }

    private void resetUI() {
        progressBar.setVisibility(View.GONE);
        buttonVTDetails.setVisibility(View.GONE);
        buttonGSBDetails.setVisibility(View.GONE);
        verdictTextView.setText("");
        verdictIcon.setImageDrawable(null);
    }

    private void startScan() {
        String input = editTextDomain.getText().toString().trim();

        if (input.isEmpty()) {
            Toast.makeText(this, "Please enter a URL or domain", Toast.LENGTH_SHORT).show();
            return;
        }

        String domain = extractDomain(input);

        if (domain.isEmpty()) {
            Toast.makeText(this, "Invalid URL or domain entered", Toast.LENGTH_SHORT).show();
            return;
        }

        resetUI();
        progressBar.setVisibility(View.VISIBLE);
        buttonScan.setEnabled(false);

        new ScanTask().execute(domain);
    }

    private void openReport(String title, String reportJson) {
        Intent intent = new Intent(this, ReportDetailsActivity.class);
        intent.putExtra("title", title);
        intent.putExtra("report", reportJson);
        startActivity(intent);
    }

    /**
     * Extracts the domain from a URL or domain string.
     */
    private String extractDomain(String urlOrDomain) {
        try {
            String domain = urlOrDomain.toLowerCase();

            if (domain.startsWith("http://")) {
                domain = domain.substring(7);
            } else if (domain.startsWith("https://")) {
                domain = domain.substring(8);
            }

            int slashIndex = domain.indexOf('/');
            if (slashIndex != -1) {
                domain = domain.substring(0, slashIndex);
            }

            if (domain.startsWith("www.")) {
                domain = domain.substring(4);
            }

            // Validate domain format
            if (domain.isEmpty() || !domain.contains(".")) {
                return "";
            }

            return domain;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * AsyncTask to perform API calls and heuristics off the UI thread.
     */
    private class ScanTask extends AsyncTask<String, Void, String> {
        private String error = "";
        private boolean heuristicFlag = false;

        @Override
        protected String doInBackground(String... params) {
            String domain = params[0];
            OkHttpClient client = new OkHttpClient();

            // VirusTotal API call
            Request vtRequest = new Request.Builder()
                    .url("https://www.virustotal.com/api/v3/domains/" + domain)
                    .get()
                    .addHeader("x-apikey", VT_API_KEY)
                    .build();

            try (Response response = client.newCall(vtRequest).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    vtFullJson = response.body().string();
                    parseVirusTotalResult(vtFullJson);
                } else {
                    error += "VirusTotal error: " + response.code() + "\n";
                    vtFullJson = "";
                    vtVerdict = "Unknown";
                }
            } catch (IOException e) {
                error += "VirusTotal request failed: " + e.getMessage() + "\n";
                vtFullJson = "";
                vtVerdict = "Unknown";
            }

            // Google Safe Browsing API call
            String gsbPayload = "{ \"client\": {\"clientId\": \"smishingApp\", \"clientVersion\": \"1.0\"}, " +
                    "\"threatInfo\": { \"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\"], " +
                    "\"platformTypes\": [\"ANY_PLATFORM\"], \"threatEntryTypes\": [\"URL\"], " +
                    "\"threatEntries\": [{\"url\": \"http://" + domain + "\"}] } }";

            Request gsbRequest = new Request.Builder()
                    .url("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GSB_API_KEY)
                    .post(RequestBody.create(gsbPayload, MediaType.parse("application/json")))
                    .build();

            try (Response response = client.newCall(gsbRequest).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    gsbFullJson = response.body().string();
                    parseGSBResult(gsbFullJson);
                } else {
                    error += "Google Safe Browsing error: " + response.code() + "\n";
                    gsbFullJson = "";
                    gsbVerdict = "Unknown";
                }
            } catch (IOException e) {
                error += "Google Safe Browsing request failed: " + e.getMessage() + "\n";
                gsbFullJson = "";
                gsbVerdict = "Unknown";
            }

            // Heuristic analysis
            heuristicFlag = checkSmishingHeuristic(domain);

            return error;
        }

        @Override
        protected void onPostExecute(String errorMsg) {
            progressBar.setVisibility(View.GONE);
            buttonScan.setEnabled(true);

            if (!errorMsg.isEmpty()) {
                Toast.makeText(VirusTotalScanner.this, errorMsg.trim(), Toast.LENGTH_LONG).show();
            }

            updateVerdictUI();
        }

        private void updateVerdictUI() {
            String finalVerdict;

            if (heuristicFlag) {
                finalVerdict = "⚠️ Suspicious smishing characteristics detected!";
                verdictIcon.setImageResource(android.R.drawable.ic_dialog_alert);
            } else if ("Malicious".equals(vtVerdict) || "Malicious".equals(gsbVerdict)) {
                finalVerdict = "⚠️ Malicious website detected!";
                verdictIcon.setImageResource(android.R.drawable.ic_dialog_alert);
            } else if ("Suspicious".equals(vtVerdict)) {
                finalVerdict = "⚠️ Website may be suspicious.";
                verdictIcon.setImageResource(android.R.drawable.ic_dialog_info);
            } else if ("Safe".equals(vtVerdict) && "Safe".equals(gsbVerdict)) {
                finalVerdict = "✅ Website appears safe.";
                verdictIcon.setImageResource(android.R.drawable.ic_menu_info_details);
            } else {
                finalVerdict = "❓ Verdict unknown.";
                verdictIcon.setImageDrawable(null);
            }

            verdictTextView.setText(finalVerdict);

            buttonVTDetails.setVisibility(vtFullJson.isEmpty() ? View.GONE : View.VISIBLE);
            buttonGSBDetails.setVisibility(gsbFullJson.isEmpty() ? View.GONE : View.VISIBLE);
        }
    }

    /**
     * Parses VirusTotal JSON response and sets the verdict accordingly.
     */
    private void parseVirusTotalResult(String json) {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonObject stats = root.getAsJsonObject("data")
                    .getAsJsonObject("attributes")
                    .getAsJsonObject("last_analysis_stats");

            int malicious = stats.get("malicious").getAsInt();
            int suspicious = stats.get("suspicious").getAsInt();

            if (malicious >= 5) {
                vtVerdict = "Malicious";
            } else if (malicious > 0 || suspicious > 0) {
                vtVerdict = "Suspicious";
            } else {
                vtVerdict = "Safe";
            }
        } catch (Exception e) {
            vtVerdict = "Unknown";
        }
    }

    /**
     * Parses Google Safe Browsing JSON response and sets the verdict accordingly.
     */
    private void parseGSBResult(String json) {
        if (json.contains("matches")) {
            gsbVerdict = "Malicious";
        } else if (json.trim().isEmpty() || json.equals("{}")) {
            gsbVerdict = "Safe";
        } else {
            gsbVerdict = "Unknown";
        }
    }

    /**
     * Heuristic checks for suspicious domain patterns common in smishing URLs.
     */
    private boolean checkSmishingHeuristic(String domain) {
        String[] suspiciousKeywords = {
                "login", "verify", "update", "secure", "account", "confirm", "alert", "bank",
                "ebay", "paypal", "amazon", "appleid", "password", "signin", "customer",
                "service", "support", "webscr", "security", "validation", "billing", "invoice",
                "reset", "unlock", "access", "loginsecure", "free", "urgent", "limited",
                "offer", "prize", "bonus", "reward", "claim", "click", "payment", "transaction",
                "fail", "error", "warning"
        };
        domain = domain.toLowerCase();

        for (String keyword : suspiciousKeywords) {
            if (domain.contains(keyword)) {
                return true;
            }
        }

        // Check for suspicious number patterns like long numeric strings
        if (domain.matches(".*\\d{5,}.*")) {
            return true;
        }

        return false;
    }
}
