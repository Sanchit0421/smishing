package com.example.smishingdetectionapp;

import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;

public class VirusTotalScanner extends AppCompatActivity {

    private static final String TAG = "VirusTotalScanner";
    private static final String API_KEY = "e02aa771b39881b01a39696594554735363695dc088e53240bbb74c864be75cc";

    private EditText editTextDomain;
    private TextView textViewResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_virustotal_scanner);

        editTextDomain = findViewById(R.id.editTextDomain);
        textViewResult = findViewById(R.id.textViewResult);
        Button buttonScan = findViewById(R.id.buttonScan);

        buttonScan.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String domain = editTextDomain.getText().toString().trim();

                if (domain == null || domain.isEmpty()) {
                    Toast.makeText(VirusTotalScanner.this, "Please enter a valid domain URL", Toast.LENGTH_SHORT).show();
                    return;
                }

                scanDomain(domain);
            }
        });
    }

    private void scanDomain(String domain) {
        new VirusTotalTask().execute(domain);
    }

    private class VirusTotalTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... domains) {
            OkHttpClient client = new OkHttpClient();

            Request request = new Request.Builder()
                    .url("https://www.virustotal.com/api/v3/domains/" + domains[0])
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", API_KEY)
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    return "Error: " + response.code() + " - " + response.message();
                }
                return response.body() != null ? response.body().string() : "No response body";
            } catch (IOException e) {
                return "Request failed: " + e.getMessage();
            }
        }

        @Override
        protected void onPostExecute(String result) {
            textViewResult.setText(result);
            Log.d(TAG, "VirusTotal result: " + result);
        }
    }
}

