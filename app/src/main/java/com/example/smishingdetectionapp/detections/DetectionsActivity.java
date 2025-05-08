package com.example.smishingdetectionapp.detections;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.*;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.smishingdetectionapp.MainActivity;
import com.example.smishingdetectionapp.R;
import com.google.android.material.bottomsheet.BottomSheetDialog;

import org.json.JSONObject;

import java.io.IOException;

import okhttp3.*;

public class DetectionsActivity extends AppCompatActivity {

    private static final String API_KEY = "e02aa771b39881b01a39696594554735363695dc088e53240bbb74c864be75cc";

    private ListView detectionLV;
    private DatabaseAccess databaseAccess;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_detections);

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            v.setPadding(
                    insets.getInsets(WindowInsetsCompat.Type.systemBars()).left,
                    insets.getInsets(WindowInsetsCompat.Type.systemBars()).top,
                    insets.getInsets(WindowInsetsCompat.Type.systemBars()).right,
                    insets.getInsets(WindowInsetsCompat.Type.systemBars()).bottom
            );
            return insets;
        });

        setupUI();
    }

    private void setupUI() {
        detectionLV = findViewById(R.id.lvDetectionsList);
        databaseAccess = new DatabaseAccess(this);
        databaseAccess.open();

        refreshList();
        setupBackButton();
        setupSearchBox();
        setupFilterDialog();
        setupDeleteOnLongPress();
        setupUrlScanDialog();
    }

    private void setupBackButton() {
        ImageButton back = findViewById(R.id.detections_back);
        back.setOnClickListener(v -> {
            clearRadioButtonState();
            startActivity(new Intent(this, MainActivity.class));
            finish();
        });
    }

    private void setupSearchBox() {
        EditText searchBox = findViewById(R.id.searchTextBox);
        searchBox.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void afterTextChanged(Editable s) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                searchDB(s.toString());
            }
        });
    }

    private void setupFilterDialog() {
        ImageView filterBtn = findViewById(R.id.filterBtn);
        SharedPreferences prefs = getSharedPreferences("RadioPrefs", MODE_PRIVATE);

        filterBtn.setOnClickListener(v -> {
            View sheet = getLayoutInflater().inflate(R.layout.popup_filter, null);
            BottomSheetDialog dialog = new BottomSheetDialog(this);
            dialog.setContentView(sheet);
            dialog.show();

            RadioButton oldToNew = sheet.findViewById(R.id.OldToNewRB);
            RadioButton newToOld = sheet.findViewById(R.id.NewToOldRB);

            oldToNew.setChecked(prefs.getBoolean("OldToNewRB", false));
            newToOld.setChecked(prefs.getBoolean("NewToOldRB", false));

            oldToNew.setOnCheckedChangeListener((b, checked) -> {
                if (checked) {
                    newToOld.setChecked(false);
                    sortONDB();
                }
                saveRadioButtonState("OldToNewRB", checked);
            });

            newToOld.setOnCheckedChangeListener((b, checked) -> {
                if (checked) {
                    oldToNew.setChecked(false);
                    sortNODB();
                }
                saveRadioButtonState("NewToOldRB", checked);
            });
        });
    }

    private void setupDeleteOnLongPress() {
        detectionLV.setOnItemLongClickListener((parent, view, position, id) -> {
            View sheet = getLayoutInflater().inflate(R.layout.popup_deleteitem, null);
            BottomSheetDialog dialog = new BottomSheetDialog(this);
            dialog.setContentView(sheet);
            dialog.show();

            sheet.findViewById(R.id.delItemCancel).setOnClickListener(v -> dialog.dismiss());
            sheet.findViewById(R.id.DelItemConfirm).setOnClickListener(v -> {
                deleteRow(String.valueOf(id));
                refreshList();
                Toast.makeText(this, "Detection Deleted!", Toast.LENGTH_SHORT).show();
                dialog.dismiss();
            });

            return true;
        });
    }

    private void setupUrlScanDialog() {
        Button urlButton = findViewById(R.id.btnCheckUrl);
        urlButton.setOnClickListener(v -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Enter URL for Detection");

            EditText input = new EditText(this);
            input.setHint("https://example.com");
            input.setInputType(android.text.InputType.TYPE_TEXT_VARIATION_URI);
            LinearLayout layout = new LinearLayout(this);
            layout.setPadding(50, 40, 50, 10);
            layout.addView(input);

            builder.setView(layout);
            builder.setPositiveButton("Detect", (dialog, which) -> {
                String url = input.getText().toString().trim();
                if (url.isEmpty()) {
                    Toast.makeText(this, "URL cannot be empty", Toast.LENGTH_SHORT).show();
                } else {
                    new VirusTotalUrlScanTask().execute(url);
                }
            });
            builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
            builder.show();
        });
    }

    private class VirusTotalUrlScanTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... urls) {
            OkHttpClient client = new OkHttpClient();
            String url = urls[0];

            try {
                // Submit URL using FormBody instead of JSON
                RequestBody body = new FormBody.Builder()
                        .add("url", url)
                        .build();

                Request postRequest = new Request.Builder()
                        .url("https://www.virustotal.com/api/v3/urls")
                        .addHeader("x-apikey", API_KEY)
                        .post(body)
                        .build();

                Response postResp = client.newCall(postRequest).execute();
                if (!postResp.isSuccessful()) return "Failed to submit: " + postResp.code();

                String analysisId = new JSONObject(postResp.body().string())
                        .getJSONObject("data").getString("id");

                Thread.sleep(3000); // wait before fetching result

                Request getRequest = new Request.Builder()
                        .url("https://www.virustotal.com/api/v3/analyses/" + analysisId)
                        .addHeader("x-apikey", API_KEY)
                        .get()
                        .build();

                Response getResp = client.newCall(getRequest).execute();
                return getResp.body() != null ? getResp.body().string() : "No response body";

            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        @Override
        protected void onPostExecute(String result) {
            try {
                JSONObject json = new JSONObject(result);
                JSONObject stats = json.getJSONObject("data")
                        .getJSONObject("attributes")
                        .getJSONObject("stats");

                String msg = "Harmless: " + stats.optInt("harmless", 0) +
                        "\nMalicious: " + stats.optInt("malicious", 0) +
                        "\nSuspicious: " + stats.optInt("suspicious", 0) +
                        "\nUndetected: " + stats.optInt("undetected", 0);

                new AlertDialog.Builder(DetectionsActivity.this)
                        .setTitle("Scan Result")
                        .setMessage(msg)
                        .setPositiveButton("OK", null)
                        .show();

            } catch (Exception e) {
                new AlertDialog.Builder(DetectionsActivity.this)
                        .setTitle("Raw Result")
                        .setMessage(result)
                        .setPositiveButton("OK", null)
                        .show();
            }
        }
    }

    private void refreshList() {
        Cursor cursor = DatabaseAccess.db.rawQuery("SELECT * FROM Detections", null);
        detectionLV.setAdapter(new DisplayDataAdapterView(this, cursor));
    }

    private void searchDB(String text) {
        String wildcard = "%" + text + "%";
        Cursor cursor = DatabaseAccess.db.rawQuery(
                "SELECT * FROM Detections WHERE Phone_Number LIKE ? OR Message LIKE ? OR Date LIKE ?",
                new String[]{wildcard, wildcard, wildcard}
        );
        detectionLV.setAdapter(new DisplayDataAdapterView(this, cursor));
    }

    private void sortONDB() {
        Cursor cursor = DatabaseAccess.db.rawQuery("SELECT * FROM Detections ORDER BY Date ASC", null);
        detectionLV.setAdapter(new DisplayDataAdapterView(this, cursor));
    }

    private void sortNODB() {
        Cursor cursor = DatabaseAccess.db.rawQuery("SELECT * FROM Detections ORDER BY Date DESC", null);
        detectionLV.setAdapter(new DisplayDataAdapterView(this, cursor));
    }

    private void deleteRow(String id) {
        DatabaseAccess.db.delete("Detections", "_id = ?", new String[]{id});
    }

    private void saveRadioButtonState(String key, boolean checked) {
        SharedPreferences prefs = getSharedPreferences("RadioPrefs", MODE_PRIVATE);
        prefs.edit().putBoolean(key, checked).apply();
    }

    private void clearRadioButtonState() {
        getSharedPreferences("RadioPrefs", MODE_PRIVATE).edit().clear().apply();
    }

    @Override
    protected void onStop() {
        super.onStop();
        databaseAccess.close();
    }
}
