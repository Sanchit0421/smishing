package com.example.smishingdetectionapp;

import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

public class QuizResultActivity extends AppCompatActivity {

    private Button shareButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_quiz_results);

        // Retrieve data from the intent
        int score = getIntent().getIntExtra("score", 0);
        int totalQuestions = getIntent().getIntExtra("totalQuestions", 0);
        ArrayList<String> questions = getIntent().getStringArrayListExtra("questions");
        ArrayList<String[]> options = (ArrayList<String[]>) getIntent().getSerializableExtra("options");
        ArrayList<Integer> userAnswers = getIntent().getIntegerArrayListExtra("userAnswers");
        ArrayList<Integer> correctAnswers = getIntent().getIntegerArrayListExtra("correctAnswers");

        // Display the score
        TextView scoreTextView = findViewById(R.id.scoreText);
        scoreTextView.setText("Score: " + score + " / " + totalQuestions);

        // Display question history
        LinearLayout historyLayout = findViewById(R.id.historyLayout);
        for (int i = 0; i < questions.size(); i++) {
            TextView questionView = new TextView(this);
            questionView.setText((i + 1) + ". " + questions.get(i));
            questionView.setTextSize(16);
            historyLayout.addView(questionView);

            // Correct and user answers
            int correctAnswerIndex = correctAnswers.get(i);
            String correctAnswerText = options.get(i)[correctAnswerIndex];

            int userAnswerIndex = userAnswers.get(i);
            TextView userAnswerView = new TextView(this);

            if (userAnswerIndex != correctAnswerIndex) {
                userAnswerView.setText("  Your Answer: " +
                        (userAnswerIndex != -1 ? options.get(i)[userAnswerIndex] : "No answer selected"));
                userAnswerView.setTextColor(0xFFFF0000); // Red for incorrect
            } else {
                userAnswerView.setText("  Your Answer: Correct");
                userAnswerView.setTextColor(0xFF228B22); // Green for correct
            }

            historyLayout.addView(userAnswerView);

            // Show correct answer only if the user was wrong
            if (userAnswerIndex != correctAnswerIndex) {
                TextView correctAnswerView = new TextView(this);
                correctAnswerView.setText("  Correct Answer: " + correctAnswerText);
                correctAnswerView.setTextColor(0xFF228B22); // Green
                historyLayout.addView(correctAnswerView);
            }

            // Separator line
            TextView separator = new TextView(this);
            separator.setText("-----------------------------");
            historyLayout.addView(separator);
        }

        // Home button to go back
        Button homeButton = findViewById(R.id.backToHomeButton);
        homeButton.setOnClickListener(v -> finish());

        // Share button to prompt the user to take a screenshot
        shareButton = findViewById(R.id.btn_share_quiz);
        shareButton.setOnClickListener(v -> captureAndShareScreenshot());
    }

    /**
     * Capture the screen, save it to a file, and share it via social media or messaging apps.
     */
    private void captureAndShareScreenshot() {
        // Capture the screen
        Bitmap screenshot = captureScreen();

        try {
            // Save the screenshot to a file
            File screenshotFile = saveScreenshot(screenshot);

            // Share the screenshot
            shareScreenshot(screenshotFile);
        } catch (IOException e) {
            e.printStackTrace();
            Toast.makeText(this, "Error saving screenshot", Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Capture the current screen content as a Bitmap.
     */
    private Bitmap captureScreen() {
        View rootView = findViewById(android.R.id.content).getRootView();
        rootView.setDrawingCacheEnabled(true);
        Bitmap bitmap = Bitmap.createBitmap(rootView.getDrawingCache());
        rootView.setDrawingCacheEnabled(false);
        return bitmap;
    }

    /**
     * Save the captured screenshot to a file.
     */
    private File saveScreenshot(Bitmap bitmap) throws IOException {
        File screenshotsDir = new File(getExternalFilesDir(Environment.DIRECTORY_PICTURES), "Screenshots");
        if (!screenshotsDir.exists()) {
            screenshotsDir.mkdirs();
        }

        File screenshotFile = new File(screenshotsDir, "quiz_result.png");
        try (FileOutputStream fos = new FileOutputStream(screenshotFile)) {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, fos);
        }

        return screenshotFile;
    }

    /**
     * Share the saved screenshot via an Intent.
     */
    private void shareScreenshot(File screenshotFile) {
        Intent shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("image/png");

        // Add the file path to the intent
        shareIntent.putExtra(Intent.EXTRA_STREAM, screenshotFile.getAbsolutePath());
        shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        startActivity(Intent.createChooser(shareIntent, "Share your result"));
    }
}
