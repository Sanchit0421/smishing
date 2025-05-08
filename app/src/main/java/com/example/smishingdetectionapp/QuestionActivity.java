package com.example.smishingdetectionapp;

import android.os.Bundle;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class QuestionActivity extends AppCompatActivity {

    private static class Question {
        String questionText;
        String[] options;
        int correctOptionIndex;

        Question(String questionText, String[] options, int correctOptionIndex) {
            this.questionText = questionText;
            this.options = options;
            this.correctOptionIndex = correctOptionIndex;
        }
    }

    private TextView questionTextView;
    private RadioGroup optionsGroup;
    private Button submitButton;
    private Button backToHomeButton;

    private List<Question> questionBank;
    private Question currentQuestion;
    private static final String KEY_CURRENT_QUESTION_INDEX = "current_question_index";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_question);

        // Enable back button in the action bar
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        // Initialize UI elements
        questionTextView = findViewById(R.id.questionText);
        optionsGroup = findViewById(R.id.optionsGroup);
        submitButton = findViewById(R.id.submitButton);
        backToHomeButton = findViewById(R.id.backToHomeButton);

        backToHomeButton.setOnClickListener(v -> finish());

        initializeQuestionBank();

        // Load previous question or show a random one
        if (savedInstanceState != null && savedInstanceState.containsKey(KEY_CURRENT_QUESTION_INDEX)) {
            int questionIndex = savedInstanceState.getInt(KEY_CURRENT_QUESTION_INDEX);
            if (questionIndex >= 0 && questionIndex < questionBank.size()) {
                currentQuestion = questionBank.get(questionIndex);
                displayQuestion();
            } else {
                displayRandomQuestion();
            }
        } else {
            displayRandomQuestion();
        }

        // Handle answer submission
        submitButton.setOnClickListener(v -> {
            int selectedId = optionsGroup.getCheckedRadioButtonId();
            if (selectedId == -1) {
                Toast.makeText(this, "Please select an answer!", Toast.LENGTH_SHORT).show();
                return;
            }

            RadioButton selectedRadioButton = findViewById(selectedId);
            int selectedIndex = optionsGroup.indexOfChild(selectedRadioButton);

            if (selectedIndex == currentQuestion.correctOptionIndex) {
                Toast.makeText(this, "🎉 Correct!", Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(this, "❌ Incorrect!", Toast.LENGTH_LONG).show();
            }

            for (int i = 0; i < optionsGroup.getChildCount(); i++) {
                optionsGroup.getChildAt(i).setEnabled(false);
            }

            submitButton.setEnabled(false);
        });
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (currentQuestion != null) {
            int questionIndex = questionBank.indexOf(currentQuestion);
            outState.putInt(KEY_CURRENT_QUESTION_INDEX, questionIndex);
        }
    }

    private void displayRandomQuestion() {
        if (questionBank == null || questionBank.isEmpty()) {
            Toast.makeText(this, "No questions available", Toast.LENGTH_LONG).show();
            return;
        }
        currentQuestion = questionBank.get(new Random().nextInt(questionBank.size()));
        displayQuestion();
    }

    private void displayQuestion() {
        questionTextView.setText(currentQuestion.questionText);
        optionsGroup.removeAllViews();

        for (String option : currentQuestion.options) {
            RadioButton radioButton = new RadioButton(this);
            radioButton.setText(option);
            optionsGroup.addView(radioButton);
        }

        optionsGroup.clearCheck();
        submitButton.setEnabled(true);
    }

    private void initializeQuestionBank() {
        questionBank = new ArrayList<>();

        // Add smishing awareness questions
        questionBank.add(new Question("What is smishing?", new String[]{"SMS scam", "Email scam", "Online theft"}, 0));
        questionBank.add(new Question("What does phishing target?", new String[]{"Personal info", "Fitness", "Entertainment"}, 0));
        questionBank.add(new Question("Which one is a safe sign of a website?", new String[]{"HTTPS", "No padlock", "HTTP"}, 0));
        questionBank.add(new Question("Don't do what when you get a suspicious message?", new String[]{"Click on links", "Delete it", "Report it"}, 0));
        questionBank.add(new Question("How can attackers disguise SMS?", new String[]{"Fake sender names", "No grammar", "Weird colors"}, 0));
        questionBank.add(new Question("Smishing uses which method to scam you?", new String[]{"Text messages", "Emails", "Phone calls"}, 0));
        questionBank.add(new Question("You get a message claiming your package is stuck. You should:", new String[]{"Not click the link", "Click the link", "Reply to the SMS"}, 0));
        questionBank.add(new Question("Safe websites have:", new String[]{"A padlock symbol", "Red text", "An emoji"}, 0));
        questionBank.add(new Question("A message says your bank account is frozen. First, you should:", new String[]{"Check directly with the bank", "Click the link in the SMS", "Ignore forever"}, 0));
        questionBank.add(new Question("Phishing emails often create:", new String[]{"Urgency", "Excitement", "Relaxation"}, 0));
        questionBank.add(new Question("What is a fake message pretending to be from a real company called?", new String[]{"Phishing", "Messaging", "Chitchat"}, 0));
        questionBank.add(new Question("Smishing can trick you by offering:", new String[]{"Fake prizes", "Real discounts", "Helpful advice"}, 0));
        questionBank.add(new Question("One way to recognize smishing is:", new String[]{"Spelling errors", "Perfect grammar", "Blue messages"}, 0));
        questionBank.add(new Question("To stay safe from smishing, never:", new String[]{"Click unknown links", "Use WiFi", "Text your friends"}, 0));
        questionBank.add(new Question("What is a red flag in a text?", new String[]{"Urgent call to action", "Weather update", "Meeting reminder"}, 0));
        questionBank.add(new Question("Can smishing include shortened URLs?", new String[]{"Yes", "No", "Only on iPhones"}, 0));
        questionBank.add(new Question("What should you do if unsure about a text?", new String[]{"Contact the sender directly", "Reply to it", "Ignore forever"}, 0));
        questionBank.add(new Question("How often should you update your phone?", new String[]{"Regularly", "Once a year", "Never"}, 0));
        questionBank.add(new Question("Can legitimate companies ask for your password via SMS?", new String[]{"No", "Yes", "Sometimes"}, 0));
        questionBank.add(new Question("What is one way to protect your device?", new String[]{"Enable two-factor authentication", "Keep old apps", "Turn off security"}, 0));
        questionBank.add(new Question("What is vishing?", new String[]{"Voice phishing", "Visual phishing", "Victory phishing"}, 0));
        questionBank.add(new Question("If a text sounds too good to be true, it probably is:", new String[]{"Fake", "Legit", "Safe"}, 0));
        questionBank.add(new Question("Should you ever click unknown links?", new String[]{"No", "Yes", "If you're curious"}, 0));
        questionBank.add(new Question("Which is safer?", new String[]{"Bank's official app", "Text link to bank", "Random website"}, 0));
        questionBank.add(new Question("What is a smishing goal?", new String[]{"Steal your data", "Share jokes", "Sell music"}, 0));
        questionBank.add(new Question("You receive an SMS saying 'Verify your account now!'. You should:", new String[]{"Ignore it", "Click it fast", "Reply with password"}, 0));
        questionBank.add(new Question("You can report smishing to:", new String[]{"Your mobile provider", "The scammer", "Your friends"}, 0));
        questionBank.add(new Question("Smishing attackers want to:", new String[]{"Get your info", "Make friends", "Chat"}, 0));
        questionBank.add(new Question("A message says you won a lottery you never entered. Likely:", new String[]{"It's a scam", "Lucky day!", "Reply to win"}, 0));
        questionBank.add(new Question("Protect yourself by:", new String[]{"Not trusting unknown texts", "Clicking all links", "Ignoring updates"}, 0));
    }
}

