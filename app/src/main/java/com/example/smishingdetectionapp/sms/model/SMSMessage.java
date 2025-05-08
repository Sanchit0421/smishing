package com.example.smishingdetectionapp.sms.model;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;

public class SMSMessage implements Parcelable {
    private String sender;
    private String body;

    public SMSMessage(String sender, String body) {
        this.sender = sender;
        this.body = body;
    }

    protected SMSMessage(Parcel in) {
        sender = in.readString();
        body = in.readString();
    }

    public static final Creator<SMSMessage> CREATOR = new Creator<SMSMessage>() {
        @Override
        public SMSMessage createFromParcel(Parcel in) {
            return new SMSMessage(in);
        }

        @Override
        public SMSMessage[] newArray(int size) {
            return new SMSMessage[size];
        }
    };

    public String getSender() {
        return sender;
    }

    public String getBody() {
        return body;
    }

    // ✅ Extract all URLs from the SMS body using regex
    public List<String> extractUrls() {
        List<String> urls = new ArrayList<>();
        Pattern urlPattern = Pattern.compile(
                "(https?://[\\w\\-._~:/?#@!$&'()*+,;=%]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = urlPattern.matcher(body);

        while (matcher.find()) {
            urls.add(matcher.group());
        }

        return urls;
    }

    // ✅ Check if the message contains suspicious URLs
    public boolean containsSuspiciousUrl() {
        for (String url : extractUrls()) {
            if (isSuspicious(url)) {
                return true;
            }
        }
        return false;
    }

    // ✅ Basic logic to identify suspicious URLs
    private boolean isSuspicious(String url) {
        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();

            // Example checks:
            // 1. If host is an IP address (instead of a domain)
            // 2. If domain looks obfuscated (e.g., contains many hyphens)
            if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                return true;
            }

            if (host.contains("--") || host.length() > 50) {
                return true;
            }

            return false;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeString(sender);
        dest.writeString(body);
    }
}
