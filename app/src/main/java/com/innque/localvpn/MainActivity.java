package com.innque.localvpn;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        connect(null);
    }

    public void connect(View v) {
        Intent intent = new Intent(this, LaunchVPN.class);
        startActivity(intent);
    }
}