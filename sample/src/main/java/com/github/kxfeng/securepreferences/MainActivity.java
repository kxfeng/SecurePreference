package com.github.kxfeng.securepreferences;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    private EditText editKey = null;
    private EditText editValue = null;
    private TextView textResult = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editKey = findViewById(R.id.edit_key);
        editValue = findViewById(R.id.edit_value);
        textResult = findViewById(R.id.text_result);

        findViewById(R.id.btn_set).setOnClickListener(v -> {
            App.getInstance().getSecurePreferences().edit().putString(editKey.getText().toString(), editValue.getText().toString()).apply();
        });

        findViewById(R.id.btn_get).setOnClickListener(v -> {
            String key = editKey.getText().toString();
            String value = App.getInstance().getSecurePreferences().getString(key, null);
            textResult.setText("key=" + key + ", value=" + value);
        });
    }
}
