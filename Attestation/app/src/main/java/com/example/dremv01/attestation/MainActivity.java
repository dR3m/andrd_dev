package com.example.dremv01.attestation;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import com.example.dremv01.attestation.KeyAttestationExample;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            KeyAttestationExample.main();
        } catch (Exception e) {
            //
        }

    }
}
