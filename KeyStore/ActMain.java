package yap.test.keystore;

import android.app.Activity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static android.content.ContentValues.TAG;
import static yap.test.keystore.Common.NEW_LINE;

public class ActMain extends Activity implements View.OnClickListener {

    private TextView mLog = null;

    /** {@inheritDoc} */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.act_main);
        mLog = (TextView) findViewById(R.id.log);
        mLog.setMovementMethod(new ScrollingMovementMethod());

        View view = mLog;
        final int id = view != null ? view.getId() : 0;

        // Simple RSA
        /*
        final KeyPair pair = KeyGen.genSimpleRsa();
        toLog(pair);
        return;
        */

        // RSA with Keystore
        try {
            final KeyPair pair = KeyGen.genRsaKeyWithKeystore(this.getApplicationContext());
            if (pair != null) {
                toLog("X Key Pair - OK");
            } else {
                toLog("X Key Pair - Fail");
                return;
            }
            final String check = KeyGen.checkRsaKeyWithKeystore();
            toLog(check);
            sendToLog();
        } catch (Exception e){
            //
        }


    }

    private void toLog(String text) {
        mLog.append(text); mLog.append(NEW_LINE);
    }

    private void toLog(KeyPair pair) {
        if (pair != null) {
            toLog(pair.getPublic().toString());
        } else {
            toLog("KeyPair is null");
        }
    }

    private void sendToLog() {
        final String log = mLog.getText().toString();
        if (!log.isEmpty()) {
            Log.i(TAG, log);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onClick(View view) {

    }
}
