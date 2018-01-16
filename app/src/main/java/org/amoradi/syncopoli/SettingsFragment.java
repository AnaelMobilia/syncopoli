package org.amoradi.syncopoli;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.support.v7.app.AlertDialog;
import android.view.Menu;
import android.view.MenuInflater;
import android.widget.Toast;


public class SettingsFragment extends PreferenceFragment implements SharedPreferences.OnSharedPreferenceChangeListener {
    public final static String KEY_SERVER_ADDRESS = "pref_key_server_address";
    public final static String KEY_PROTOCOL = "pref_key_protocol";
    public final static String KEY_RSYNC_USERNAME = "pref_key_username";
    public final static String KEY_RSYNC_OPTIONS = "pref_key_options";
    public final static String KEY_PRIVATE_KEY = "pref_key_private_key";
    public final static String KEY_PORT = "pref_key_port";
    public final static String KEY_FREQUENCY = "pref_key_frequency";
    public final static String KEY_RSYNC_PASSWORD = "pref_key_rsync_password";
    public final static String KEY_SSH_PASSWORD = "pref_key_ssh_password";
    public final static String KEY_WIFI_ONLY = "pref_key_wifi_only";
    public final static String KEY_WIFI_NAME = "pref_key_wifi_name";
    public final static String KEY_VERIFY_HOST = "pref_key_verify_host";

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        if (key.equals(KEY_WIFI_ONLY) || key.equals(KEY_RSYNC_PASSWORD)) {
            return;
        }

        Preference pref = findPreference(key);
        String summary = sharedPreferences.getString(key, "Not set");
        pref.setSummary(summary);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.pref_general);
        setHasOptionsMenu(true);

        initializeSummaries();
        getPreferenceScreen().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);

        Preference verifyButton = findPreference(KEY_VERIFY_HOST);
        verifyButton.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                new VerifyHostFingerprintTask(getActivity().getWindow().getContext()).execute();
                return true;
            }
        });
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        super.onCreateOptionsMenu(menu, inflater);
        menu.findItem(R.id.menu_settings).setVisible(false);
        menu.findItem(R.id.action_done).setVisible(false);
        menu.findItem(R.id.action_refresh).setVisible(false);
        menu.findItem(R.id.action_run).setVisible(false);
    }

    private void initializeSummaries() {
        String[] keys = {KEY_SERVER_ADDRESS, KEY_PROTOCOL, KEY_RSYNC_USERNAME,
		KEY_RSYNC_OPTIONS, KEY_PRIVATE_KEY, KEY_PORT, KEY_FREQUENCY};
        SharedPreferences sp = getPreferenceScreen().getSharedPreferences();

        for (String key : keys) {
            onSharedPreferenceChanged(sp, key);
        }
    }

    private class VerifyHostFingerprintTask extends AsyncTask<Void, Void, HostKey> {
        private Context mContext;
		private SSHManager sshman;

        VerifyHostFingerprintTask(Context ctx) {
            mContext = ctx;
			sshman = new SSHManager(mContext);
        }

        @Override
        protected HostKey doInBackground(Void... params) {
			SharedPreferences sp = getPreferenceScreen().getSharedPreferences();
			String username = sp.getString(KEY_RSYNC_USERNAME, "");
			String password = sp.getString(KEY_SSH_PASSWORD, "");
			String host = sp.getString(KEY_SERVER_ADDRESS, "");
			int port = 0;

			try {
				port = Integer.parseInt(sp.getString(KEY_PORT, "22"));
			} catch (java.lang.NumberFormatException e) {
				// the error will be handled later
			}

			if (username.equals("") || host.equals("") || port == 0) {
				return null;
			}

			HostKey hk = sshman.getRemoteHostKey(username, password, host, port);
            return hk;
        }

        @Override
        protected void onPostExecute(final HostKey result) {
			if (result == null) {
				Toast.makeText(mContext, "Failed to verify host.", Toast.LENGTH_SHORT).show();
				return;
			}

			SharedPreferences sp = getPreferenceScreen().getSharedPreferences();
			String host = sp.getString(KEY_SERVER_ADDRESS, "");

			if (sshman.matchKey(host, result)) {
				Toast.makeText(mContext, "Host keys match", Toast.LENGTH_SHORT).show();
				return;
			}

            DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    switch (which){
                        case DialogInterface.BUTTON_POSITIVE:
							sshman.acceptHostKey(result);
                            break;

                        case DialogInterface.BUTTON_NEGATIVE:
                            break;
                    }
                }
            };

            AlertDialog.Builder builder = new AlertDialog.Builder(mContext, R.style.AppTheme);
            builder.setMessage("Does the following fingerprint match the host?\n" + result.getFingerPrint(new JSch()));
            builder.setPositiveButton("Yes", dialogClickListener);
            builder.setNegativeButton("No", dialogClickListener);
            builder.show();
        }
    }
}
