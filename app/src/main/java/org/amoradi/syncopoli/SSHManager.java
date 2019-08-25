package org.amoradi.syncopoli;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SSHManager {
    private static final String TAG = "Syncopoli";

    private static final String SSH_KEY_FILENAME = "id_rsa";
    private static final String SSH_PUBKEY_FILENAME = "id_rsa.pub";

    private Context mContext;

    /* This needs the patched version of dropbear!
     * see gitlab.com/fengshaun/android-dropbear commit f49af1902d3d683c59a7445746fa3a35cd07ef33
     * Format: Fingerprint: md5 ab:cd:ef:...
     */
    private Pattern mFingerprintPattern = Pattern.compile("^Fingerprint: [\\w\\d]+ ([\\w:]+)$");
    private Pattern mAcceptedPattern = Pattern.compile("^Accepted fingerprint$");

    /* dropbearkey outputs the public key portion to stdout in the following format:
     * ssh-rsa XYZ user@host
     */
    private Pattern mPubKeyPattern = Pattern.compile("^ssh-\\w+\\s+\\S+\\s+.+$");

    private String host;
    private String port;

    SSHManager(Context ctx) throws NumberFormatException {
        mContext = ctx;

        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(mContext);
        host = sp.getString(SettingsFragment.KEY_SERVER_ADDRESS, "");
        port = sp.getString(SettingsFragment.KEY_PORT, "22");

        try {
            Integer.parseInt(port);
        } catch (java.lang.NumberFormatException e) {
            Log.e(TAG, "Could not convert port to integer: " + e.toString());
            throw e;
        }
    }

    public String getRemoteHostFingerprint() {
        List<String> args = new ArrayList<>();

        File f = new File(mContext.getFilesDir(), "ssh");
        args.add(f.getAbsolutePath());

        args.add("-p");
        args.add(port);
        /* this option is added in patched version of dropbear
         * -C make dropbear print remote host fingerprint and exit, which is what we want
         */
        args.add("-C");
        args.add(host);

        ProcessBuilder pb = new ProcessBuilder(args);
        pb.directory(mContext.getFilesDir());
        pb.redirectErrorStream(true);

        // Set environment (make sure we have reasonable $HOME, so ssh can store keys)
        Map<String, String> env = pb.environment();
        env.put("HOME", mContext.getFilesDir().getAbsolutePath());

        /*
         * RUN PROCESS
         */

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            Log.e(TAG, "Could not run ssh: " + e.toString());
            return null;
        }

        /*
         * GET STDOUT/STDERR
         */

        String temp;
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

        /* Read STDOUT & STDERR */
        try {
            while ((temp = reader.readLine()) != null) {
                Log.e(TAG, temp + "\n");

                Matcher m = mFingerprintPattern.matcher(temp);
                if (m.matches()) {
                    Log.e(TAG, "MATCHES FINGERPRINT: " + m.group(1));
                    String fp = m.group(1);

                    try {
                        process.waitFor();
                    } catch (InterruptedException e) {
                        Log.e(TAG, e.toString());
                    }

                    return fp;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Could not read/write from ssh process");
            return null;
        }

        Log.e(TAG, "Unknown error occurred when trying to communicate with ssh process");
        return null;
    }

    public boolean acceptHostKeyFingerprint(String fingerprint) {
        List<String> args = new ArrayList<>();

        File f = new File(mContext.getFilesDir(), "ssh");
        args.add(f.getAbsolutePath());

        args.add("-p");
        args.add(port);
        /* this option is added in patched version of dropbear
         * -C make dropbear print remote host fingerprint and exit, which is what we want
         */
        args.add("-A");
        args.add(fingerprint);
        args.add(host);

        ProcessBuilder pb = new ProcessBuilder(args);
        pb.directory(mContext.getFilesDir());
        pb.redirectErrorStream(true);

        // Set environment (make sure we have reasonable $HOME, so ssh can store keys)
        Map<String, String> env = pb.environment();
        env.put("HOME", mContext.getFilesDir().getAbsolutePath());

        /*
         * RUN PROCESS
         */

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            Log.e(TAG, "Could not run ssh: " + e.toString());
            return false;
        }

        /*
         * GET STDOUT/STDERR
         */

        String temp;
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

        /* Read STDOUT & STDERR */
        try {
            while ((temp = reader.readLine()) != null) {
                Log.e(TAG, temp + "\n");

                Matcher m = mAcceptedPattern.matcher(temp);
                if (m.matches()) {
                    Log.e(TAG, "Fingerprint accepted");

                    try {
                        process.waitFor();
                    } catch (InterruptedException e) {
                        Log.e(TAG, e.toString());
                    }

                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Could not read/write from ssh process");
            return false;
        }

        Log.e(TAG, "Unknown error occurred when trying to communicate with ssh process");
        return false;
    }

    public boolean clearAcceptedHostKeyFingerprints() {
        String filename = "known_hosts";
        File acceptedFingerprintsFile = new File(mContext.getFilesDir().getAbsolutePath() + "/.ssh/",
                                                 filename);

        if (!acceptedFingerprintsFile.delete()) {
            Log.e(TAG, "Failed to delete " + acceptedFingerprintsFile.getAbsolutePath());
            return false;
        }

        try {
            if (!acceptedFingerprintsFile.createNewFile()) {
                Log.e(TAG, "Failed to create new " + filename + " file: file already exists after being deleted: " + acceptedFingerprintsFile.getAbsolutePath());
                return false;
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to create new " + filename + " file: " + e.toString());
            return false;
        }

        return true;
    }

    public boolean deleteSSHKey(String filename) {
        File keyFile = new File(mContext.getFilesDir(), filename);
        if (keyFile.exists()) {
            if (!keyFile.delete()) {
                Log.e(TAG, "Failed to delete key file " + filename);
                return false;
            }
        }

        return true;
    }

    public boolean generateSSHKey() {
        ArrayList<String> final_cmd = new ArrayList<String>();
        String dropbearkeyPath = new File(mContext.getFilesDir(), "dropbearkey").getAbsolutePath();
        Log.d(TAG, "dropbearkeyPath: " + dropbearkeyPath);

        if (!deleteSSHKey(SSH_KEY_FILENAME)) { return false; }
        if (!deleteSSHKey(SSH_PUBKEY_FILENAME)) { return false; }

        final_cmd.add(dropbearkeyPath);
        final_cmd.add("-t");
        final_cmd.add("rsa");
        final_cmd.add("-s");
        final_cmd.add("2048");
        final_cmd.add("-f");
        final_cmd.add(SSH_KEY_FILENAME);

        ProcessBuilder pb = new ProcessBuilder(final_cmd);
        pb.directory(mContext.getFilesDir());
        pb.redirectErrorStream(true);

        // Set environment (make sure we have reasonable $HOME)
        Map<String, String> env = pb.environment();
        env.put("HOME", mContext.getFilesDir().getAbsolutePath());

        Process process;

        try {
            process = pb.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        int retries = 0;
        while (retries < 3) {
            try {
                process.waitFor();
                break;
            } catch (InterruptedException e) {
                if (retries >= 3) {
                    Log.e(TAG, "Running dropbearkey was interrupted three times, failing: " + e.toString());
                    return false;
                }

                retries++;
            }
        }

        StringBuilder output = new StringBuilder();

        /* Read STDOUT & STDERR */
        String temp = "";
        String pubKey = "";
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

        try {
            while ((temp = reader.readLine()) != null) {
                Log.v(TAG, temp + "\n");
                output.append(temp + "\n");

                Matcher m = mPubKeyPattern.matcher(temp);
                if (m.matches()) {
                    Log.v(TAG, "public key found: " + m.group());
                    pubKey = m.group();
                }
            }
            reader.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if (process.exitValue() != 0) {
            Log.e(TAG, "dropbearkey failed to generate key");
            return false;
        }

        return writePubKeyFile(pubKey);
    }

    private boolean writePubKeyFile(String content) {
        File pubKeyFile = new File(mContext.getFilesDir(), SSH_PUBKEY_FILENAME);

        try {
            if (!pubKeyFile.createNewFile()) {
                pubKeyFile.delete();
                pubKeyFile.createNewFile();
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to create new or delete old public key: " + e.toString());
            return false;
        }

        try {
            FileOutputStream pubStream = new FileOutputStream(pubKeyFile);
            pubStream.write(content.getBytes());
        } catch (FileNotFoundException e) {
            Log.e(TAG, "Failed to open public key for writing: " + e.toString());
            return false;
        } catch (IOException e) {
            Log.e(TAG, "Failed to write public key: " + e.toString());
            return false;
        }

        return true;
    }
}
