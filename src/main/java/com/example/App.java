package com.example;

import java.io.File;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
public class App {
    public static void main(String[] args) throws Exception {

    }

    /**
     * Arbitrary file access during archive extraction (”Zip Slip”)
     * 
     * <pre>
     * ID: java/zipslip
     * Kind: path-problem
     * Security severity: 7.5
     * Severity: error
     * Precision: high
     * Tags:
     * - security
     * - external/cwe/cwe-022
     * Query suites:
     * - java-code-scanning.qls
     * - java-security-extended.qls
     * - java-security-and-quality.qls
     * </pre>
     */
    public void writeZipEntry(ZipEntry entry, File destinationDir) throws Exception {
        // BAD
        // File file = new File(destinationDir, entry.getName());
        // FileOutputStream fos = new FileOutputStream(file); // BAD

        // workaround
        File file = new File(destinationDir, entry.getName());
        // insert check
        if (!file.toPath().normalize().startsWith(destinationDir.toPath()))
           throw new Exception("Bad zip entry");
        FileOutputStream fos = new FileOutputStream(file);
    }

    /**
     * Building a command line with string concatenation
     * 
     * <pre>
     * ID: java/concatenated-command-line
     * Kind: problem
     * Security severity: 9.8
     * Severity: error
     * Precision: high
     * Tags:
     *    - security
     *    - external/cwe/cwe-078
     *    - external/cwe/cwe-088
     * Query suites:
     *    - java-code-scanning.qls
     *    - java-security-extended.qls
     *    - java-security-and-quality.qls
     * </pre>
     */
    public void buildingACommandLineWithStringConcatenation(String args) throws IOException {
        {
            String latlonCoords = args;
            Runtime rt = Runtime.getRuntime();
            Process exec = rt.exec("cmd.exe /C latlon2utm.exe " + latlonCoords);
        }

        // GOOD: use an array of arguments instead of executing a string
        {
            String latlonCoords = args;
            Runtime rt = Runtime.getRuntime();
            Process exec = rt.exec(new String[] {
                    "cmd.exe ",
                    "/C ",
                    "latlon2utm.exe ",
                    latlonCoords });
        }
    }

    /**
     * Inefficient regular expressio
     * 
     * <pre>
     * ID: java/redos
     * Kind: problem
     * Security severity: 7.5
     * Severity: error
     * Precision: high
     * Tags:
     *    - security
     *    - external/cwe/cwe-1333
     *    - external/cwe/cwe-730
     *    - external/cwe/cwe-400
     * Query suites:
     *    - java-code-scanning.qls
     *    - java-security-extended.qls
     *   - java-security-and-quality.qls
     * </pre>
     */

    public void inefficientRegularExpression() {
        Pattern pattern = Pattern.compile("^_(__|.)+_$");
    }

    /**
     * Overly permissive regular expression range
     * 
     * <pre>
     * ID: java/overly-large-range
     * 
     * Kind: problem
     * Security severity: 5.0
     * Severity: warning
     * Precision: high
     * Tags:
     *    - correctness
     *    - security
     *    - external/cwe/cwe-020
     * Query suites:
     *    - java-code-scanning.qls
     *    - java-security-extended.qls
     *    - java-security-and-quality.qls
     * </pre>
     */
    public static boolean overlyPermissiveRegularExpressionRange(String color) {
        return Pattern.matches("#[0-9a-fA-f]{6}", color);
    }

    /**
     * Implicit narrowing conversion in compound assignment
     * 
     * <pre>
     * ID: java/implicit-cast-in-compound-assignment
     * 
     * Kind: problem
     * Security severity: 8.1
     * Severity: warning
     * Precision: very-high
     * Tags:
     *    - reliability
     *    - security
     *    - external/cwe/cwe-190
     *    - external/cwe/cwe-192
     *    - external/cwe/cwe-197
     *    - external/cwe/cwe-681
     * Query suites:
     *    - java-code-scanning.qls
     *    - java-security-extended.qls
     *    - java-security-and-quality.qls
     * </pre>
     */
    public void comparisonOfNarrowTypeWithWideTypeInLoopCondition() {
        int BIGNUM = Integer.MAX_VALUE;
        long MAXGET = Short.MAX_VALUE + 1;

        char[] buf = new char[BIGNUM];

        short bytesReceived = 0;

        while (bytesReceived < MAXGET) {
            bytesReceived += getFromInput(buf, bytesReceived);
        }
    }

    public static int getFromInput(char[] buf, short pos) {
        // write to buf
        // ...
        return 1;
    }
}