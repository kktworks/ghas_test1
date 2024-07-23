package com.example;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;

public class DeserializationOfUserControlledData {

    public int field;

    DeserializationOfUserControlledData(int field) {
        this.field = field;
    }

    /**
     * Deserialization of user-controlled data
     * 
     * <pre>
     * ID: java/unsafe-deserialization
     * Kind: path-problem
     * Security severity: 9.8
     * Severity: error
     * Precision: high
     * Tags:
     *    - security
     *    - external/cwe/cwe-502
     * Query suites:
     *    - java-code-scanning.qls
     *    - java-security-extended.qls
     *    - java-security-and-quality.qls
     * </pre>
     */
    public DeserializationOfUserControlledData deserialize(Socket sock) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(sock.getInputStream())) {
            return (DeserializationOfUserControlledData) in.readObject(); // unsafe
        }
    }
}
