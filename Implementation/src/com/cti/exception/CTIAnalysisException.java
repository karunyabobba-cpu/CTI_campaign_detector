package com.cti.exception;

public class CTIAnalysisException extends Exception {
    public CTIAnalysisException(String message) {
        super(message);
    }

    public CTIAnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}