package com.cti.service;

import com.cti.exception.CTIAnalysisException;
import java.io.File;
import java.util.List;

public interface OSINTAnalyzer<T> {
    List<T> analyzeSource(File datasetFile, File intelFeedFile) throws CTIAnalysisException;
}