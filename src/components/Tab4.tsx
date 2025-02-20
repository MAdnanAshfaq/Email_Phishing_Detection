import React, { useState } from 'react';
import axios from 'axios';

interface EmailAnalysisResult {
  headers: Record<string, string>;
  vendorAnalysis: Record<string, any>;
  maliciousUrls: string[];
  timestamp: string;
}

export function Tab4() {
  const [analysisResult, setAnalysisResult] = useState<EmailAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCompleteInfo = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get('http://127.0.0.1:5000/api/email/complete-analysis');
      setAnalysisResult(response.data);
    } catch (err) {
      setError('Failed to fetch complete analysis');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSpecificInfo = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get('http://127.0.0.1:5000/api/email/vendor-analysis');
      setAnalysisResult(response.data);
    } catch (err) {
      setError('Failed to fetch vendor analysis');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleExtractUrls = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get('http://127.0.0.1:5000/api/email/malicious-urls');
      setAnalysisResult(response.data);
    } catch (err) {
      setError('Failed to extract URLs');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="tab4-container">
      <h2>Email Security Analysis</h2>
      
      <div className="button-group">
        <button 
          onClick={handleCompleteInfo}
          disabled={loading}
        >
          Complete Info
        </button>
        <button 
          onClick={handleSpecificInfo}
          disabled={loading}
        >
          Specific Info
        </button>
        <button 
          onClick={handleExtractUrls}
          disabled={loading}
        >
          Extract URLs
        </button>
      </div>

      {loading && <div className="loading">Loading...</div>}
      {error && <div className="error">{error}</div>}
      
      {analysisResult && (
        <div className="results">
          <h3>Analysis Results</h3>
          {analysisResult.headers && (
            <div className="section">
              <h4>Email Headers</h4>
              <pre>{JSON.stringify(analysisResult.headers, null, 2)}</pre>
            </div>
          )}
          
          {analysisResult.vendorAnalysis && (
            <div className="section">
              <h4>Vendor Analysis</h4>
              <pre>{JSON.stringify(analysisResult.vendorAnalysis, null, 2)}</pre>
            </div>
          )}
          
          {analysisResult.maliciousUrls && (
            <div className="section">
              <h4>Malicious URLs</h4>
              <ul>
                {analysisResult.maliciousUrls.map((url, index) => (
                  <li key={index}>{url}</li>
                ))}
              </ul>
            </div>
          )}
          
          <div className="timestamp">
            Analysis performed at: {analysisResult.timestamp}
          </div>
        </div>
      )}
    </div>
  );
}

export default Tab4; 