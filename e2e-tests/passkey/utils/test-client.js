/**
 * HTTP Test Client for OpenSearch API
 * 
 * Provides authenticated HTTP requests to OpenSearch with SSL/TLS support.
 */

import https from 'https';
import fetch from 'node-fetch';

/**
 * Test client for making requests to OpenSearch
 */
export class TestClient {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || 'https://localhost:9200';
    this.username = options.username || 'admin';
    this.password = options.password || 'MyStr0ng!Pass#2026';
    this.rejectUnauthorized = options.rejectUnauthorized !== undefined 
      ? options.rejectUnauthorized 
      : false; // Allow self-signed certs in tests
    
    this.agent = new https.Agent({
      rejectUnauthorized: this.rejectUnauthorized
    });
  }

  /**
   * Make authenticated request
   */
  async request(method, path, options = {}) {
    const url = `${this.baseUrl}${path}`;
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };

    // Add basic auth if credentials provided
    if (this.username && this.password) {
      const auth = Buffer.from(`${this.username}:${this.password}`).toString('base64');
      headers['Authorization'] = `Basic ${auth}`;
    }

    const fetchOptions = {
      method,
      headers,
      agent: this.agent
    };

    if (options.body) {
      fetchOptions.body = typeof options.body === 'string' 
        ? options.body 
        : JSON.stringify(options.body);
    }

    const response = await fetch(url, fetchOptions);
    
    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    return {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      data
    };
  }

  /**
   * GET request
   */
  async get(path, options = {}) {
    return this.request('GET', path, options);
  }

  /**
   * POST request
   */
  async post(path, body, options = {}) {
    return this.request('POST', path, { ...options, body });
  }

  /**
   * PUT request
   */
  async put(path, body, options = {}) {
    return this.request('PUT', path, { ...options, body });
  }

  /**
   * DELETE request
   */
  async delete(path, options = {}) {
    return this.request('DELETE', path, options);
  }

  /**
   * Check cluster health
   */
  async checkHealth() {
    const response = await this.get('/_cluster/health');
    return response.status === 200;
  }

  /**
   * Wait for cluster to be ready
   */
  async waitForCluster(timeout = 60000, interval = 1000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      try {
        const healthy = await this.checkHealth();
        if (healthy) {
          return true;
        }
      } catch (error) {
        // Cluster not ready yet
      }
      
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    
    throw new Error('Cluster did not become ready within timeout');
  }

  /**
   * Passkey registration - get options
   */
  async getRegistrationOptions(username) {
    return this.post('/_plugins/_security/passkey/registration/options', {
      username
    });
  }

  /**
   * Passkey registration - verify credential
   */
  async verifyRegistration(credential) {
    return this.post('/_plugins/_security/passkey/registration/verify', credential, {
      headers: {
        'Origin': 'https://localhost:9200'
      }
    });
  }

  /**
   * Passkey authentication - get options
   */
  async getAuthenticationOptions(username = null) {
    const body = username ? { username } : {};
    return this.post('/_plugins/_security/passkey/authentication/options', body);
  }

  /**
   * Passkey authentication - verify assertion
   */
  async verifyAuthentication(assertion) {
    return this.post('/_plugins/_security/passkey/authentication/verify', assertion, {
      headers: {
        'Origin': 'https://localhost:9200'
      }
    });
  }

  /**
   * List user credentials
   */
  async listCredentials(username = null) {
    const body = username ? { username } : {};
    return this.post('/_plugins/_security/passkey/credentials/list', body);
  }

  /**
   * Delete credential
   */
  async deleteCredential(credentialId) {
    return this.delete(`/_plugins/_security/passkey/credentials/${credentialId}`);
  }

  /**
   * Update credential metadata
   */
  async updateCredential(credentialId, metadata) {
    return this.put(`/_plugins/_security/passkey/credentials/${credentialId}`, metadata);
  }

  /**
   * Create test index
   */
  async createIndex(indexName, mapping = {}) {
    return this.put(`/${indexName}`, {
      mappings: mapping
    });
  }

  /**
   * Delete test index
   */
  async deleteIndex(indexName) {
    return this.delete(`/${indexName}`);
  }

  /**
   * Index document
   */
  async indexDocument(indexName, document, id = null) {
    const path = id ? `/${indexName}/_doc/${id}` : `/${indexName}/_doc`;
    return this.post(path, document);
  }

  /**
   * Search documents
   */
  async search(indexName, query) {
    return this.post(`/${indexName}/_search`, query);
  }
}

export default TestClient;
