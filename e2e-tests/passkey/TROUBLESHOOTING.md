# Troubleshooting Passkey E2E Tests

## Common Issues and Solutions

### Cluster Issues

#### Cluster Won't Start

**Symptoms:**
- `docker-compose up` fails
- Cluster health check times out
- Port 9200 not responding

**Solutions:**

1. **Check Docker is running:**
   ```bash
   docker ps
   ```
   If this fails, start Docker Desktop or Docker daemon.

2. **Check port availability:**
   ```bash
   lsof -i :9200
   lsof -i :9600
   ```
   If ports are in use, stop the conflicting process or change ports in docker-compose.yml.

3. **Clean up existing containers:**
   ```bash
   docker-compose down -v
   docker system prune -f
   ```

4. **Check logs:**
   ```bash
   docker-compose logs opensearch
   ```
   Look for error messages about configuration, memory, or permissions.

5. **Increase Docker memory:**
   - Docker Desktop → Settings → Resources → Memory
   - Allocate at least 4GB

#### Cluster Starts But Health Check Fails

**Symptoms:**
- Container is running but health check fails
- Cluster status is red or yellow

**Solutions:**

1. **Wait longer:**
   ```bash
   # Cluster may take 1-2 minutes to initialize
   sleep 60
   curl -k -u admin:Admin123! https://localhost:9200/_cluster/health
   ```

2. **Check cluster status:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200/_cluster/health?pretty
   ```

3. **Check security plugin:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200/_plugins/_security/health
   ```

4. **Restart cluster:**
   ```bash
   docker-compose restart
   ```

### Certificate Issues

#### SSL/TLS Errors

**Symptoms:**
- `UNABLE_TO_VERIFY_LEAF_SIGNATURE`
- `CERT_HAS_EXPIRED`
- `SSL certificate problem`

**Solutions:**

1. **Regenerate certificates:**
   ```bash
   rm -rf certs/*.pem certs/*.key
   ./scripts/generate-certs.sh
   ```

2. **Restart cluster:**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

3. **Check certificate validity:**
   ```bash
   openssl x509 -in certs/node.pem -text -noout
   ```

4. **Verify certificate permissions:**
   ```bash
   chmod 644 certs/*.pem
   chmod 600 certs/*.key
   ```

### Test Failures

#### Tests Timeout

**Symptoms:**
- Tests hang and eventually timeout
- No response from cluster

**Solutions:**

1. **Increase test timeout:**
   ```javascript
   // In jest.config.js
   testTimeout: 60000 // 60 seconds
   ```

2. **Check cluster is responsive:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200
   ```

3. **Add delays in tests:**
   ```javascript
   await sleep(1000); // Wait for indexing
   ```

4. **Run tests sequentially:**
   ```bash
   npm test -- --runInBand
   ```

#### Authentication Failures

**Symptoms:**
- 401 Unauthorized errors
- Invalid credentials errors

**Solutions:**

1. **Verify admin credentials:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200
   ```

2. **Check security configuration:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200/_plugins/_security/api/securityconfig
   ```

3. **Verify passkey domain is configured:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200/_plugins/_security/api/securityconfig | jq '.config.dynamic.authc'
   ```

4. **Restart cluster with fresh config:**
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

#### Challenge Validation Failures

**Symptoms:**
- "Challenge mismatch" errors
- "Challenge expired" errors
- "Challenge not found" errors

**Solutions:**

1. **Check challenge timeout configuration:**
   ```yaml
   # In config/config.yml
   challenge_timeout_ms: 300000  # 5 minutes
   ```

2. **Reduce delays in tests:**
   ```javascript
   // Remove or reduce sleep() calls
   await sleep(100); // Instead of sleep(5000)
   ```

3. **Generate fresh challenge for each attempt:**
   ```javascript
   // Don't reuse challenges
   const optionsResponse = await client.getAuthenticationOptions(username);
   const challenge = decodeBase64Url(optionsResponse.data.challenge);
   ```

4. **Check challenge store:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200/.passkey-challenges/_search
   ```

#### Signature Verification Failures

**Symptoms:**
- "Invalid signature" errors
- "Signature verification failed" errors

**Solutions:**

1. **Verify credential is registered:**
   ```bash
   curl -k -u admin:Admin123! https://localhost:9200/.passkey-credentials/_search
   ```

2. **Use same authenticator instance:**
   ```javascript
   // Don't create new authenticator
   const authenticator = new VirtualAuthenticator();
   const credential = authenticator.makeCredential(...);
   // Later, use same authenticator
   const assertion = authenticator.getAssertion(...);
   ```

3. **Check RP ID matches:**
   ```javascript
   // Registration and authentication must use same RP ID
   rpId: 'localhost'
   ```

4. **Verify public key format:**
   ```javascript
   // Ensure COSE encoding is correct
   ```

### Data Issues

#### Test Data Conflicts

**Symptoms:**
- "Credential already exists" errors
- "User already has credential" errors
- Tests fail when run multiple times

**Solutions:**

1. **Run cleanup:**
   ```bash
   npm run cleanup
   ```

2. **Use unique usernames:**
   ```javascript
   const username = generateUsername('test_prefix');
   ```

3. **Clean up in afterAll:**
   ```javascript
   afterAll(async () => {
     for (const credId of testCredentials) {
       await client.deleteCredential(credId);
     }
   });
   ```

4. **Delete test indices:**
   ```bash
   curl -k -u admin:Admin123! -X DELETE https://localhost:9200/test-*
   ```

#### Indexing Delays

**Symptoms:**
- Credential not found immediately after registration
- List returns empty when credentials exist

**Solutions:**

1. **Add delay after write operations:**
   ```javascript
   await client.verifyRegistration(credential);
   await sleep(1000); // Wait for indexing
   ```

2. **Refresh indices:**
   ```javascript
   await client.post('/_refresh');
   ```

3. **Use retry logic:**
   ```javascript
   await retry(async () => {
     const list = await client.listCredentials();
     expect(list.data.credentials.length).toBeGreaterThan(0);
   });
   ```

### Performance Issues

#### Slow Tests

**Symptoms:**
- Tests take very long to complete
- Cluster is slow to respond

**Solutions:**

1. **Check Docker resources:**
   - Increase CPU and memory allocation
   - Close other applications

2. **Reduce test iterations:**
   ```javascript
   // Reduce number of test cases
   // Combine related tests
   ```

3. **Use test parallelization:**
   ```bash
   npm test -- --maxWorkers=4
   ```

4. **Profile tests:**
   ```bash
   npm test -- --verbose
   ```

### Network Issues

#### Connection Refused

**Symptoms:**
- `ECONNREFUSED` errors
- Cannot connect to localhost:9200

**Solutions:**

1. **Check cluster is running:**
   ```bash
   docker ps | grep opensearch
   ```

2. **Check port mapping:**
   ```bash
   docker-compose ps
   ```

3. **Try different URL:**
   ```javascript
   // Try 127.0.0.1 instead of localhost
   baseUrl: 'https://127.0.0.1:9200'
   ```

4. **Check firewall:**
   ```bash
   # macOS
   sudo pfctl -d
   
   # Linux
   sudo ufw status
   ```

#### DNS Resolution Issues

**Symptoms:**
- `ENOTFOUND` errors
- Cannot resolve hostname

**Solutions:**

1. **Use IP address:**
   ```javascript
   baseUrl: 'https://127.0.0.1:9200'
   ```

2. **Check /etc/hosts:**
   ```bash
   cat /etc/hosts | grep localhost
   ```

3. **Flush DNS cache:**
   ```bash
   # macOS
   sudo dscacheutil -flushcache
   
   # Linux
   sudo systemd-resolve --flush-caches
   ```

## Getting Help

If you're still experiencing issues:

1. **Check logs:**
   ```bash
   docker-compose logs opensearch
   npm test -- --verbose
   ```

2. **Enable debug logging:**
   ```javascript
   // In test file
   console.log('Debug info:', data);
   ```

3. **Run single test:**
   ```bash
   npm test -- tests/registration.test.js -t "specific test name"
   ```

4. **Check OpenSearch documentation:**
   - https://opensearch.org/docs/latest/security/

5. **Open an issue:**
   - Include error messages
   - Include logs
   - Include steps to reproduce
   - Include environment details (OS, Docker version, Node version)

## Useful Commands

```bash
# Cluster management
docker-compose up -d          # Start cluster
docker-compose down           # Stop cluster
docker-compose down -v        # Stop and remove volumes
docker-compose logs -f        # Follow logs
docker-compose restart        # Restart cluster

# Testing
npm test                      # Run all tests
npm test -- --watch          # Watch mode
npm test -- --coverage       # With coverage
npm run cleanup              # Clean test data

# Debugging
curl -k -u admin:Admin123! https://localhost:9200/_cluster/health
curl -k -u admin:Admin123! https://localhost:9200/_cat/indices
curl -k -u admin:Admin123! https://localhost:9200/.passkey-credentials/_search
curl -k -u admin:Admin123! https://localhost:9200/.passkey-challenges/_search

# Docker
docker ps                     # List containers
docker logs opensearch-passkey-test  # View container logs
docker exec -it opensearch-passkey-test bash  # Shell into container
docker system prune -f        # Clean up Docker
```
