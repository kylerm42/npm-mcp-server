# Security Audit: Nginx Proxy Manager MCP Server
---
reviewer: AP-5 (Security Audit)
date: 2026-02-01
status: APPROVED_WITH_RECOMMENDATIONS
overall_security_rating: MEDIUM-HIGH (Safe for isolated network deployment)
---

## Executive Summary
This MCP server for Nginx Proxy Manager is fundamentally secure for deployment on an isolated home network without internet access. No data exfiltration mechanisms, backdoors, or malicious code were detected. The codebase makes only legitimate API calls to the local NPM instance. However, credential storage patterns and lack of transport security could be improved for defense-in-depth.

**Deployment Recommendation**: ✅ SAFE TO DEPLOY on isolated network with provided mitigations.

---

## Critical Issues 🔴

### None Identified

No critical security vulnerabilities that would prevent deployment were found.

---

## High Priority Security Findings 🟡

### src/index.ts:9-11 - Credentials Stored in Environment Variables (Plain Text)
**Severity**: HIGH (in context of compromise, but acceptable for isolated deployment)
**Category**: Credential Management

**Issue**: NPM credentials (email and password) are read from environment variables and passed directly to the API client without encryption or secure storage.

```typescript
const NPM_EMAIL = process.env.NPM_EMAIL || "";
const NPM_PASSWORD = process.env.NPM_PASSWORD || "";
```

**Why This Matters**: 
- If the host system is compromised, credentials are accessible in process memory
- Environment variables can leak through process listings (`ps aux`, `/proc/`)
- Configuration files (e.g., `claude_desktop_config.json`) store passwords in plain text
- No credential rotation mechanism exists

**Risk Level in Your Context**: MEDIUM
- On an isolated network without internet access, the attack surface is limited to local network threats
- If an attacker gains access to your workstation, credentials could be extracted
- These credentials grant full administrative access to NPM

**Mitigations**:
1. ✅ **Immediate**: Use NPM's token-based authentication if available (check NPM API docs)
2. ✅ **Immediate**: Restrict file permissions on configuration files: `chmod 600 ~/.config/opencode/settings.json`
3. ✅ **Short-term**: Consider using a credential manager (e.g., macOS Keychain, pass, 1Password CLI)
4. ✅ **Long-term**: Run MCP server as dedicated service account with minimal privileges

**Evidence of Secure Usage**:
- Credentials are only transmitted to the configured NPM URL (lines 242, 270 in api-client.ts)
- No credentials are logged or written to disk
- Token caching reduces credential exposure (api-client.ts:237-262)

---

### src/api-client.ts:242-251 - Authentication Over HTTP (No TLS Enforcement)
**Severity**: MEDIUM-HIGH
**Category**: Transport Security

**Issue**: The API client accepts `http://` URLs without warning, transmitting credentials in clear text.

```typescript
const response = await fetch(`${this.baseUrl}/api/tokens`, {
  method: "POST",
  body: JSON.stringify({
    identity: this.email,
    secret: this.password,
  }),
});
```

**Why This Matters**:
- On local networks, credentials can be intercepted via ARP spoofing, man-in-the-middle attacks
- Malicious devices on the network (compromised IoT devices, rogue access points) could capture credentials
- WiFi networks (even WPA3) are vulnerable to deauth attacks and packet capture

**Risk Level in Your Context**: LOW-MEDIUM
- On a truly isolated, wired network with trusted devices only: LOW risk
- On a WiFi network or network with IoT devices: MEDIUM risk

**Mitigations**:
1. ✅ **Immediate**: Configure NPM to use HTTPS with self-signed certificate
2. ✅ **Immediate**: Update MCP configuration to use `https://` URLs
3. ⚠️ **Code Change Recommended**: Add warning when HTTP is used:

```typescript
constructor(config: NpmConfig) {
  this.baseUrl = config.baseUrl.replace(/\/$/, "");
  if (!this.baseUrl.startsWith('https://') && !this.baseUrl.includes('localhost')) {
    console.warn('[SECURITY WARNING] NPM_URL uses HTTP. Credentials will be transmitted unencrypted.');
  }
  // ... rest of constructor
}
```

---

### src/api-client.ts:139, 197, 209 - Arbitrary Nginx Configuration Injection
**Severity**: MEDIUM
**Category**: Input Validation / Code Injection

**Issue**: The `advanced_config` parameter accepts arbitrary Nginx configuration directives without validation or sanitization.

**Why This Matters**:
- Malicious Nginx directives could enable proxy abuse, expose internal services, or create backdoors
- Examples of dangerous directives:
  - `proxy_pass` to arbitrary external URLs (data exfiltration)
  - `rewrite` rules to redirect traffic
  - `access_log` to log sensitive data to attacker-controlled locations
  - `lua_code_cache` with malicious Lua scripts (if Nginx has Lua module)

**Risk Level in Your Context**: LOW-MEDIUM
- MCP server typically controlled by you via AI assistant
- Risk exists if AI assistant is compromised or manipulated via prompt injection
- Risk exists if MCP server is exposed to untrusted users

**Current Protection**: 
- NPM_READONLY mode blocks modifications (index.ts:12, api-client.ts:231-235)

**Mitigations**:
1. ✅ **Immediate**: Use `NPM_READONLY=true` for normal operations
2. ✅ **Operational**: Only enable write access when making intentional configuration changes
3. ⚠️ **Code Change Recommended**: Add input validation for `advanced_config`:

```typescript
private validateAdvancedConfig(config: string): void {
  const dangerousDirectives = ['lua_code_cache', 'perl_require', 'perl_modules', 'access_log /'];
  const externalProxyPattern = /proxy_pass\s+https?:\/\/[^1][^9][^2]/;
  
  if (dangerousDirectives.some(d => config.includes(d))) {
    throw new Error('Configuration contains potentially dangerous Nginx directives');
  }
  if (externalProxyPattern.test(config)) {
    throw new Error('Configuration attempts to proxy to external URLs');
  }
}
```

---

### src/index.ts:15-18 - Credentials Logged to Console on Startup Failure
**Severity**: LOW-MEDIUM
**Category**: Information Disclosure

**Issue**: If credentials are missing, the error message is written to stderr, which may be logged by the MCP host.

```typescript
if (!NPM_EMAIL || !NPM_PASSWORD) {
  console.error(
    "Error: NPM_EMAIL and NPM_PASSWORD environment variables are required"
  );
  process.exit(1);
}
```

**Why This Matters**:
- Stderr may be captured in system logs, MCP server logs, or crash reports
- While the current message doesn't leak credentials, it confirms their absence
- Error handling elsewhere uses similar patterns that could leak sensitive data

**Risk Level**: LOW (no actual credential leakage detected)

**Mitigations**:
1. ✅ Already handled correctly - no credentials are logged
2. 💚 Good practice maintained throughout codebase (verified all error handlers)

---

## Medium Priority Findings 🟠

### package.json:25-27 - Dependency Security Review
**Severity**: MEDIUM
**Category**: Supply Chain Security

**Dependencies Analysis**:

**Direct Dependencies**:
1. ✅ `@modelcontextprotocol/sdk@1.25.3` - Official Anthropic MCP SDK, actively maintained
2. ✅ `zod@4.3.6` - Well-established validation library, no known vulnerabilities

**Transitive Dependencies of Concern**:
1. ⚠️ `express@5.2.1` - Used by MCP SDK for HTTP server (not used by this codebase directly)
2. ⚠️ `eventsource@3.0.7` - Used by MCP SDK for SSE connections (not used by this codebase directly)
3. ⚠️ `cors@2.8.6` - Used by MCP SDK for CORS handling (not used by this codebase directly)

**Security Assessment**:
- No transitive dependencies are invoked by this codebase's logic
- MCP SDK uses StdioServerTransport (stdio communication), not HTTP transport
- Express, cors, eventsource are unused code paths in stdio mode
- No network listeners are created by this server

**Evidence**:
```typescript
// Line 975-976: Only stdio transport is used
const transport = new StdioServerTransport();
await server.connect(transport);
```

**Recommendations**:
1. ✅ Current dependency versions are secure for this use case
2. 💚 Monitor MCP SDK updates for security patches
3. 💚 Run `npm audit` periodically (currently shows 0 vulnerabilities expected)

---

### src/api-client.ts:214-218 - Token Storage in Memory
**Severity**: LOW-MEDIUM
**Category**: Credential Management

**Issue**: Authentication tokens are stored in plaintext class properties.

```typescript
private token: string | null = null;
private tokenExpires: Date | null = null;
```

**Why This Matters**:
- Memory dumps or process inspection could reveal active tokens
- Tokens provide temporary access to NPM without password

**Risk Level**: LOW
- Tokens expire (NPM default is typically 24 hours)
- Tokens are session-specific and not reusable across restarts
- Memory dumping requires root access or process debugging privileges

**Mitigations**:
1. ✅ Already acceptable for the threat model
2. 💚 Token expiry is properly validated (api-client.ts:238-239)
3. 💚 No token persistence to disk

---

## Low Priority / Informational Findings 🟢

### src/api-client.ts:270-278 - No Certificate Validation Warning for Self-Signed Certs
**Severity**: INFO
**Category**: Transport Security

**Observation**: Native `fetch()` API is used, which follows Node.js defaults for certificate validation.

**For Your Deployment**:
If you use self-signed certificates for NPM HTTPS, you'll need to configure Node.js to accept them:

```bash
# Option 1: Set in MCP configuration environment
NODE_TLS_REJECT_UNAUTHORIZED=0

# Option 2: Add custom CA certificate
NODE_EXTRA_CA_CERTS=/path/to/npm-ca.crt
```

⚠️ **Security Note**: `NODE_TLS_REJECT_UNAUTHORIZED=0` disables certificate validation entirely. Prefer adding your CA certificate to trust store.

---

### src/index.ts:977, 981 - Diagnostic Messages to Stderr
**Severity**: INFO
**Category**: Observability

**Observation**: Startup and error messages are written to stderr for MCP protocol compliance.

```typescript
console.error("Nginx Proxy Manager MCP Server running on stdio");
console.error("Fatal error:", error);
```

**Assessment**: ✅ Correct implementation
- Stderr is the proper channel for diagnostic messages in MCP protocol
- No sensitive data is logged in these messages
- Error messages sanitize exception details (error.message used, not full stack traces to client)

---

## Data Exfiltration Analysis ✅

### Network Call Inventory

**All network calls in this codebase**:

1. **Authentication** (api-client.ts:242)
   - Destination: `${this.baseUrl}/api/tokens`
   - Purpose: Obtain NPM access token
   - Data sent: Email and password
   - ✅ Destination is user-configured NPM instance only

2. **API Requests** (api-client.ts:270)
   - Destination: `${this.baseUrl}/api/...`
   - Purpose: NPM management operations
   - Data sent: Configuration data, no external destinations
   - ✅ All endpoints are relative paths on NPM server

3. **Health Check** (api-client.ts:518)
   - Destination: `${this.baseUrl}/api/`
   - Purpose: NPM version and status check
   - Data sent: None
   - ✅ Read-only, no data exfiltration

**Findings**:
- ✅ No hardcoded external URLs found
- ✅ No DNS queries to external domains
- ✅ No telemetry or analytics calls
- ✅ No websocket connections to external services
- ✅ No database connections
- ✅ No file system operations outside of module loading
- ✅ All network destinations are controlled by `NPM_URL` environment variable

**Verification**:
```bash
# Confirmed no external domains in codebase
grep -r "https\?://" src/ | grep -v "localhost" | grep -v "example.com"
# Result: 0 matches
```

---

## Code Integrity Analysis ✅

### Dangerous Function Usage

**Audit Results**:
- ✅ No `eval()` usage
- ✅ No `Function()` constructor usage
- ✅ No `child_process.exec()` or similar
- ✅ No `vm` module usage
- ✅ No dynamic `require()` with user input
- ✅ No file system writes
- ✅ No shell command execution

**Code Patterns**:
- All imports are static and deterministic
- No dynamic code generation
- No reflection or introspection for code execution
- Input validation uses Zod schema validation (type-safe)

---

## Authentication & Authorization Analysis ✅

### Credential Flow

1. **Credential Input**: Environment variables only (src/index.ts:9-11)
2. **Credential Storage**: Memory only, never persisted to disk
3. **Credential Transmission**: Via HTTPS (if configured) to NPM API
4. **Token Caching**: In-memory only, with expiry validation
5. **Credential Scope**: Single NPM instance, no third-party services

### Readonly Mode Protection

**Implementation** (api-client.ts:231-235):
```typescript
private assertWritable(operation: string): void {
  if (this._readonly) {
    throw new ReadonlyModeError(operation);
  }
}
```

**Coverage**: Applied to all mutating operations:
- ✅ Create operations
- ✅ Update operations  
- ✅ Delete operations
- ✅ Enable/disable operations
- ✅ Certificate renewal

**Effectiveness**: Strong protection against accidental modifications.

---

## Input Validation Analysis ✅

### Zod Schema Validation

**Coverage**: All MCP tool inputs are validated via Zod schemas
- ✅ Type validation (strings, numbers, booleans, arrays)
- ✅ Enum validation for fixed value sets (http/https, etc.)
- ✅ Required vs optional field enforcement

**Example** (src/index.ts:103-139):
```typescript
domain_names: z.array(z.string()).describe("..."),
forward_host: z.string().describe("..."),
forward_port: z.number().describe("..."),
forward_scheme: z.enum(["http", "https"]).default("http"),
```

**Potential Gaps**:
1. ⚠️ No validation on string content (domain names, hostnames)
   - Could accept malformed domains like `"; rm -rf /"`
   - **Risk**: LOW - NPM API will reject invalid formats
   - **Mitigation**: NPM API is the final validator

2. ⚠️ No validation on `advanced_config` content (addressed in High Priority section)

---

## Attack Surface Summary

### Threat Model for Isolated Network Deployment

**Attack Vectors Ranked by Risk**:

1. **Local Network MitM (MEDIUM)** - If using HTTP instead of HTTPS
   - Mitigated by: Using HTTPS with self-signed cert

2. **Compromised AI Assistant (LOW-MEDIUM)** - Prompt injection leading to malicious config
   - Mitigated by: NPM_READONLY mode for normal operations

3. **Process Memory Inspection (LOW)** - Extracting credentials from running process
   - Requires: Root/sudo access on host system
   - Mitigated by: OS-level access controls

4. **Configuration File Exposure (LOW)** - Reading plain text credentials
   - Requires: File system access to user's home directory
   - Mitigated by: File permissions (chmod 600)

5. **Supply Chain Attack (LOW)** - Compromised npm package
   - Mitigated by: Using official packages, npm audit, package-lock.json

**Not Applicable for Isolated Network**:
- ❌ Remote code execution from internet (no internet access)
- ❌ DDoS attacks (not exposed to internet)
- ❌ External data exfiltration (no external network calls)

---

## Comparison with Original Repository

**Git Analysis**:
- Single commit: `9aa11a35` by thangho98 (thangho250498@gmail.com)
- Commit message: "feat: Initial MCP server for Nginx Proxy Manager"

**Verification Needed**:
⚠️ **ACTION REQUIRED**: Verify this is actually a fork of a public repository
- README claims this is a fork, but git history shows only 1 commit
- package.json shows repository: `https://github.com/kylerm42/npm-mcp-server.git`
- Need to confirm: Is this the original author's repo or a fork with rebased history?

**Recommendation**: 
```bash
# Check if this matches the upstream repository
git remote add upstream https://github.com/ORIGINAL_REPO_URL
git fetch upstream
git diff HEAD upstream/main
```

If this is a fork with modified history, review the original repo for comparison.

---

## Deployment Recommendations

### For Your Isolated Home Network Scenario

**Pre-Deployment Checklist**:

1. ✅ **Verify Network Isolation**
   - Confirm NPM server has no internet access
   - Confirm MCP client (Claude) has no route to NPM except through this server
   - Verify no port forwarding rules expose NPM to internet

2. ✅ **Enable Transport Security**
   ```bash
   # In NPM, enable HTTPS with self-signed certificate
   # Update MCP configuration:
   NPM_URL=https://npm.local:443
   NODE_EXTRA_CA_CERTS=/path/to/npm-ca.crt
   ```

3. ✅ **Use Readonly Mode by Default**
   ```json
   {
     "env": {
       "NPM_READONLY": "true"
     }
   }
   ```

4. ✅ **Restrict Configuration File Permissions**
   ```bash
   chmod 600 ~/.config/opencode/settings.json
   chmod 600 ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

5. ✅ **Monitor Access**
   - Review NPM access logs periodically
   - Check for unexpected proxy host changes
   - Monitor MCP server stderr output for errors

### Operational Security Practices

**When Making Changes**:
1. Switch to read-write mode temporarily: `NPM_READONLY=false`
2. Make intended changes via AI assistant
3. Verify changes in NPM UI
4. Switch back to readonly mode: `NPM_READONLY=true`
5. Restart Claude to reload MCP server

**Regular Audits**:
1. Monthly: Review NPM proxy host configurations
2. Monthly: Check for NPM security updates
3. Quarterly: Re-run `npm audit` on MCP server dependencies
4. Quarterly: Review MCP server logs for anomalies

---

## Verdict

### Overall Security Rating: MEDIUM-HIGH ✅

**Safe for Deployment**: YES, with provided mitigations

**Risk Assessment**:
- **Data Exfiltration Risk**: ✅ NONE - No external network calls detected
- **Backdoor Risk**: ✅ NONE - No malicious code detected  
- **Credential Leakage Risk**: 🟡 LOW - Credentials in env vars (standard practice, acceptable)
- **Code Injection Risk**: 🟡 LOW-MEDIUM - `advanced_config` accepts raw Nginx directives
- **Transport Security**: 🟡 MEDIUM - HTTP allowed but can be configured to HTTPS
- **Supply Chain Risk**: ✅ LOW - Using official, well-maintained packages

**Deal Breakers**: NONE IDENTIFIED

**Primary Concern Addressed**: 
> "ensuring NPM credentials and configuration cannot be accessed by strangers or leaked to the internet"

✅ **CONFIRMED SECURE**: No internet communication, no external data transmission, credentials only sent to configured NPM instance.

---

## Recommended Mitigations Priority

### Immediate (Before Deployment)
1. Configure NPM to use HTTPS with self-signed certificate
2. Update MCP configuration to use `https://` URL
3. Set `NPM_READONLY=true` for default operation
4. Restrict configuration file permissions: `chmod 600`

### Short-Term (Within 1 Week)
1. Add warning for HTTP usage in constructor (code change)
2. Verify this is actually a fork and compare with upstream
3. Document operational procedures for read-write mode switching

### Long-Term (Within 1 Month)
1. Add validation for `advanced_config` parameter (code change)
2. Consider implementing credential manager integration
3. Set up monthly security review process

---

## Appendix: Security Testing Methodology

**Static Analysis Performed**:
1. ✅ Full codebase review (1,506 lines total)
2. ✅ Dependency tree analysis (55 transitive dependencies)
3. ✅ Network call inventory (3 endpoints, all to NPM)
4. ✅ Dangerous function audit (eval, exec, etc.)
5. ✅ Input validation review (Zod schemas)
6. ✅ Credential flow analysis (env vars → memory → NPM API)
7. ✅ Error handling review (no sensitive data in logs)

**Manual Code Patterns Searched**:
- External URLs: `https?://[^l][^o][^c]` (none found)
- Shell execution: `exec|spawn|child_process` (none found)  
- Dynamic code: `eval|Function\(` (none found)
- File operations: `fs\.|writeFile|readFile` (none found in app code)
- Network: `net\.|http\.|https\.|fetch|axios` (only fetch to NPM)

**Files Reviewed**:
- ✅ src/index.ts (984 lines)
- ✅ src/api-client.ts (522 lines)  
- ✅ package.json
- ✅ package-lock.json (dependency tree)
- ✅ tsconfig.json
- ✅ README.md
- ✅ .env.example
- ✅ .gitignore

**Not Reviewed** (not present):
- Test files (none exist)
- Build artifacts (dist/ excluded)
- node_modules (excluded)

---

## Contact & Questions

This security audit was performed by AP-5 (Security Review Agent) on 2026-02-01.

If you have questions about specific findings or need clarification on mitigation strategies, I can provide additional analysis or code examples.

**Key Takeaway**: This codebase is fundamentally secure for your use case (isolated home network). The credential management and transport security recommendations are defense-in-depth measures, not critical vulnerabilities.
