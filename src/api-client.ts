/**
 * Nginx Proxy Manager API Client
 */

export interface NpmConfig {
  baseUrl: string;
  email: string;
  password: string;
  readonly?: boolean;
}

export class ReadonlyModeError extends Error {
  constructor(operation: string) {
    super(`Operation "${operation}" is not allowed in readonly mode`);
    this.name = "ReadonlyModeError";
  }
}

export interface TokenResponse {
  token: string;
  expires: string;
}

export interface ProxyHost {
  id: number;
  created_on: string;
  modified_on: string;
  owner_user_id: number;
  domain_names: string[];
  forward_host: string;
  forward_port: number;
  forward_scheme: "http" | "https";
  access_list_id: number;
  certificate_id: number;
  ssl_forced: boolean;
  caching_enabled: boolean;
  block_exploits: boolean;
  advanced_config: string;
  meta: Record<string, unknown>;
  allow_websocket_upgrade: boolean;
  http2_support: boolean;
  enabled: boolean;
  locations: ProxyLocation[];
  hsts_enabled: boolean;
  hsts_subdomains: boolean;
}

export interface ProxyLocation {
  id?: number;
  path: string;
  forward_scheme: "http" | "https";
  forward_host: string;
  forward_port: number;
  forward_path?: string;
  advanced_config?: string;
}

export interface CreateProxyHostInput {
  domain_names: string[];
  forward_scheme: "http" | "https";
  forward_host: string;
  forward_port: number;
  certificate_id?: number;
  ssl_forced?: boolean;
  hsts_enabled?: boolean;
  hsts_subdomains?: boolean;
  http2_support?: boolean;
  block_exploits?: boolean;
  caching_enabled?: boolean;
  allow_websocket_upgrade?: boolean;
  access_list_id?: number;
  advanced_config?: string;
  enabled?: boolean;
  locations?: ProxyLocation[];
}

export interface Certificate {
  id: number;
  created_on: string;
  modified_on: string;
  owner_user_id: number;
  provider: string;
  nice_name: string;
  domain_names: string[];
  expires_on: string;
  meta: Record<string, unknown>;
}

export interface Stream {
  id: number;
  created_on: string;
  modified_on: string;
  owner_user_id: number;
  incoming_port: number;
  forwarding_host: string;
  forwarding_port: number;
  tcp_forwarding: boolean;
  udp_forwarding: boolean;
  enabled: boolean;
  meta: Record<string, unknown>;
}

export interface CreateStreamInput {
  incoming_port: number;
  forwarding_host: string;
  forwarding_port: number;
  tcp_forwarding?: boolean;
  udp_forwarding?: boolean;
  enabled?: boolean;
}

export interface RedirectionHost {
  id: number;
  created_on: string;
  modified_on: string;
  owner_user_id: number;
  domain_names: string[];
  forward_scheme: "http" | "https" | "$scheme";
  forward_domain_name: string;
  forward_http_code: number;
  preserve_path: boolean;
  certificate_id: number;
  ssl_forced: boolean;
  hsts_enabled: boolean;
  hsts_subdomains: boolean;
  http2_support: boolean;
  block_exploits: boolean;
  enabled: boolean;
}

export interface CreateRedirectionHostInput {
  domain_names: string[];
  forward_scheme: "http" | "https" | "$scheme";
  forward_domain_name: string;
  forward_http_code: number;
  preserve_path?: boolean;
  certificate_id?: number;
  ssl_forced?: boolean;
  hsts_enabled?: boolean;
  hsts_subdomains?: boolean;
  http2_support?: boolean;
  block_exploits?: boolean;
  enabled?: boolean;
}

export interface AccessList {
  id: number;
  created_on: string;
  modified_on: string;
  owner_user_id: number;
  name: string;
  meta: Record<string, unknown>;
  items: AccessListItem[];
  clients: AccessListClient[];
}

export interface AccessListItem {
  username: string;
  password: string;
}

export interface AccessListClient {
  address: string;
  directive: "allow" | "deny";
}

export interface CreateAccessListInput {
  name: string;
  satisfy_any?: boolean;
  pass_auth?: boolean;
  items?: AccessListItem[];
  clients?: AccessListClient[];
}

export interface User {
  id: number;
  created_on: string;
  modified_on: string;
  is_disabled: boolean;
  email: string;
  name: string;
  nickname: string;
  avatar: string;
  roles: string[];
}

export interface DeadHost {
  id: number;
  created_on: string;
  modified_on: string;
  owner_user_id: number;
  domain_names: string[];
  certificate_id: number;
  ssl_forced: boolean;
  hsts_enabled: boolean;
  hsts_subdomains: boolean;
  http2_support: boolean;
  enabled: boolean;
}

export interface CreateDeadHostInput {
  domain_names: string[];
  certificate_id?: number;
  ssl_forced?: boolean;
  hsts_enabled?: boolean;
  hsts_subdomains?: boolean;
  http2_support?: boolean;
  enabled?: boolean;
  advanced_config?: string;
}

export class NpmApiClient {
  private baseUrl: string;
  private token: string | null = null;
  private tokenExpires: Date | null = null;
  private email: string;
  private password: string;
  private _readonly: boolean;

  constructor(config: NpmConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.email = config.email;
    this.password = config.password;
    this._readonly = config.readonly ?? false;
  }

  get isReadonly(): boolean {
    return this._readonly;
  }

  private assertWritable(operation: string): void {
    if (this._readonly) {
      throw new ReadonlyModeError(operation);
    }
  }

  private async ensureToken(): Promise<string> {
    if (this.token && this.tokenExpires && this.tokenExpires > new Date()) {
      return this.token;
    }

    const response = await fetch(`${this.baseUrl}/api/tokens`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        identity: this.email,
        secret: this.password,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Authentication failed: ${error}`);
    }

    const data = (await response.json()) as TokenResponse;
    this.token = data.token;
    this.tokenExpires = new Date(data.expires);
    return this.token;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    queryParams?: Record<string, string | number>
  ): Promise<T> {
    const token = await this.ensureToken();
    
    let url = `${this.baseUrl}/api${path}`;
    if (queryParams) {
      const params = new URLSearchParams();
      Object.entries(queryParams).forEach(([key, value]) => {
        params.append(key, String(value));
      });
      url += `?${params.toString()}`;
    }
    
    const response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`API request failed: ${response.status} - ${error}`);
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json() as Promise<T>;
  }

  // Proxy Hosts
  async listProxyHosts(options?: {
    limit?: number;
    offset?: number;
  }): Promise<ProxyHost[]> {
    // Fetch all hosts (API doesn't support server-side pagination)
    const allHosts = await this.request<ProxyHost[]>(
      "GET",
      "/nginx/proxy-hosts"
    );
    
    // Apply client-side pagination
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allHosts.slice(offset, offset + limit);
      }
      return allHosts.slice(offset);
    }
    
    return allHosts;
  }

  async getProxyHost(id: number): Promise<ProxyHost> {
    return this.request<ProxyHost>("GET", `/nginx/proxy-hosts/${id}`);
  }

  async createProxyHost(data: CreateProxyHostInput): Promise<ProxyHost> {
    this.assertWritable("createProxyHost");
    return this.request<ProxyHost>("POST", "/nginx/proxy-hosts", data);
  }

  async updateProxyHost(
    id: number,
    data: Partial<CreateProxyHostInput>
  ): Promise<ProxyHost> {
    this.assertWritable("updateProxyHost");
    return this.request<ProxyHost>("PUT", `/nginx/proxy-hosts/${id}`, data);
  }

  async deleteProxyHost(id: number): Promise<void> {
    this.assertWritable("deleteProxyHost");
    await this.request<void>("DELETE", `/nginx/proxy-hosts/${id}`);
  }

  async enableProxyHost(id: number): Promise<ProxyHost> {
    this.assertWritable("enableProxyHost");
    return this.request<ProxyHost>("POST", `/nginx/proxy-hosts/${id}/enable`);
  }

  async disableProxyHost(id: number): Promise<ProxyHost> {
    this.assertWritable("disableProxyHost");
    return this.request<ProxyHost>("POST", `/nginx/proxy-hosts/${id}/disable`);
  }

  // Certificates
  async listCertificates(options?: {
    limit?: number;
    offset?: number;
  }): Promise<Certificate[]> {
    const allCerts = await this.request<Certificate[]>(
      "GET",
      "/nginx/certificates"
    );
    
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allCerts.slice(offset, offset + limit);
      }
      return allCerts.slice(offset);
    }
    
    return allCerts;
  }

  async getCertificate(id: number): Promise<Certificate> {
    return this.request<Certificate>("GET", `/nginx/certificates/${id}`);
  }

  async deleteCertificate(id: number): Promise<void> {
    this.assertWritable("deleteCertificate");
    await this.request<void>("DELETE", `/nginx/certificates/${id}`);
  }

  async renewCertificate(id: number): Promise<Certificate> {
    this.assertWritable("renewCertificate");
    return this.request<Certificate>(
      "POST",
      `/nginx/certificates/${id}/renew`
    );
  }

  // Streams
  async listStreams(options?: {
    limit?: number;
    offset?: number;
  }): Promise<Stream[]> {
    const allStreams = await this.request<Stream[]>(
      "GET",
      "/nginx/streams"
    );
    
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allStreams.slice(offset, offset + limit);
      }
      return allStreams.slice(offset);
    }
    
    return allStreams;
  }

  async getStream(id: number): Promise<Stream> {
    return this.request<Stream>("GET", `/nginx/streams/${id}`);
  }

  async createStream(data: CreateStreamInput): Promise<Stream> {
    this.assertWritable("createStream");
    return this.request<Stream>("POST", "/nginx/streams", data);
  }

  async updateStream(
    id: number,
    data: Partial<CreateStreamInput>
  ): Promise<Stream> {
    this.assertWritable("updateStream");
    return this.request<Stream>("PUT", `/nginx/streams/${id}`, data);
  }

  async deleteStream(id: number): Promise<void> {
    this.assertWritable("deleteStream");
    await this.request<void>("DELETE", `/nginx/streams/${id}`);
  }

  async enableStream(id: number): Promise<Stream> {
    this.assertWritable("enableStream");
    return this.request<Stream>("POST", `/nginx/streams/${id}/enable`);
  }

  async disableStream(id: number): Promise<Stream> {
    this.assertWritable("disableStream");
    return this.request<Stream>("POST", `/nginx/streams/${id}/disable`);
  }

  // Redirection Hosts
  async listRedirectionHosts(options?: {
    limit?: number;
    offset?: number;
  }): Promise<RedirectionHost[]> {
    const allHosts = await this.request<RedirectionHost[]>(
      "GET",
      "/nginx/redirection-hosts"
    );
    
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allHosts.slice(offset, offset + limit);
      }
      return allHosts.slice(offset);
    }
    
    return allHosts;
  }

  async getRedirectionHost(id: number): Promise<RedirectionHost> {
    return this.request<RedirectionHost>(
      "GET",
      `/nginx/redirection-hosts/${id}`
    );
  }

  async createRedirectionHost(
    data: CreateRedirectionHostInput
  ): Promise<RedirectionHost> {
    this.assertWritable("createRedirectionHost");
    return this.request<RedirectionHost>(
      "POST",
      "/nginx/redirection-hosts",
      data
    );
  }

  async updateRedirectionHost(
    id: number,
    data: Partial<CreateRedirectionHostInput>
  ): Promise<RedirectionHost> {
    this.assertWritable("updateRedirectionHost");
    return this.request<RedirectionHost>(
      "PUT",
      `/nginx/redirection-hosts/${id}`,
      data
    );
  }

  async deleteRedirectionHost(id: number): Promise<void> {
    this.assertWritable("deleteRedirectionHost");
    await this.request<void>("DELETE", `/nginx/redirection-hosts/${id}`);
  }

  async enableRedirectionHost(id: number): Promise<RedirectionHost> {
    this.assertWritable("enableRedirectionHost");
    return this.request<RedirectionHost>(
      "POST",
      `/nginx/redirection-hosts/${id}/enable`
    );
  }

  async disableRedirectionHost(id: number): Promise<RedirectionHost> {
    this.assertWritable("disableRedirectionHost");
    return this.request<RedirectionHost>(
      "POST",
      `/nginx/redirection-hosts/${id}/disable`
    );
  }

  // Dead Hosts (404 Hosts)
  async listDeadHosts(options?: {
    limit?: number;
    offset?: number;
  }): Promise<DeadHost[]> {
    const allHosts = await this.request<DeadHost[]>(
      "GET",
      "/nginx/dead-hosts"
    );
    
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allHosts.slice(offset, offset + limit);
      }
      return allHosts.slice(offset);
    }
    
    return allHosts;
  }

  async getDeadHost(id: number): Promise<DeadHost> {
    return this.request<DeadHost>("GET", `/nginx/dead-hosts/${id}`);
  }

  async createDeadHost(data: CreateDeadHostInput): Promise<DeadHost> {
    this.assertWritable("createDeadHost");
    return this.request<DeadHost>("POST", "/nginx/dead-hosts", data);
  }

  async updateDeadHost(
    id: number,
    data: Partial<CreateDeadHostInput>
  ): Promise<DeadHost> {
    this.assertWritable("updateDeadHost");
    return this.request<DeadHost>("PUT", `/nginx/dead-hosts/${id}`, data);
  }

  async deleteDeadHost(id: number): Promise<void> {
    this.assertWritable("deleteDeadHost");
    await this.request<void>("DELETE", `/nginx/dead-hosts/${id}`);
  }

  async enableDeadHost(id: number): Promise<DeadHost> {
    this.assertWritable("enableDeadHost");
    return this.request<DeadHost>("POST", `/nginx/dead-hosts/${id}/enable`);
  }

  async disableDeadHost(id: number): Promise<DeadHost> {
    this.assertWritable("disableDeadHost");
    return this.request<DeadHost>("POST", `/nginx/dead-hosts/${id}/disable`);
  }

  // Access Lists
  async listAccessLists(options?: {
    limit?: number;
    offset?: number;
  }): Promise<AccessList[]> {
    const allLists = await this.request<AccessList[]>(
      "GET",
      "/nginx/access-lists"
    );
    
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allLists.slice(offset, offset + limit);
      }
      return allLists.slice(offset);
    }
    
    return allLists;
  }

  async getAccessList(id: number): Promise<AccessList> {
    return this.request<AccessList>("GET", `/nginx/access-lists/${id}`);
  }

  async createAccessList(data: CreateAccessListInput): Promise<AccessList> {
    this.assertWritable("createAccessList");
    return this.request<AccessList>("POST", "/nginx/access-lists", data);
  }

  async updateAccessList(
    id: number,
    data: Partial<CreateAccessListInput>
  ): Promise<AccessList> {
    this.assertWritable("updateAccessList");
    return this.request<AccessList>("PUT", `/nginx/access-lists/${id}`, data);
  }

  async deleteAccessList(id: number): Promise<void> {
    this.assertWritable("deleteAccessList");
    await this.request<void>("DELETE", `/nginx/access-lists/${id}`);
  }

  // Users
  async listUsers(options?: {
    limit?: number;
    offset?: number;
  }): Promise<User[]> {
    const allUsers = await this.request<User[]>(
      "GET",
      "/users"
    );
    
    if (options?.limit !== undefined || options?.offset !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit;
      
      if (limit !== undefined) {
        return allUsers.slice(offset, offset + limit);
      }
      return allUsers.slice(offset);
    }
    
    return allUsers;
  }

  async getUser(id: number): Promise<User> {
    return this.request<User>("GET", `/users/${id}`);
  }

  // Health / Status
  async getHealth(): Promise<{ status: string; version: { current: string } }> {
    const response = await fetch(`${this.baseUrl}/api/`);
    return response.json();
  }
}
