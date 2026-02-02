#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { NpmApiClient } from "./api-client.js";

// Get configuration from environment variables
const NPM_URL = process.env.NPM_URL || "http://localhost:81";
const NPM_EMAIL = process.env.NPM_EMAIL || "";
const NPM_PASSWORD = process.env.NPM_PASSWORD || "";
const NPM_READONLY = process.env.NPM_READONLY === "true";

if (!NPM_EMAIL || !NPM_PASSWORD) {
  console.error(
    "Error: NPM_EMAIL and NPM_PASSWORD environment variables are required"
  );
  process.exit(1);
}

const client = new NpmApiClient({
  baseUrl: NPM_URL,
  email: NPM_EMAIL,
  password: NPM_PASSWORD,
  readonly: NPM_READONLY,
});

if (NPM_READONLY) {
  console.error("Nginx Proxy Manager MCP Server running in READONLY mode");
}

const server = new McpServer({
  name: "nginx-proxy-manager",
  version: "1.0.0",
});

// Helper function to format paginated responses
function formatPaginatedResponse<T>(
  items: T[],
  limit: number,
  offset: number,
  itemsKey: string
): string {
  const hasMore = items.length === limit;
  const result = {
    [itemsKey]: items,
    pagination: {
      limit,
      offset,
      returned: items.length,
      hasMore,
      nextOffset: hasMore ? offset + limit : null,
    },
  };
  
  let message = JSON.stringify(result, null, 2);
  
  if (hasMore) {
    message += `\n\n⚠️  MORE DATA AVAILABLE: ${items.length} results returned. There may be more ${itemsKey}. Use offset=${offset + limit} to fetch the next page.`;
  } else if (items.length === 0 && offset > 0) {
    message += `\n\nℹ️  No more results. You've reached the end of the data.`;
  }
  
  return message;
}

// ============ PROXY HOSTS ============

server.tool(
  "list_proxy_hosts",
  "List all proxy hosts configured in Nginx Proxy Manager",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const hosts = await client.listProxyHosts({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(hosts, limit, offset, "hosts"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "get_proxy_host",
  "Get details of a specific proxy host by ID",
  {
    id: z.number().describe("The proxy host ID"),
  },
  async ({ id }) => {
    try {
      const host = await client.getProxyHost(id);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(host, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "create_proxy_host",
  "Create a new proxy host to forward traffic from domain(s) to a backend server",
  {
    domain_names: z
      .array(z.string())
      .describe("List of domain names (e.g., ['app.example.com'])"),
    forward_host: z
      .string()
      .describe("The backend host to forward to (e.g., '192.168.1.100')"),
    forward_port: z
      .number()
      .describe("The backend port to forward to (e.g., 8080)"),
    forward_scheme: z
      .enum(["http", "https"])
      .default("http")
      .describe("Protocol to use when forwarding"),
    ssl_forced: z
      .boolean()
      .default(false)
      .describe("Force SSL/HTTPS for incoming requests"),
    allow_websocket_upgrade: z
      .boolean()
      .default(false)
      .describe("Allow WebSocket connections"),
    block_exploits: z
      .boolean()
      .default(false)
      .describe("Block common exploits"),
    caching_enabled: z.boolean().default(false).describe("Enable caching"),
    http2_support: z.boolean().default(false).describe("Enable HTTP/2 support"),
    hsts_enabled: z.boolean().default(false).describe("Enable HSTS"),
    certificate_id: z
      .number()
      .optional()
      .describe("SSL certificate ID to use"),
    access_list_id: z.number().optional().describe("Access list ID to apply"),
    advanced_config: z
      .string()
      .optional()
      .describe("Custom Nginx configuration"),
  },
  async (params) => {
    try {
      const host = await client.createProxyHost({
        domain_names: params.domain_names,
        forward_host: params.forward_host,
        forward_port: params.forward_port,
        forward_scheme: params.forward_scheme,
        ssl_forced: params.ssl_forced,
        allow_websocket_upgrade: params.allow_websocket_upgrade,
        block_exploits: params.block_exploits,
        caching_enabled: params.caching_enabled,
        http2_support: params.http2_support,
        hsts_enabled: params.hsts_enabled,
        certificate_id: params.certificate_id,
        access_list_id: params.access_list_id,
        advanced_config: params.advanced_config,
      });
      return {
        content: [
          {
            type: "text",
            text: `Proxy host created successfully:\n${JSON.stringify(host, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "update_proxy_host",
  "Update an existing proxy host",
  {
    id: z.number().describe("The proxy host ID to update"),
    domain_names: z.array(z.string()).optional().describe("List of domain names"),
    forward_host: z.string().optional().describe("The backend host"),
    forward_port: z.number().optional().describe("The backend port"),
    forward_scheme: z.enum(["http", "https"]).optional().describe("Protocol"),
    ssl_forced: z.boolean().optional().describe("Force SSL"),
    allow_websocket_upgrade: z.boolean().optional().describe("Allow WebSocket"),
    block_exploits: z.boolean().optional().describe("Block exploits"),
    caching_enabled: z.boolean().optional().describe("Enable caching"),
    http2_support: z.boolean().optional().describe("Enable HTTP/2"),
    hsts_enabled: z.boolean().optional().describe("Enable HSTS"),
    certificate_id: z.number().optional().describe("SSL certificate ID"),
    access_list_id: z.number().optional().describe("Access list ID"),
    advanced_config: z.string().optional().describe("Custom Nginx config"),
  },
  async ({ id, ...params }) => {
    try {
      const host = await client.updateProxyHost(id, params);
      return {
        content: [
          {
            type: "text",
            text: `Proxy host updated successfully:\n${JSON.stringify(host, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "delete_proxy_host",
  "Delete a proxy host",
  {
    id: z.number().describe("The proxy host ID to delete"),
  },
  async ({ id }) => {
    try {
      await client.deleteProxyHost(id);
      return {
        content: [
          {
            type: "text",
            text: `Proxy host ${id} deleted successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "enable_proxy_host",
  "Enable a proxy host",
  {
    id: z.number().describe("The proxy host ID to enable"),
  },
  async ({ id }) => {
    try {
      const host = await client.enableProxyHost(id);
      return {
        content: [
          {
            type: "text",
            text: `Proxy host ${id} enabled successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "disable_proxy_host",
  "Disable a proxy host",
  {
    id: z.number().describe("The proxy host ID to disable"),
  },
  async ({ id }) => {
    try {
      const host = await client.disableProxyHost(id);
      return {
        content: [
          {
            type: "text",
            text: `Proxy host ${id} disabled successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ STREAMS ============

server.tool(
  "list_streams",
  "List all TCP/UDP stream configurations",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const streams = await client.listStreams({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(streams, limit, offset, "streams"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "create_stream",
  "Create a new TCP/UDP stream to forward traffic on a specific port",
  {
    incoming_port: z.number().describe("The port to listen on"),
    forwarding_host: z.string().describe("The backend host to forward to"),
    forwarding_port: z.number().describe("The backend port to forward to"),
    tcp_forwarding: z.boolean().default(true).describe("Enable TCP forwarding"),
    udp_forwarding: z.boolean().default(false).describe("Enable UDP forwarding"),
  },
  async (params) => {
    try {
      const stream = await client.createStream(params);
      return {
        content: [
          {
            type: "text",
            text: `Stream created successfully:\n${JSON.stringify(stream, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "delete_stream",
  "Delete a stream",
  {
    id: z.number().describe("The stream ID to delete"),
  },
  async ({ id }) => {
    try {
      await client.deleteStream(id);
      return {
        content: [
          {
            type: "text",
            text: `Stream ${id} deleted successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "enable_stream",
  "Enable a stream",
  {
    id: z.number().describe("The stream ID to enable"),
  },
  async ({ id }) => {
    try {
      await client.enableStream(id);
      return {
        content: [
          {
            type: "text",
            text: `Stream ${id} enabled successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "disable_stream",
  "Disable a stream",
  {
    id: z.number().describe("The stream ID to disable"),
  },
  async ({ id }) => {
    try {
      await client.disableStream(id);
      return {
        content: [
          {
            type: "text",
            text: `Stream ${id} disabled successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ REDIRECTION HOSTS ============

server.tool(
  "list_redirection_hosts",
  "List all redirection hosts",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const hosts = await client.listRedirectionHosts({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(hosts, limit, offset, "redirection_hosts"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "create_redirection_host",
  "Create a new redirection host to redirect traffic from domain(s) to another URL",
  {
    domain_names: z.array(z.string()).describe("List of domain names"),
    forward_scheme: z
      .enum(["http", "https", "$scheme"])
      .describe("Redirect scheme"),
    forward_domain_name: z.string().describe("Target domain to redirect to"),
    forward_http_code: z
      .number()
      .default(301)
      .describe("HTTP redirect code (301, 302, etc.)"),
    preserve_path: z
      .boolean()
      .default(true)
      .describe("Preserve the path in redirect"),
    ssl_forced: z.boolean().default(false).describe("Force SSL"),
    block_exploits: z.boolean().default(false).describe("Block exploits"),
    certificate_id: z.number().optional().describe("SSL certificate ID"),
  },
  async (params) => {
    try {
      const host = await client.createRedirectionHost(params);
      return {
        content: [
          {
            type: "text",
            text: `Redirection host created successfully:\n${JSON.stringify(host, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "delete_redirection_host",
  "Delete a redirection host",
  {
    id: z.number().describe("The redirection host ID to delete"),
  },
  async ({ id }) => {
    try {
      await client.deleteRedirectionHost(id);
      return {
        content: [
          {
            type: "text",
            text: `Redirection host ${id} deleted successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ CERTIFICATES ============

server.tool(
  "list_certificates",
  "List all SSL certificates",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const certs = await client.listCertificates({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(certs, limit, offset, "certificates"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "get_certificate",
  "Get details of a specific certificate",
  {
    id: z.number().describe("The certificate ID"),
  },
  async ({ id }) => {
    try {
      const cert = await client.getCertificate(id);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(cert, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "renew_certificate",
  "Renew an SSL certificate",
  {
    id: z.number().describe("The certificate ID to renew"),
  },
  async ({ id }) => {
    try {
      const cert = await client.renewCertificate(id);
      return {
        content: [
          {
            type: "text",
            text: `Certificate renewed successfully:\n${JSON.stringify(cert, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "delete_certificate",
  "Delete an SSL certificate",
  {
    id: z.number().describe("The certificate ID to delete"),
  },
  async ({ id }) => {
    try {
      await client.deleteCertificate(id);
      return {
        content: [
          {
            type: "text",
            text: `Certificate ${id} deleted successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ ACCESS LISTS ============

server.tool(
  "list_access_lists",
  "List all access lists",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const lists = await client.listAccessLists({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(lists, limit, offset, "access_lists"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "create_access_list",
  "Create a new access list for authentication or IP-based access control",
  {
    name: z.string().describe("Name for the access list"),
    satisfy_any: z
      .boolean()
      .default(false)
      .describe("Satisfy any or all conditions"),
    pass_auth: z
      .boolean()
      .default(false)
      .describe("Pass auth to upstream"),
  },
  async (params) => {
    try {
      const list = await client.createAccessList(params);
      return {
        content: [
          {
            type: "text",
            text: `Access list created successfully:\n${JSON.stringify(list, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "delete_access_list",
  "Delete an access list",
  {
    id: z.number().describe("The access list ID to delete"),
  },
  async ({ id }) => {
    try {
      await client.deleteAccessList(id);
      return {
        content: [
          {
            type: "text",
            text: `Access list ${id} deleted successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ DEAD HOSTS (404) ============

server.tool(
  "list_dead_hosts",
  "List all 404 hosts (domains that show a 404 page)",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const hosts = await client.listDeadHosts({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(hosts, limit, offset, "dead_hosts"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "create_dead_host",
  "Create a new 404 host (shows 404 page for specified domains)",
  {
    domain_names: z.array(z.string()).describe("List of domain names"),
    certificate_id: z.number().optional().describe("SSL certificate ID"),
    ssl_forced: z.boolean().default(false).describe("Force SSL"),
  },
  async (params) => {
    try {
      const host = await client.createDeadHost(params);
      return {
        content: [
          {
            type: "text",
            text: `Dead host created successfully:\n${JSON.stringify(host, null, 2)}`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "delete_dead_host",
  "Delete a 404 host",
  {
    id: z.number().describe("The dead host ID to delete"),
  },
  async ({ id }) => {
    try {
      await client.deleteDeadHost(id);
      return {
        content: [
          {
            type: "text",
            text: `Dead host ${id} deleted successfully`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ USERS ============

server.tool(
  "list_users",
  "List all users in Nginx Proxy Manager",
  {
    limit: z
      .number()
      .min(1)
      .max(100)
      .default(50)
      .describe("Maximum number of results to return (default: 50, max: 100)"),
    offset: z
      .number()
      .min(0)
      .default(0)
      .describe("Number of results to skip for pagination (default: 0)"),
  },
  async ({ limit, offset }) => {
    try {
      const users = await client.listUsers({ limit, offset });
      return {
        content: [
          {
            type: "text",
            text: formatPaginatedResponse(users, limit, offset, "users"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ============ HEALTH ============

server.tool(
  "get_status",
  "Get the health status, version, and mode of Nginx Proxy Manager MCP server",
  {},
  async () => {
    try {
      const health = await client.getHealth();
      const status = {
        ...health,
        mcp_server: {
          readonly: client.isReadonly,
          mode: client.isReadonly ? "readonly" : "read-write",
        },
      };
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(status, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Nginx Proxy Manager MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
