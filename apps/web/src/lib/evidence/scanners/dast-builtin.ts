import http from "http";
import https from "https";
import tls from "tls";
import { URL } from "url";

const REQUEST_TIMEOUT_MS = 10000;

interface DastCheck {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "fail" | "error";
  detail: string;
}

interface TlsInfo {
  protocol: string | null;
  cipher: string | null;
  cert_expires: string | null;
  cert_issuer: string | null;
}

export interface DastScanResult {
  scan_timestamp: string;
  scanner: "complyt-dast";
  target_url: string;
  tls: TlsInfo;
  checks: DastCheck[];
  summary: {
    total: number;
    passed: number;
    failed: number;
  };
  errors: string[];
}

const SENSITIVE_PATHS = [
  "/.env",
  "/.git/config",
  "/.aws/credentials",
  "/wp-admin",
  "/server-status",
  "/phpinfo.php",
  "/actuator",
  "/.well-known/security.txt",
];

function makeRequest(
  targetUrl: string,
  extraHeaders: Record<string, string> = {},
  method = "GET"
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === "https:";
    const transport = isHttps ? https : http;

    const req = transport.request(
      targetUrl,
      {
        method,
        headers: {
          "User-Agent": "ComplytDAST/1.0",
          ...extraHeaders,
        },
        timeout: REQUEST_TIMEOUT_MS,
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf-8").slice(0, 50000),
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });
    req.on("error", reject);
    req.end();
  });
}

function makeHeadRequest(
  targetUrl: string
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.startsWith("https:");
    const transport = isHttps ? https : http;

    const req = transport.request(
      targetUrl,
      {
        method: "HEAD",
        headers: { "User-Agent": "ComplytDAST/1.0" },
        timeout: REQUEST_TIMEOUT_MS,
        rejectUnauthorized: false,
      },
      (res) => {
        res.resume();
        resolve({ statusCode: res.statusCode ?? 0, headers: res.headers });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("HEAD request timed out"));
    });
    req.on("error", reject);
    req.end();
  });
}

function getTlsInfo(hostname: string, port: number): Promise<TlsInfo> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        rejectUnauthorized: false,
        timeout: REQUEST_TIMEOUT_MS,
      },
      () => {
        const protocol = socket.getProtocol?.() ?? null;
        const cipher = socket.getCipher?.()?.name ?? null;
        const cert = socket.getPeerCertificate?.();

        let certExpires: string | null = null;
        let certIssuer: string | null = null;

        if (cert && typeof cert === "object" && "valid_to" in cert) {
          certExpires = (cert as { valid_to: string }).valid_to;
          const issuerObj = (cert as { issuer?: { O?: string; CN?: string } }).issuer;
          certIssuer = issuerObj
            ? [issuerObj.O, issuerObj.CN].filter(Boolean).join(" - ") || null
            : null;
        }

        socket.end();
        resolve({ protocol, cipher, cert_expires: certExpires, cert_issuer: certIssuer });
      }
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ protocol: null, cipher: null, cert_expires: null, cert_issuer: null });
    });

    socket.on("error", () => {
      socket.destroy();
      resolve({ protocol: null, cipher: null, cert_expires: null, cert_issuer: null });
    });
  });
}

function checkHeaderPresent(
  headers: http.IncomingHttpHeaders,
  headerName: string,
  expectedValue?: string
): { present: boolean; value: string | null } {
  const raw = headers[headerName];
  const value = Array.isArray(raw) ? raw[0] : raw ?? null;
  const present = value != null && value.length > 0;

  if (expectedValue && present) {
    return { present: value!.toLowerCase().includes(expectedValue.toLowerCase()), value };
  }

  return { present, value };
}

function checkServerVersionDisclosure(headers: http.IncomingHttpHeaders): DastCheck {
  const server = headers["server"] ?? "";
  const hasVersion = /\d+\.\d+/.test(String(server));

  return {
    id: "HTTP-07",
    title: "Server version disclosure",
    severity: "high",
    status: hasVersion ? "fail" : "pass",
    detail: hasVersion
      ? `Server header discloses version: ${server}`
      : "Server header does not disclose version number",
  };
}

function checkXPoweredBy(headers: http.IncomingHttpHeaders): DastCheck {
  const value = headers["x-powered-by"];
  const present = value != null;

  return {
    id: "HTTP-08",
    title: "X-Powered-By disclosure",
    severity: "medium",
    status: present ? "fail" : "pass",
    detail: present
      ? `X-Powered-By header present: ${value}`
      : "X-Powered-By header not present",
  };
}

function checkTlsProtocol(tlsInfo: TlsInfo): DastCheck {
  if (!tlsInfo.protocol) {
    return {
      id: "HTTP-09",
      title: "Weak TLS protocol",
      severity: "high",
      status: "error",
      detail: "Could not determine TLS protocol version",
    };
  }

  const weak = ["TLSv1", "TLSv1.1", "SSLv3"];
  const isFail = weak.some((w) => tlsInfo.protocol!.includes(w));

  return {
    id: "HTTP-09",
    title: "Weak TLS protocol",
    severity: "high",
    status: isFail ? "fail" : "pass",
    detail: isFail
      ? `Weak TLS protocol in use: ${tlsInfo.protocol}`
      : `TLS protocol: ${tlsInfo.protocol}`,
  };
}

function checkCertExpiry(tlsInfo: TlsInfo): DastCheck {
  if (!tlsInfo.cert_expires) {
    return {
      id: "HTTP-10",
      title: "Certificate expiry",
      severity: "high",
      status: "error",
      detail: "Could not determine certificate expiry",
    };
  }

  const expiryDate = new Date(tlsInfo.cert_expires);
  const now = new Date();
  const daysUntilExpiry = Math.floor(
    (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );

  if (daysUntilExpiry < 0) {
    return {
      id: "HTTP-10",
      title: "Certificate expiry",
      severity: "high",
      status: "fail",
      detail: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago (${tlsInfo.cert_expires})`,
    };
  }

  if (daysUntilExpiry < 30) {
    return {
      id: "HTTP-10",
      title: "Certificate expiry",
      severity: "high",
      status: "fail",
      detail: `Certificate expires in ${daysUntilExpiry} days (${tlsInfo.cert_expires})`,
    };
  }

  return {
    id: "HTTP-10",
    title: "Certificate expiry",
    severity: "high",
    status: "pass",
    detail: `Certificate valid for ${daysUntilExpiry} days (expires ${tlsInfo.cert_expires})`,
  };
}

interface CookieAttributes {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: boolean;
}

function parseCookies(headers: http.IncomingHttpHeaders): CookieAttributes[] {
  const raw = headers["set-cookie"];
  if (!raw) return [];

  return raw.map((cookie) => {
    const parts = cookie.split(";").map((p) => p.trim().toLowerCase());
    const nameMatch = cookie.match(/^([^=]+)=/);
    return {
      name: nameMatch ? nameMatch[1].trim() : "unknown",
      secure: parts.some((p) => p === "secure"),
      httpOnly: parts.some((p) => p === "httponly"),
      sameSite: parts.some((p) => p.startsWith("samesite")),
    };
  });
}

function checkCookieSecure(cookies: CookieAttributes[]): DastCheck {
  if (cookies.length === 0) {
    return {
      id: "HTTP-11",
      title: "Cookie missing Secure flag",
      severity: "high",
      status: "pass",
      detail: "No cookies set",
    };
  }

  const insecure = cookies.filter((c) => !c.secure).map((c) => c.name);
  return {
    id: "HTTP-11",
    title: "Cookie missing Secure flag",
    severity: "high",
    status: insecure.length > 0 ? "fail" : "pass",
    detail:
      insecure.length > 0
        ? `Cookies without Secure flag: ${insecure.join(", ")}`
        : "All cookies have Secure flag",
  };
}

function checkCookieHttpOnly(cookies: CookieAttributes[]): DastCheck {
  if (cookies.length === 0) {
    return {
      id: "HTTP-12",
      title: "Cookie missing HttpOnly flag",
      severity: "medium",
      status: "pass",
      detail: "No cookies set",
    };
  }

  const exposed = cookies.filter((c) => !c.httpOnly).map((c) => c.name);
  return {
    id: "HTTP-12",
    title: "Cookie missing HttpOnly flag",
    severity: "medium",
    status: exposed.length > 0 ? "fail" : "pass",
    detail:
      exposed.length > 0
        ? `Cookies without HttpOnly flag: ${exposed.join(", ")}`
        : "All cookies have HttpOnly flag",
  };
}

function checkCookieSameSite(cookies: CookieAttributes[]): DastCheck {
  if (cookies.length === 0) {
    return {
      id: "HTTP-13",
      title: "Cookie missing SameSite attribute",
      severity: "medium",
      status: "pass",
      detail: "No cookies set",
    };
  }

  const missing = cookies.filter((c) => !c.sameSite).map((c) => c.name);
  return {
    id: "HTTP-13",
    title: "Cookie missing SameSite attribute",
    severity: "medium",
    status: missing.length > 0 ? "fail" : "pass",
    detail:
      missing.length > 0
        ? `Cookies without SameSite: ${missing.join(", ")}`
        : "All cookies have SameSite attribute",
  };
}

async function checkCors(targetUrl: string): Promise<DastCheck> {
  try {
    const response = await makeRequest(
      targetUrl,
      { Origin: "https://evil.example.com" }
    );

    const acao = response.headers["access-control-allow-origin"];
    const isWildcard = acao === "*";
    const reflectsEvil = acao === "https://evil.example.com";

    if (isWildcard) {
      return {
        id: "HTTP-14",
        title: "Overly permissive CORS",
        severity: "high",
        status: "fail",
        detail: "Access-Control-Allow-Origin is set to wildcard (*)",
      };
    }

    if (reflectsEvil) {
      return {
        id: "HTTP-14",
        title: "Overly permissive CORS",
        severity: "high",
        status: "fail",
        detail: "Server reflects arbitrary Origin header in ACAO",
      };
    }

    return {
      id: "HTTP-14",
      title: "Overly permissive CORS",
      severity: "high",
      status: "pass",
      detail: acao
        ? `CORS restricted to: ${acao}`
        : "No CORS header present (same-origin policy applies)",
    };
  } catch (err) {
    return {
      id: "HTTP-14",
      title: "Overly permissive CORS",
      severity: "high",
      status: "error",
      detail: `CORS check failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function checkSensitivePaths(baseUrl: string): Promise<DastCheck> {
  const exposed: string[] = [];

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (p) => {
      try {
        const url = new URL(p, baseUrl).toString();
        const res = await makeHeadRequest(url);
        if (res.statusCode === 200) exposed.push(p);
      } catch {
        // path unreachable — not exposed
      }
    })
  );

  // allSettled always resolves; results consumed via `exposed` side-effect above
  void results;

  return {
    id: "HTTP-15",
    title: "Sensitive paths exposed",
    severity: "high",
    status: exposed.length > 0 ? "fail" : "pass",
    detail:
      exposed.length > 0
        ? `Accessible sensitive paths: ${exposed.join(", ")}`
        : "No sensitive paths accessible",
  };
}

function validateUrl(input: string): URL | null {
  try {
    const parsed = new URL(input);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function runBuiltinDastScan(
  targetUrl: string
): Promise<DastScanResult> {
  const timestamp = new Date().toISOString();
  const errors: string[] = [];
  const nullTls: TlsInfo = {
    protocol: null,
    cipher: null,
    cert_expires: null,
    cert_issuer: null,
  };

  const parsed = validateUrl(targetUrl);
  if (!parsed) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-dast",
      target_url: targetUrl,
      tls: nullTls,
      checks: [],
      summary: { total: 0, passed: 0, failed: 0 },
      errors: [`Invalid URL: ${targetUrl}. Must be http:// or https://`],
    };
  }

  const isHttps = parsed.protocol === "https:";
  const port = parsed.port ? parseInt(parsed.port, 10) : isHttps ? 443 : 80;

  let mainResponse: Awaited<ReturnType<typeof makeRequest>>;
  try {
    mainResponse = await makeRequest(targetUrl);
  } catch (err) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-dast",
      target_url: targetUrl,
      tls: nullTls,
      checks: [],
      summary: { total: 0, passed: 0, failed: 0 },
      errors: [
        `Connection failed: ${err instanceof Error ? err.message : String(err)}`,
      ],
    };
  }

  const headers = mainResponse.headers;
  const checks: DastCheck[] = [];

  const headerChecks: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    header: string;
    expected?: string;
  }> = [
    { id: "HTTP-01", severity: "high", title: "Missing HSTS", header: "strict-transport-security" },
    { id: "HTTP-02", severity: "medium", title: "Missing X-Content-Type-Options", header: "x-content-type-options", expected: "nosniff" },
    { id: "HTTP-03", severity: "medium", title: "Missing X-Frame-Options", header: "x-frame-options" },
    { id: "HTTP-04", severity: "medium", title: "Missing Content-Security-Policy", header: "content-security-policy" },
    { id: "HTTP-05", severity: "low", title: "Missing Referrer-Policy", header: "referrer-policy" },
    { id: "HTTP-06", severity: "low", title: "Missing Permissions-Policy", header: "permissions-policy" },
  ];

  for (const hc of headerChecks) {
    const { present, value } = checkHeaderPresent(headers, hc.header, hc.expected);
    checks.push({
      id: hc.id,
      title: hc.title,
      severity: hc.severity,
      status: present ? "pass" : "fail",
      detail: present
        ? `${hc.header}: ${value}`
        : `${hc.header} header is missing`,
    });
  }

  checks.push(checkServerVersionDisclosure(headers));
  checks.push(checkXPoweredBy(headers));

  let tlsInfo = nullTls;
  if (isHttps) {
    tlsInfo = await getTlsInfo(parsed.hostname, port);
    checks.push(checkTlsProtocol(tlsInfo));
    checks.push(checkCertExpiry(tlsInfo));
  } else {
    checks.push({
      id: "HTTP-09",
      title: "Weak TLS protocol",
      severity: "high",
      status: "error",
      detail: "Skipped — target is not HTTPS",
    });
    checks.push({
      id: "HTTP-10",
      title: "Certificate expiry",
      severity: "high",
      status: "error",
      detail: "Skipped — target is not HTTPS",
    });
    errors.push("TLS checks skipped: target URL is not HTTPS");
  }

  const cookies = parseCookies(headers);
  checks.push(checkCookieSecure(cookies));
  checks.push(checkCookieHttpOnly(cookies));
  checks.push(checkCookieSameSite(cookies));

  checks.push(await checkCors(targetUrl));
  checks.push(await checkSensitivePaths(targetUrl));

  const passed = checks.filter((c) => c.status === "pass").length;
  const failed = checks.filter((c) => c.status === "fail").length;

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-dast",
    target_url: targetUrl,
    tls: tlsInfo,
    checks,
    summary: { total: checks.length, passed, failed },
    errors,
  };
}
