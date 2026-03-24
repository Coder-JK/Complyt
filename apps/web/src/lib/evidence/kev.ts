import fs from "fs";
import path from "path";
import { resilientFetch, OfflineError } from "./http";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const CACHE_DIR = path.resolve(process.cwd(), "data", "cache");
const CACHE_FILE = path.join(CACHE_DIR, "kev.json");
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

export async function fetchKev(): Promise<Map<string, KevEntry>> {
  const catalog = await loadKevCatalog();
  const map = new Map<string, KevEntry>();

  for (const vuln of catalog.vulnerabilities) {
    map.set(vuln.cveID, vuln);
  }

  return map;
}

async function loadKevCatalog(): Promise<KevCatalog> {
  const cached = readCache();
  if (cached) return cached;

  try {
    const response = await resilientFetch(KEV_URL, { timeoutMs: 15000 });
    const data: KevCatalog = await response.json();
    writeCache(data);
    return data;
  } catch (error) {
    if (error instanceof OfflineError) {
      const stale = readCache(true);
      if (stale) return stale;
    }
    throw error;
  }
}

function readCache(ignoreExpiry = false): KevCatalog | null {
  try {
    if (!fs.existsSync(CACHE_FILE)) return null;
    const stat = fs.statSync(CACHE_FILE);
    const ageMs = Date.now() - stat.mtimeMs;

    if (!ignoreExpiry && ageMs > CACHE_TTL_MS) return null;

    const raw = fs.readFileSync(CACHE_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function writeCache(data: KevCatalog): void {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data));
  } catch {
    // Non-critical: cache write failure
  }
}
