import { resilientFetch, OfflineError } from "./http";

const EPSS_API = "https://api.first.org/data/v1/epss";
const BATCH_SIZE = 30;

export interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
}

export async function fetchEpssScores(
  cveIds: string[]
): Promise<Map<string, EpssEntry>> {
  const map = new Map<string, EpssEntry>();
  if (cveIds.length === 0) return map;

  const unique = [...new Set(cveIds)];
  const batches = chunk(unique, BATCH_SIZE);

  for (const batch of batches) {
    try {
      const cveParam = batch.join(",");
      const response = await resilientFetch(
        `${EPSS_API}?cve=${cveParam}`,
        { timeoutMs: 10000, maxRetries: 2 }
      );

      const data = await response.json();

      if (data.data && Array.isArray(data.data)) {
        for (const entry of data.data) {
          map.set(entry.cve, {
            cve: entry.cve,
            epss: parseFloat(entry.epss),
            percentile: parseFloat(entry.percentile),
            date: entry.date,
          });
        }
      }
    } catch (error) {
      if (error instanceof OfflineError) throw error;
      // Non-critical: skip this batch
    }
  }

  return map;
}

function chunk<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
