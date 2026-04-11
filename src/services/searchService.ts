import { loadConfig } from '../config/loader';
import { SearchIndexConfig } from '../config/types';
import logger from './logger';

export type SearchMode = 'regulations' | 'cases';

export interface SearchOptions {
  query: string;
  mode: SearchMode;
  top?: number;
  skip?: number;
}

export interface SearchDocument {
  [key: string]: unknown;
}

export interface SearchResultCaption {
  text: string;
  highlights?: string;
}

export interface SearchResultItem {
  score: number | null;
  captions?: SearchResultCaption[];
  document: SearchDocument;
}

export interface SearchResult {
  mode: SearchMode;
  query: string;
  count: number | null;
  results: SearchResultItem[];
}

function isVerbose(): boolean {
  const { mode } = loadConfig();
  return mode === 'dev' || mode === 'stage';
}

function getIndexConfig(mode: SearchMode): SearchIndexConfig | null {
  const { search } = loadConfig();
  return (search[mode] as SearchIndexConfig | undefined) ?? null;
}

function buildSearchUrl(indexConfig: SearchIndexConfig): string {
  const { search } = loadConfig();
  return (
    `https://${indexConfig.service}.${search.dnsSuffix}` +
    `/indexes/${indexConfig.index}/docs/search` +
    `?api-version=${search.apiVersion}`
  );
}

/**
 * Performs a search against the Azure AI Search index for the given mode.
 * Uses semantic search when a semanticConfig is configured, otherwise simple search.
 */
export async function search(options: SearchOptions): Promise<SearchResult> {
  const { query, mode, top = 10, skip = 0 } = options;

  const indexConfig = getIndexConfig(mode);
  if (!indexConfig) {
    throw new Error(`Search mode "${mode}" is not configured in config.yaml`);
  }

  const url = buildSearchUrl(indexConfig);

  const usesSemantic = Boolean(indexConfig.semanticConfig);
  const requestBody: Record<string, unknown> = {
    search: query,
    queryType: usesSemantic ? 'semantic' : 'simple',
    top,
    skip,
    count: true,
  };

  if (usesSemantic && indexConfig.semanticConfig) {
    requestBody.semanticConfiguration = indexConfig.semanticConfig;
    requestBody.answers = 'extractive|count-3';
    requestBody.captions = 'extractive|highlight-true';
  }

  if (isVerbose()) {
    logger.debug('→ Azure AI Search request', {
      mode,
      url,
      index: indexConfig.index,
      queryType: requestBody.queryType,
      query,
      top,
      skip,
    });
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': indexConfig.key,
      },
      body: JSON.stringify(requestBody),
    });
  } catch (networkErr) {
    const message = networkErr instanceof Error ? networkErr.message : String(networkErr);
    logger.error('✖ Azure AI Search network error', { mode, error: message });
    throw new Error(`Azure AI Search network error: ${message}`);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    logger.error('✖ Azure AI Search — failed to parse response JSON', {
      mode,
      status: response.status,
    });
    throw new Error(`Azure AI Search returned non-JSON response (HTTP ${response.status})`);
  }

  if (!response.ok) {
    const errorObj = body as Record<string, unknown>;
    const errorMessage =
      (errorObj?.error as Record<string, unknown>)?.message ??
      JSON.stringify(errorObj) ??
      `HTTP ${response.status}`;

    logger.error('✖ Azure AI Search error response', {
      mode,
      status: response.status,
      index: indexConfig.index,
      azureResponseBody: body,
    });

    throw new Error(`Azure AI Search error (${response.status}): ${errorMessage}`);
  }

  const data = body as {
    '@odata.count'?: number;
    value?: Array<{
      '@search.score'?: number;
      '@search.captions'?: Array<{ text?: string; highlights?: string }>;
      [key: string]: unknown;
    }>;
  };

  const results: SearchResultItem[] = (data.value ?? []).map((item) => {
    const { '@search.score': score, '@search.captions': rawCaptions, ...document } = item;

    let captions: SearchResultCaption[] | undefined;
    if (Array.isArray(rawCaptions) && rawCaptions.length > 0) {
      captions = rawCaptions.map((c) => ({
        text: typeof c.text === 'string' ? c.text : '',
        highlights: typeof c.highlights === 'string' ? c.highlights : undefined,
      })).filter((c) => c.text.length > 0);
      if (captions.length === 0) captions = undefined;
    }

    return { score: score ?? null, captions, document };
  });

  const result: SearchResult = {
    mode,
    query,
    count: data['@odata.count'] ?? null,
    results,
  };

  if (isVerbose()) {
    logger.debug('← Azure AI Search response', {
      mode,
      index: indexConfig.index,
      count: result.count,
      returnedResults: results.length,
    });
  }

  return result;
}
