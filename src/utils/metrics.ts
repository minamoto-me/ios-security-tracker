import { Env } from '../types';
import { Logger } from './logger';

export interface MetricData {
  name: string;
  value: number;
  timestamp: string;
  tags?: Record<string, string>;
}

export class Metrics {
  private cache: KVNamespace;

  constructor(env: Env) {
    this.cache = env.CACHE;
  }

  async recordMetric(name: string, value: number, tags?: Record<string, string>): Promise<void> {
    try {
      const metric: MetricData = {
        name,
        value,
        timestamp: new Date().toISOString(),
        tags,
      };

      const key = `metrics:${name}:${Date.now()}`;
      await this.cache.put(key, JSON.stringify(metric), { expirationTtl: 86400 * 7 }); // 7 days

      Logger.debug(`Recorded metric: ${name} = ${value}`, tags);
    } catch (error) {
      Logger.error('Failed to record metric', error, { name, value, tags });
    }
  }

  async incrementCounter(name: string, tags?: Record<string, string>): Promise<void> {
    await this.recordMetric(name, 1, tags);
  }

  async recordDuration(name: string, startTime: number, tags?: Record<string, string>): Promise<void> {
    const duration = Date.now() - startTime;
    await this.recordMetric(name, duration, tags);
  }

  async recordVulnerabilityScanMetrics(results: {
    vulnerabilities_found: number;
    vulnerabilities_new: number;
    vulnerabilities_updated: number;
    ios_releases_processed: number;
    execution_time_ms: number;
    errors?: string | null;
  }): Promise<void> {

    await Promise.all([
      this.recordMetric('scan.vulnerabilities_found', results.vulnerabilities_found),
      this.recordMetric('scan.vulnerabilities_new', results.vulnerabilities_new),
      this.recordMetric('scan.vulnerabilities_updated', results.vulnerabilities_updated),
      this.recordMetric('scan.ios_releases_processed', results.ios_releases_processed),
      this.recordMetric('scan.execution_time_ms', results.execution_time_ms),
      this.incrementCounter('scan.completed', {
        status: results.errors ? 'partial' : 'success',
      }),
    ]);

    if (results.errors) {
      await this.incrementCounter('scan.errors');
    }

    Logger.info('Vulnerability scan metrics recorded', results);
  }

  async recordApiMetrics(endpoint: string, method: string, statusCode: number, duration: number): Promise<void> {
    const tags = {
      endpoint,
      method,
      status_code: statusCode.toString(),
      status_class: `${Math.floor(statusCode / 100)}xx`,
    };

    await Promise.all([
      this.recordMetric('api.request_duration_ms', duration, tags),
      this.incrementCounter('api.requests', tags),
    ]);

    if (statusCode >= 400) {
      await this.incrementCounter('api.errors', tags);
    }
  }

  async recordNvdApiMetrics(cveId: string, success: boolean, duration: number, cached: boolean): Promise<void> {
    const tags = {
      cve_id: cveId,
      success: success.toString(),
      cached: cached.toString(),
    };

    await Promise.all([
      this.recordMetric('nvd.request_duration_ms', duration, tags),
      this.incrementCounter('nvd.requests', tags),
    ]);

    if (!success) {
      await this.incrementCounter('nvd.errors', { cve_id: cveId });
    }

    if (cached) {
      await this.incrementCounter('nvd.cache_hits', { cve_id: cveId });
    }
  }

  async recordDatabaseMetrics(operation: string, success: boolean, duration: number, recordCount?: number): Promise<void> {
    const tags = {
      operation,
      success: success.toString(),
    };

    await Promise.all([
      this.recordMetric('database.operation_duration_ms', duration, tags),
      this.incrementCounter('database.operations', tags),
    ]);

    if (!success) {
      await this.incrementCounter('database.errors', { operation });
    }

    if (recordCount !== undefined) {
      await this.recordMetric('database.records_processed', recordCount, { operation });
    }
  }

  async getMetricsSummary(hours: number = 24): Promise<Record<string, any>> {
    try {
      // Note: In a production environment, you might want to use
      // a more sophisticated metrics aggregation system
      return {
        period_hours: hours,
        timestamp: new Date().toISOString(),
        note: 'Metrics summary would require additional aggregation logic',
      };
    } catch (error) {
      Logger.error('Failed to get metrics summary', error);
      return {};
    }
  }
}

export class PerformanceTimer {
  private startTime: number;
  private name: string;

  constructor(name: string) {
    this.name = name;
    this.startTime = Date.now();
  }

  stop(): number {
    const duration = Date.now() - this.startTime;
    Logger.performance(this.name, this.startTime);
    return duration;
  }

  async stopAndRecord(metrics: Metrics, tags?: Record<string, string>): Promise<number> {
    const duration = this.stop();
    await metrics.recordMetric(`performance.${this.name}`, duration, tags);
    return duration;
  }
}