import { Env } from '../types';
import { Logger } from './logger';

export interface AlertCondition {
  name: string;
  description: string;
  condition: (data: any) => boolean;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface Alert {
  id: string;
  name: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  triggered_at: string;
  data: any;
  resolved: boolean;
  resolved_at?: string;
}

export class AlertManager {
  private cache: KVNamespace;

  constructor(env: Env) {
    this.cache = env.CACHE;
  }

  private readonly alertConditions: AlertCondition[] = [
    {
      name: 'high_vulnerability_count',
      description: 'High number of new vulnerabilities detected in single scan',
      condition: (data) => data.vulnerabilities_new > 10,
      severity: 'HIGH',
    },
    {
      name: 'critical_vulnerability_detected',
      description: 'Critical severity vulnerability detected',
      condition: (data) => data.severity === 'CRITICAL',
      severity: 'CRITICAL',
    },
    {
      name: 'scan_failure',
      description: 'Vulnerability scan failed completely',
      condition: (data) => data.status === 'FAILED',
      severity: 'HIGH',
    },
    {
      name: 'scan_slow_execution',
      description: 'Vulnerability scan took unusually long to complete',
      condition: (data) => data.execution_time_ms > 300000, // 5 minutes
      severity: 'MEDIUM',
    },
    {
      name: 'api_error_rate_high',
      description: 'High API error rate detected',
      condition: (data) => data.error_rate > 0.1, // 10% error rate
      severity: 'MEDIUM',
    },
    {
      name: 'nvd_api_failures',
      description: 'Multiple NVD API failures detected',
      condition: (data) => data.nvd_failures > 5,
      severity: 'MEDIUM',
    },
  ];

  async checkScanAlerts(scanResults: {
    status: string;
    vulnerabilities_found: number;
    vulnerabilities_new: number;
    execution_time_ms: number;
    errors?: string | null;
  }): Promise<Alert[]> {
    const alerts: Alert[] = [];

    for (const condition of this.alertConditions) {
      if (condition.condition(scanResults)) {
        const alert = await this.triggerAlert(condition, scanResults);
        alerts.push(alert);
      }
    }

    return alerts;
  }

  async checkVulnerabilityAlert(vulnerability: {
    cve_id: string;
    severity: string;
    cvss_score?: number;
  }): Promise<Alert | null> {
    const criticalCondition = this.alertConditions.find(c => c.name === 'critical_vulnerability_detected');
    if (criticalCondition && criticalCondition.condition(vulnerability)) {
      return await this.triggerAlert(criticalCondition, vulnerability);
    }
    return null;
  }

  private async triggerAlert(condition: AlertCondition, data: any): Promise<Alert> {
    const alert: Alert = {
      id: this.generateAlertId(),
      name: condition.name,
      description: condition.description,
      severity: condition.severity,
      triggered_at: new Date().toISOString(),
      data,
      resolved: false,
    };

    try {
      // Store alert in cache
      const alertKey = `alert:${alert.id}`;
      await this.cache.put(alertKey, JSON.stringify(alert), { expirationTtl: 86400 * 30 }); // 30 days

      // Also store in recent alerts list
      await this.addToRecentAlerts(alert);

      Logger.warn(`Alert triggered: ${alert.name}`, {
        alert_id: alert.id,
        severity: alert.severity,
        data: alert.data,
      });

      // In a production environment, you might want to send notifications here
      // await this.sendNotification(alert);

    } catch (error) {
      Logger.error('Failed to store alert', error, { alert });
    }

    return alert;
  }

  private async addToRecentAlerts(alert: Alert): Promise<void> {
    try {
      const recentAlertsKey = 'recent_alerts';
      const existing = await this.cache.get(recentAlertsKey, 'json') as Alert[] || [];

      // Add new alert to the beginning and keep only the most recent 100
      const updated = [alert, ...existing].slice(0, 100);

      await this.cache.put(recentAlertsKey, JSON.stringify(updated), { expirationTtl: 86400 * 7 });
    } catch (error) {
      Logger.error('Failed to update recent alerts', error);
    }
  }

  async getRecentAlerts(limit: number = 20): Promise<Alert[]> {
    try {
      const recentAlertsKey = 'recent_alerts';
      const alerts = await this.cache.get(recentAlertsKey, 'json') as Alert[] || [];
      return alerts.slice(0, limit);
    } catch (error) {
      Logger.error('Failed to get recent alerts', error);
      return [];
    }
  }

  async resolveAlert(alertId: string): Promise<boolean> {
    try {
      const alertKey = `alert:${alertId}`;
      const alertData = await this.cache.get(alertKey, 'json') as Alert;

      if (!alertData) {
        Logger.warn(`Alert ${alertId} not found for resolution`);
        return false;
      }

      alertData.resolved = true;
      alertData.resolved_at = new Date().toISOString();

      await this.cache.put(alertKey, JSON.stringify(alertData), { expirationTtl: 86400 * 30 });

      Logger.info(`Alert resolved: ${alertId}`);
      return true;
    } catch (error) {
      Logger.error('Failed to resolve alert', error, { alertId });
      return false;
    }
  }

  async getAlertSummary(): Promise<{
    total_alerts: number;
    unresolved_alerts: number;
    by_severity: Record<string, number>;
    recent_count: number;
  }> {
    try {
      const recentAlerts = await this.getRecentAlerts(100);

      const summary = {
        total_alerts: recentAlerts.length,
        unresolved_alerts: recentAlerts.filter(a => !a.resolved).length,
        by_severity: {
          CRITICAL: 0,
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
        },
        recent_count: recentAlerts.filter(a => {
          const alertTime = new Date(a.triggered_at);
          const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
          return alertTime > oneDayAgo;
        }).length,
      };

      recentAlerts.forEach(alert => {
        summary.by_severity[alert.severity]++;
      });

      return summary;
    } catch (error) {
      Logger.error('Failed to get alert summary', error);
      return {
        total_alerts: 0,
        unresolved_alerts: 0,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        recent_count: 0,
      };
    }
  }

  private generateAlertId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `alert_${timestamp}_${random}`;
  }

  // Future enhancement: notification methods
  // private async sendNotification(alert: Alert): Promise<void> {
  //   // Implementation for sending notifications (email, webhook, etc.)
  // }
}