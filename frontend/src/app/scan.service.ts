import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Status = 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_APPLICABLE';

export interface CheckResult {
  rule_id: string;
  title: string;
  resource_id: string;
  resource_type: string;
  status: Status;
  severity: Severity;
  reason: string;
  evidence: unknown;
  impact: string;
  recommendation: string;
  reference: string;
  depends_on_parameter_defaults: string[];
}

export interface Summary {
  resources_analyzed: number;
  resources_unsupported: number;
  total_checks: number;
  passed: number;
  failed: number;
  unknown: number;
  not_applicable: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface UnsupportedResource {
  logical_id: string;
  type: string;
  reason?: string;
}

export interface ScanResult {
  summary: Summary;
  results: CheckResult[];
  unsupported: UnsupportedResource[];
  warnings: string[];
}

export interface SampleInfo {
  id: string;
  label: string;
  description: string;
}

export interface SampleTemplate {
  id: string;
  label: string;
  template: unknown;
}

export interface CompareItem {
  rule_id: string;
  title: string;
  resource_id: string;
  severity: Severity;
  before_status: Status | null;
  after_status: Status | null;
  note?: string;
}

export interface CompareResult {
  before: Summary;
  after: Summary;
  resolved: CompareItem[];
  new: CompareItem[];
  unchanged: CompareItem[];
  not_reevaluated: CompareItem[];
  counts: { resolved: number; new: number; unchanged: number; not_reevaluated: number };
}

export interface RuleInfo {
  id: string;
  title: string;
  severity: Severity;
  applies_to: string;
  impact: string;
  recommendation: string;
  reference: string;
}

@Injectable({ providedIn: 'root' })
export class ScanService {
  private http = inject(HttpClient);

  // عنوان الـ Backend المنشور (من Render). بعد ما تنشره، غيّر السطر ده بالعنوان الحقيقي بتاعك.
  private readonly deployedApi = 'https://cloudsentinel-api.onrender.com';

  // على جهازك بيكلم الـ Backend المحلي، ولما الموقع يتنشر بيكلم الـ Backend المنشور
  readonly baseUrl =
    location.hostname === 'localhost' || location.hostname === '127.0.0.1'
      ? 'http://localhost:8000'
      : this.deployedApi;

  samples() {
    return this.http.get<SampleInfo[]>(`${this.baseUrl}/api/cfn/samples`);
  }

  sample(id: string) {
    return this.http.get<SampleTemplate>(`${this.baseUrl}/api/cfn/samples/${id}`);
  }

  scanSample(id: string) {
    return this.http.post<ScanResult>(`${this.baseUrl}/api/cfn/scan/sample/${id}`, {});
  }

  scanTemplate(template: unknown) {
    return this.http.post<ScanResult>(`${this.baseUrl}/api/cfn/scan`, { template });
  }

  compare(before: unknown, after: unknown) {
    return this.http.post<CompareResult>(`${this.baseUrl}/api/cfn/compare`, { before, after });
  }

  rules() {
    return this.http.get<RuleInfo[]>(`${this.baseUrl}/api/cfn/rules`);
  }
}
