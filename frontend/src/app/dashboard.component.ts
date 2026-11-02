import { HttpErrorResponse } from '@angular/common/http';
import { Component, ViewEncapsulation, computed, inject, signal } from '@angular/core';
import { Observable, forkJoin, map, of, switchMap } from 'rxjs';
import {
  CheckResult,
  CompareItem,
  CompareResult,
  RuleInfo,
  SampleInfo,
  ScanResult,
  ScanService,
  Severity,
  Status,
  Summary,
} from './scan.service';

type Tab = 'scan' | 'compare' | 'rules';
type StatusFilter = Status | 'ALL';

interface CompareRow {
  label: string;
  key: keyof Summary;
  lowerIsBetter: boolean;
}

const MAX_UPLOAD_BYTES = 1_000_000; // 1MB كفاية لـ template
const UPLOADED = '__uploaded__';

@Component({
  selector: 'app-root',
  standalone: true,
  encapsulation: ViewEncapsulation.None,
  template: `
    <div class="cs-bg"></div>
    <main class="cs-wrap">
      <header class="cs-hero">
        <div class="cs-badge"><span class="cs-dot"></span> CLOUDSENTINEL AI</div>
        <h1>Intelligent Cloud Security Analysis</h1>
        <p>
          Scan AWS CloudFormation templates, identify misconfigurations, see exactly why each check
          passed, failed or could not be evaluated, and verify your fixes.
        </p>
      </header>

      <nav class="cs-tabs">
        <button [class.active]="tab() === 'scan'" (click)="tab.set('scan')">Scan</button>
        <button [class.active]="tab() === 'compare'" (click)="tab.set('compare')">Before / After</button>
        <button [class.active]="tab() === 'rules'" (click)="openRules()">Rules</button>
      </nav>

      @if (error()) {
        <div class="cs-error" role="alert">{{ error() }}</div>
      }

      @if (!error() && samples().length === 0) {
        <div class="cs-loading">
          <div class="cs-scanline"></div>
          Connecting to the server… The free server sleeps when idle, so the first request can take up to a minute.
        </div>
      }

      <!-- ============================== SCAN ============================== -->
      @if (tab() === 'scan') {
        <section class="cs-panel">
          <div class="cs-panel-head">
            <h2>1 · Choose what to scan</h2>
            <span class="cs-note">Sample data is fictional. Do not upload real credentials.</span>
          </div>

          <div class="cs-samples">
            @for (s of samples(); track s.id) {
              <button class="cs-sample" [class.active]="selectedId() === s.id" [disabled]="loading()" (click)="runSample(s)">
                <strong>{{ s.label }}</strong>
                <span>{{ s.description }}</span>
              </button>
            }
            <label class="cs-sample cs-upload" [class.disabled]="loading()">
              <strong>Upload CloudFormation template</strong>
              <span>A JSON template (max 1MB). YAML is not supported yet.</span>
              <input type="file" accept=".json,application/json" (change)="onFile($event)" [disabled]="loading()" />
            </label>
          </div>
        </section>

        @if (loading()) {
          <div class="cs-loading"><div class="cs-scanline"></div>Scanning template…</div>
        }

        @if (result(); as r) {
          <section class="cs-panel cs-fade">
            <div class="cs-panel-head">
              <h2>2 · Results</h2>
              <span class="cs-note">Source: {{ sourceLabel() }}</span>
            </div>

            <div class="cs-summary">
              <div class="cs-score">
                <svg viewBox="0 0 120 120" width="150" height="150" aria-label="Share of evaluated checks that passed">
                  <circle cx="60" cy="60" r="52" class="ring-bg"></circle>
                  <circle
                    cx="60" cy="60" r="52" class="ring-fg"
                    [style.stroke]="scoreColor()"
                    [attr.stroke-dasharray]="circumference"
                    [attr.stroke-dashoffset]="dashOffset()"
                    transform="rotate(-90 60 60)"
                  ></circle>
                </svg>
                <div class="cs-score-text">
                  <b>{{ score() }}%</b>
                  <span>of evaluated checks passed</span>
                </div>
              </div>

              <div class="cs-cards">
                <div class="cs-card"><span>Total checks</span><b>{{ r.summary.total_checks }}</b></div>
                <div class="cs-card ok"><span>Passed</span><b>{{ r.summary.passed }}</b></div>
                <div class="cs-card bad"><span>Failed</span><b>{{ r.summary.failed }}</b></div>
                <div class="cs-card unk"><span>Unknown</span><b>{{ r.summary.unknown }}</b></div>
                <div class="cs-card na"><span>Not applicable</span><b>{{ r.summary.not_applicable }}</b></div>
              </div>
            </div>

            <div class="cs-cards cs-sevrow">
              <div class="cs-card sev-critical"><span>Critical</span><b>{{ r.summary.critical }}</b></div>
              <div class="cs-card sev-high"><span>High</span><b>{{ r.summary.high }}</b></div>
              <div class="cs-card sev-medium"><span>Medium</span><b>{{ r.summary.medium }}</b></div>
              <div class="cs-card sev-low"><span>Low</span><b>{{ r.summary.low }}</b></div>
            </div>

            <p class="cs-legend">
              {{ r.summary.resources_analyzed }} resource(s) analyzed
              @if (r.summary.resources_unsupported > 0) {
                · {{ r.summary.resources_unsupported }} not analyzed (unsupported type)
              }
              · Severity counts include failed checks only. <b>Unknown</b> means the template does not contain
              enough information to decide (for example a <code>Ref</code> or <code>Fn::If</code> value), so
              it is never counted as passed.
            </p>
            @for (w of r.warnings; track w) {
              <p class="cs-warn">⚠ {{ w }}</p>
            }
          </section>

          <section class="cs-panel cs-fade">
            <div class="cs-panel-head"><h2>3 · Checks</h2></div>

            <div class="cs-filters">
              @for (f of filters; track f) {
                <button class="cs-chip" [class.active]="statusFilter() === f" (click)="statusFilter.set(f)">
                  {{ filterLabel(f) }} <em>{{ countOf(f) }}</em>
                </button>
              }
            </div>

            @if (visible().length === 0) {
              <div class="cs-clean">No checks with this status.</div>
            } @else {
              <ul class="cs-findings">
                @for (x of visible(); track keyOf(x)) {
                  <li class="cs-finding" [class.open]="isOpen(x)">
                    <button class="cs-finding-head" (click)="toggle(x)" [attr.aria-expanded]="isOpen(x)">
                      <span [class]="statusClass(x.status)">{{ statusLabel(x.status) }}</span>
                      @if (x.status === 'FAIL') {
                        <span [class]="sevClass(x.severity)">{{ x.severity }}</span>
                      }
                      <span class="cs-title">{{ x.title }}<small>{{ x.resource_id }}</small></span>
                      <span class="cs-rule">{{ x.rule_id }}</span>
                      <span class="cs-chevron">▾</span>
                    </button>

                    @if (isOpen(x)) {
                      <div class="cs-finding-body">
                        <div class="cs-grid">
                          <div>
                            <h4>Why this result</h4>
                            <p>{{ x.reason }}</p>
                          </div>
                          @if (x.status === 'FAIL') {
                            <div>
                              <h4>Potential impact</h4>
                              <p>{{ x.impact }}</p>
                            </div>
                            <div>
                              <h4>How to fix it</h4>
                              <p>{{ x.recommendation }}</p>
                            </div>
                          }
                          @if (x.status === 'UNKNOWN') {
                            <div>
                              <h4>How to resolve</h4>
                              <p>Provide the concrete value (for example replace the parameter or condition with the value you deploy) and scan again.</p>
                            </div>
                          }
                          <div>
                            <h4>Resource</h4>
                            <p><code>{{ x.resource_id }}</code> · {{ x.resource_type }}</p>
                            @if (hasEvidence(x)) {
                              <pre>{{ pretty(x.evidence) }}</pre>
                            }
                          </div>
                        </div>
                        @if (x.depends_on_parameter_defaults.length > 0) {
                          <p class="cs-warn">
                            ⚠ This resource uses the default value of parameter(s)
                            <code>{{ x.depends_on_parameter_defaults.join(', ') }}</code>.
                            The value used at deploy time may be different.
                          </p>
                        }
                        <div class="cs-ref">Reference: {{ x.reference }}</div>
                      </div>
                    }
                  </li>
                }
              </ul>
            }
          </section>

          @if (r.unsupported.length > 0) {
            <section class="cs-panel cs-fade">
              <div class="cs-panel-head">
                <h2>Not analyzed</h2>
                <span class="cs-note">These resource types have no rules yet, so nothing was checked for them.</span>
              </div>
              <ul class="cs-plain">
                @for (u of r.unsupported; track u.logical_id) {
                  <li><code>{{ u.logical_id }}</code> · {{ u.type }}@if (u.reason) { · {{ u.reason }} }</li>
                }
              </ul>
            </section>
          }
        }
      }

      <!-- ============================ COMPARE ============================= -->
      @if (tab() === 'compare') {
        <section class="cs-panel">
          <div class="cs-panel-head">
            <h2>Compare two scans</h2>
            <span class="cs-note">Pick the template before the fix and the template after it.</span>
          </div>

          <div class="cs-pick">
            <label>
              Before
              <select (change)="beforeSel.set(val($event))">
                <option value="">Select…</option>
                @for (o of options(); track o.id) {
                  <option [value]="o.id" [selected]="beforeSel() === o.id">{{ o.label }}</option>
                }
              </select>
            </label>
            <label>
              After
              <select (change)="afterSel.set(val($event))">
                <option value="">Select…</option>
                @for (o of options(); track o.id) {
                  <option [value]="o.id" [selected]="afterSel() === o.id">{{ o.label }}</option>
                }
              </select>
            </label>
            <button class="cs-btn" [disabled]="!canCompare()" (click)="runCompare()">Compare</button>
          </div>
          <p class="cs-legend">Tip: upload your own template from the Scan tab and it will appear in these lists. Try "Insecure Stack" → "Insecure Stack Fixed".</p>
        </section>

        @if (cmpLoading()) {
          <div class="cs-loading"><div class="cs-scanline"></div>Comparing…</div>
        }

        @if (cmp(); as c) {
          <section class="cs-panel cs-fade">
            <div class="cs-panel-head"><h2>Result</h2></div>

            <div class="cs-cards">
              <div class="cs-card ok"><span>Resolved</span><b>{{ c.counts.resolved }}</b></div>
              <div class="cs-card bad"><span>New findings</span><b>{{ c.counts.new }}</b></div>
              <div class="cs-card sev-high"><span>Unchanged</span><b>{{ c.counts.unchanged }}</b></div>
              <div class="cs-card unk"><span>Not re-evaluated</span><b>{{ c.counts.not_reevaluated }}</b></div>
            </div>

            <table class="cs-table">
              <thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
              <tbody>
                @for (row of rows; track row.key) {
                  <tr>
                    <td>{{ row.label }}</td>
                    <td>{{ c.before[row.key] }}</td>
                    <td>{{ c.after[row.key] }}</td>
                    <td [class]="deltaClass(row, c)">{{ deltaText(row, c) }}</td>
                  </tr>
                }
              </tbody>
            </table>
            <p class="cs-legend">
              Counts alone can mislead if the two templates contain different resources, so the lists below show
              exactly which findings were resolved, are new, stayed, or could not be re-checked.
            </p>
          </section>

          @for (g of groups(c); track g.title) {
            @if (g.items.length > 0) {
              <section class="cs-panel cs-fade">
                <div class="cs-panel-head"><h2>{{ g.title }}</h2><span class="cs-note">{{ g.hint }}</span></div>
                <ul class="cs-findings">
                  @for (i of g.items; track $index) {
                    <li class="cs-finding">
                      <div class="cs-finding-head cs-static">
                        <span [class]="sevClass(i.severity)">{{ i.severity }}</span>
                        <span class="cs-title">{{ i.title }}<small>{{ i.resource_id }}@if (i.note) { · {{ i.note }} }</small></span>
                        <span class="cs-rule">{{ i.rule_id }}</span>
                        <span class="cs-rule">{{ i.before_status ?? '—' }} → {{ i.after_status ?? '—' }}</span>
                      </div>
                    </li>
                  }
                </ul>
              </section>
            }
          }
        }
      }

      <!-- ============================== RULES ============================== -->
      @if (tab() === 'rules') {
        <section class="cs-panel cs-fade">
          <div class="cs-panel-head">
            <h2>Rule catalog</h2>
            <span class="cs-note">What every rule checks and why it matters.</span>
          </div>
          <ul class="cs-findings">
            @for (r of rules(); track r.id) {
              <li class="cs-finding" [class.open]="openRule() === r.id">
                <button class="cs-finding-head" (click)="toggleRule(r.id)" [attr.aria-expanded]="openRule() === r.id">
                  <span [class]="sevClass(r.severity)">{{ r.severity }}</span>
                  <span class="cs-title">{{ r.title }}<small>{{ r.applies_to }}</small></span>
                  <span class="cs-rule">{{ r.id }}</span>
                  <span class="cs-chevron">▾</span>
                </button>
                @if (openRule() === r.id) {
                  <div class="cs-finding-body">
                    <div class="cs-grid">
                      <div><h4>Why it matters</h4><p>{{ r.impact }}</p></div>
                      <div><h4>How to fix it</h4><p>{{ r.recommendation }}</p></div>
                    </div>
                    <div class="cs-ref">Reference: {{ r.reference }}</div>
                  </div>
                }
              </li>
            }
          </ul>
        </section>
      }

      <footer class="cs-foot">CloudSentinel AI · academic project · rules-based detection</footer>
    </main>
  `,
  styles: [
    `
      :root {
        --bg: #070b14;
        --panel: #0d1424;
        --panel-2: #111a2e;
        --line: #1f2b45;
        --text: #e6ecf8;
        --muted: #8b9ab8;
        --accent: #38bdf8;
        --accent-2: #818cf8;
        --critical: #ff4d6d;
        --high: #ff9f43;
        --medium: #ffd166;
        --low: #4cc9f0;
        --ok: #34d399;
        --unknown: #a78bfa;
        --na: #94a3b8;
      }
      * { box-sizing: border-box; }
      html, body { margin: 0; background: var(--bg); color: var(--text); }
      body {
        font-family: Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
        min-height: 100vh;
        -webkit-font-smoothing: antialiased;
      }
      .cs-bg {
        position: fixed; inset: 0; z-index: -1;
        background:
          radial-gradient(900px 500px at 15% -10%, rgba(56, 189, 248, 0.16), transparent 60%),
          radial-gradient(800px 500px at 90% 0%, rgba(129, 140, 248, 0.14), transparent 60%),
          var(--bg);
      }
      .cs-wrap { max-width: 1040px; margin: 0 auto; padding: 40px 20px 60px; }

      .cs-hero { text-align: center; margin-bottom: 26px; }
      .cs-badge {
        display: inline-flex; align-items: center; gap: 8px;
        font-size: 12px; letter-spacing: 0.18em; color: var(--accent);
        border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 999px;
        padding: 6px 14px; background: rgba(56, 189, 248, 0.07);
      }
      .cs-dot {
        width: 8px; height: 8px; border-radius: 50%; background: var(--ok);
        box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.7); animation: pulse 2s infinite;
      }
      .cs-hero h1 {
        margin: 18px 0 10px; font-size: clamp(28px, 5vw, 46px); line-height: 1.1;
        background: linear-gradient(90deg, #fff, var(--accent) 60%, var(--accent-2));
        -webkit-background-clip: text; background-clip: text; color: transparent;
      }
      .cs-hero p { margin: 0 auto; max-width: 620px; color: var(--muted); line-height: 1.6; }

      .cs-tabs { display: flex; justify-content: center; gap: 8px; margin-bottom: 22px; flex-wrap: wrap; }
      .cs-tabs button {
        font: inherit; font-size: 14px; color: var(--muted); cursor: pointer;
        background: transparent; border: 1px solid var(--line); border-radius: 999px; padding: 8px 18px;
      }
      .cs-tabs button.active { color: var(--text); border-color: var(--accent); background: rgba(56, 189, 248, 0.1); }

      .cs-panel {
        background: linear-gradient(180deg, var(--panel-2), var(--panel));
        border: 1px solid var(--line); border-radius: 18px;
        padding: 22px; margin-bottom: 22px;
        box-shadow: 0 20px 50px -25px rgba(0, 0, 0, 0.7);
      }
      .cs-panel-head { display: flex; flex-wrap: wrap; gap: 8px; justify-content: space-between; align-items: baseline; margin-bottom: 16px; }
      .cs-panel-head h2 { margin: 0; font-size: 17px; }
      .cs-note { font-size: 12px; color: var(--muted); }

      .cs-samples { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }
      .cs-sample {
        text-align: left; font: inherit; color: inherit; cursor: pointer;
        background: rgba(255, 255, 255, 0.02); border: 1px solid var(--line);
        border-radius: 14px; padding: 14px 16px; display: flex; flex-direction: column; gap: 6px;
        transition: transform 0.15s, border-color 0.15s, background 0.15s;
      }
      .cs-sample span { font-size: 13px; color: var(--muted); line-height: 1.45; }
      .cs-sample:hover:not(:disabled) { transform: translateY(-2px); border-color: var(--accent); background: rgba(56, 189, 248, 0.06); }
      .cs-sample.active { border-color: var(--accent); background: rgba(56, 189, 248, 0.1); }
      .cs-sample:disabled, .cs-sample.disabled { opacity: 0.5; cursor: not-allowed; }
      .cs-upload { border-style: dashed; }
      .cs-upload input { margin-top: 6px; font-size: 12px; color: var(--muted); max-width: 100%; }

      .cs-error {
        margin: 0 0 18px; padding: 12px 14px; border-radius: 12px; font-size: 14px;
        background: rgba(255, 77, 109, 0.1); border: 1px solid rgba(255, 77, 109, 0.4); color: #ffb3c0;
      }

      .cs-loading { position: relative; overflow: hidden; text-align: center; color: var(--muted); padding: 28px; margin-bottom: 22px; border: 1px dashed var(--line); border-radius: 18px; }
      .cs-scanline { position: absolute; left: 0; right: 0; height: 2px; top: 0; background: linear-gradient(90deg, transparent, var(--accent), transparent); animation: scan 1.2s linear infinite; }

      .cs-summary { display: flex; flex-wrap: wrap; gap: 28px; align-items: center; justify-content: center; }
      .cs-score { position: relative; width: 150px; height: 150px; }
      .ring-bg { fill: none; stroke: rgba(255, 255, 255, 0.07); stroke-width: 10; }
      .ring-fg { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset 0.9s ease, stroke 0.4s; }
      .cs-score-text { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 0 22px; }
      .cs-score-text b { font-size: 30px; }
      .cs-score-text span { font-size: 10px; color: var(--muted); line-height: 1.3; }

      .cs-cards { flex: 1; min-width: 260px; display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; }
      .cs-sevrow { margin-top: 14px; }
      .cs-card { background: rgba(255, 255, 255, 0.03); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; }
      .cs-card span { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
      .cs-card b { font-size: 26px; }
      .cs-card.ok b { color: var(--ok); }
      .cs-card.bad b { color: var(--critical); }
      .cs-card.unk b { color: var(--unknown); }
      .cs-card.na b { color: var(--na); }
      .cs-card.sev-critical b { color: var(--critical); }
      .cs-card.sev-high b { color: var(--high); }
      .cs-card.sev-medium b { color: var(--medium); }
      .cs-card.sev-low b { color: var(--low); }

      .cs-legend { margin: 16px 0 0; font-size: 12.5px; color: var(--muted); line-height: 1.65; }
      .cs-legend code, .cs-plain code, .cs-grid code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #9fe3ff; }

      .cs-clean { padding: 18px; border-radius: 14px; background: rgba(255, 255, 255, 0.03); border: 1px dashed var(--line); color: var(--muted); }

      .cs-filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
      .cs-chip { font: inherit; font-size: 13px; color: var(--muted); cursor: pointer; background: transparent; border: 1px solid var(--line); border-radius: 999px; padding: 6px 12px; }
      .cs-chip em { font-style: normal; margin-left: 6px; color: var(--text); }
      .cs-chip.active { color: var(--text); border-color: var(--accent); background: rgba(56, 189, 248, 0.1); }

      .cs-findings { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
      .cs-finding { border: 1px solid var(--line); border-radius: 14px; background: rgba(255, 255, 255, 0.02); overflow: hidden; transition: border-color 0.15s; }
      .cs-finding.open { border-color: rgba(56, 189, 248, 0.5); }
      .cs-finding-head { width: 100%; display: flex; align-items: center; gap: 12px; padding: 14px 16px; background: none; border: 0; color: inherit; font: inherit; cursor: pointer; text-align: left; }
      .cs-finding-head.cs-static { cursor: default; flex-wrap: wrap; }
      .cs-title { flex: 1; font-weight: 600; min-width: 160px; }
      .cs-title small { display: block; font-weight: 400; font-size: 12px; color: var(--muted); margin-top: 2px; }
      .cs-rule { font-size: 12px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      .cs-chevron { color: var(--muted); transition: transform 0.2s; }
      .cs-finding.open .cs-chevron { transform: rotate(180deg); }

      .cs-sev, .cs-st { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; padding: 4px 9px; border-radius: 8px; min-width: 76px; text-align: center; }
      .cs-sev.sev-critical { background: rgba(255, 77, 109, 0.15); color: var(--critical); border: 1px solid rgba(255, 77, 109, 0.5); }
      .cs-sev.sev-high { background: rgba(255, 159, 67, 0.15); color: var(--high); border: 1px solid rgba(255, 159, 67, 0.5); }
      .cs-sev.sev-medium { background: rgba(255, 209, 102, 0.13); color: var(--medium); border: 1px solid rgba(255, 209, 102, 0.45); }
      .cs-sev.sev-low { background: rgba(76, 201, 240, 0.13); color: var(--low); border: 1px solid rgba(76, 201, 240, 0.45); }
      .cs-st.st-fail { background: rgba(255, 77, 109, 0.15); color: var(--critical); }
      .cs-st.st-pass { background: rgba(52, 211, 153, 0.15); color: var(--ok); }
      .cs-st.st-unknown { background: rgba(167, 139, 250, 0.16); color: var(--unknown); }
      .cs-st.st-not_applicable { background: rgba(148, 163, 184, 0.15); color: var(--na); }

      .cs-finding-body { padding: 4px 18px 18px; border-top: 1px solid var(--line); animation: fadeUp 0.25s ease; }
      .cs-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; padding-top: 14px; }
      .cs-grid h4 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--accent); }
      .cs-grid p { margin: 0; line-height: 1.6; color: #cdd7ec; font-size: 14px; }
      .cs-grid pre { margin: 10px 0 0; padding: 10px 12px; border-radius: 10px; background: #060a13; border: 1px solid var(--line); overflow: auto; color: #9fe3ff; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
      .cs-ref { margin-top: 16px; font-size: 12px; color: var(--muted); }

      .cs-warn { margin: 12px 0 0; padding: 9px 12px; border-radius: 10px; font-size: 12.5px; line-height: 1.55; color: #ffe2a8; background: rgba(255, 209, 102, 0.08); border: 1px solid rgba(255, 209, 102, 0.35); }
      .cs-plain { margin: 0; padding-left: 18px; color: #cdd7ec; line-height: 1.9; font-size: 14px; }

      .cs-pick { display: flex; flex-wrap: wrap; gap: 14px; align-items: flex-end; }
      .cs-pick label { display: flex; flex-direction: column; gap: 6px; font-size: 12px; color: var(--muted); flex: 1; min-width: 200px; }
      .cs-pick select { font: inherit; font-size: 14px; color: var(--text); background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; }
      .cs-btn { font: inherit; font-weight: 600; cursor: pointer; color: #06101e; background: linear-gradient(90deg, var(--accent), var(--accent-2)); border: 0; border-radius: 10px; padding: 11px 22px; }
      .cs-btn:disabled { opacity: 0.4; cursor: not-allowed; }

      .cs-table { width: 100%; border-collapse: collapse; margin-top: 18px; font-size: 14px; }
      .cs-table th, .cs-table td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); }
      .cs-table th { font-size: 12px; color: var(--muted); font-weight: 600; }
      .cs-table td.good { color: var(--ok); }
      .cs-table td.bad { color: var(--critical); }

      .cs-fade { animation: fadeUp 0.4s ease; }
      .cs-foot { text-align: center; color: var(--muted); font-size: 12px; margin-top: 30px; }

      @keyframes fadeUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
      @keyframes pulse { 70% { box-shadow: 0 0 0 8px rgba(52, 211, 153, 0); } 100% { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); } }
      @keyframes scan { from { top: 0; } to { top: 100%; } }

      @media (prefers-reduced-motion: reduce) {
        * { animation: none !important; transition: none !important; }
      }
    `,
  ],
})
export class DashboardComponent {
  private api = inject(ScanService);

  readonly circumference = 2 * Math.PI * 52;
  readonly filters: StatusFilter[] = ['FAIL', 'UNKNOWN', 'PASS', 'NOT_APPLICABLE', 'ALL'];
  readonly rows: CompareRow[] = [
    { label: 'Failed checks', key: 'failed', lowerIsBetter: true },
    { label: 'Unknown checks', key: 'unknown', lowerIsBetter: true },
    { label: 'Passed checks', key: 'passed', lowerIsBetter: false },
    { label: 'Critical', key: 'critical', lowerIsBetter: true },
    { label: 'High', key: 'high', lowerIsBetter: true },
    { label: 'Medium', key: 'medium', lowerIsBetter: true },
    { label: 'Low', key: 'low', lowerIsBetter: true },
  ];

  tab = signal<Tab>('scan');
  samples = signal<SampleInfo[]>([]);
  selectedId = signal<string | null>(null);
  result = signal<ScanResult | null>(null);
  loading = signal(false);
  error = signal<string | null>(null);
  sourceLabel = signal('');
  statusFilter = signal<StatusFilter>('FAIL');
  private openKeys = signal<Set<string>>(new Set());

  uploaded = signal<{ name: string; template: unknown } | null>(null);
  beforeSel = signal('');
  afterSel = signal('');
  cmp = signal<CompareResult | null>(null);
  cmpLoading = signal(false);

  rules = signal<RuleInfo[]>([]);
  openRule = signal<string | null>(null);

  score = computed(() => {
    const r = this.result();
    if (!r) return 0;
    const evaluated = r.summary.passed + r.summary.failed + r.summary.unknown;
    return evaluated === 0 ? 0 : Math.round((r.summary.passed / evaluated) * 100);
  });

  dashOffset = computed(() => this.circumference * (1 - this.score() / 100));

  scoreColor = computed(() => {
    const s = this.score();
    if (s >= 85) return '#34d399';
    if (s >= 50) return '#ffd166';
    return '#ff4d6d';
  });

  visible = computed(() => {
    const r = this.result();
    if (!r) return [];
    const f = this.statusFilter();
    return f === 'ALL' ? r.results : r.results.filter((x) => x.status === f);
  });

  options = computed(() => {
    const list = this.samples().map((s) => ({ id: s.id, label: s.label }));
    const up = this.uploaded();
    if (up) list.push({ id: UPLOADED, label: `Uploaded · ${up.name}` });
    return list;
  });

  canCompare = computed(() => !!this.beforeSel() && !!this.afterSel() && !this.cmpLoading());

  constructor() {
    this.api.samples().subscribe({
      next: (list) => this.samples.set(list),
      error: (e) => this.fail(e),
    });
  }

  // ------------------------------------------------------------- scan

  runSample(sample: SampleInfo) {
    this.selectedId.set(sample.id);
    this.begin(`Sample · ${sample.label}`);
    this.api.scanSample(sample.id).subscribe({
      next: (r) => this.show(r),
      error: (e) => this.fail(e),
    });
  }

  async onFile(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = ''; // عشان نقدر نرفع نفس الملف تاني
    if (!file) return;

    if (file.size > MAX_UPLOAD_BYTES) {
      this.error.set('File is too large. Maximum size is 1MB.');
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      this.error.set('This file is not valid JSON. (YAML templates are not supported yet.)');
      return;
    }

    const obj = parsed as Record<string, unknown> | null;
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj) || !('Resources' in obj)) {
      this.error.set("This does not look like a CloudFormation template (it has no 'Resources' section).");
      return;
    }

    this.uploaded.set({ name: file.name, template: parsed });
    this.selectedId.set(null);
    this.begin(`Uploaded file · ${file.name}`);
    this.api.scanTemplate(parsed).subscribe({
      next: (r) => this.show(r),
      error: (e) => this.fail(e),
    });
  }

  countOf(f: StatusFilter): number {
    const r = this.result();
    if (!r) return 0;
    return f === 'ALL' ? r.results.length : r.results.filter((x) => x.status === f).length;
  }

  keyOf(x: CheckResult): string {
    return `${x.rule_id}|${x.resource_id}`;
  }

  isOpen(x: CheckResult): boolean {
    return this.openKeys().has(this.keyOf(x));
  }

  toggle(x: CheckResult) {
    const next = new Set(this.openKeys());
    const key = this.keyOf(x);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    this.openKeys.set(next);
  }

  hasEvidence(x: CheckResult): boolean {
    return x.evidence !== null && x.evidence !== undefined;
  }

  pretty(value: unknown): string {
    return JSON.stringify(value, null, 2) ?? '';
  }

  // ---------------------------------------------------------- compare

  val(event: Event): string {
    return (event.target as HTMLSelectElement).value;
  }

  runCompare() {
    const before = this.beforeSel();
    const after = this.afterSel();
    if (!before || !after) return;

    this.error.set(null);
    this.cmp.set(null);
    this.cmpLoading.set(true);

    forkJoin([this.templateFor(before), this.templateFor(after)])
      .pipe(switchMap(([b, a]) => this.api.compare(b, a)))
      .subscribe({
        next: (c) => {
          this.cmp.set(c);
          this.cmpLoading.set(false);
        },
        error: (e) => this.fail(e),
      });
  }

  private templateFor(selection: string): Observable<unknown> {
    if (selection === UPLOADED) return of(this.uploaded()?.template);
    return this.api.sample(selection).pipe(map((s) => s.template));
  }

  groups(c: CompareResult): { title: string; hint: string; items: CompareItem[] }[] {
    return [
      { title: 'Resolved', hint: 'Failed before, passes now.', items: c.resolved },
      { title: 'New findings', hint: 'Failing now, but not failing before.', items: c.new },
      { title: 'Unchanged', hint: 'Still failing in both scans.', items: c.unchanged },
      { title: 'Could not be re-evaluated', hint: 'Failed before; the second scan cannot confirm a fix.', items: c.not_reevaluated },
    ];
  }

  private delta(row: CompareRow, c: CompareResult): number {
    return c.after[row.key] - c.before[row.key];
  }

  deltaText(row: CompareRow, c: CompareResult): string {
    const d = this.delta(row, c);
    return d === 0 ? '—' : d > 0 ? `+${d}` : `${d}`;
  }

  deltaClass(row: CompareRow, c: CompareResult): string {
    const d = this.delta(row, c);
    if (d === 0) return '';
    return row.lowerIsBetter === d < 0 ? 'good' : 'bad';
  }

  // ------------------------------------------------------------ rules

  openRules() {
    this.tab.set('rules');
    if (this.rules().length === 0) {
      this.api.rules().subscribe({
        next: (r) => this.rules.set(r),
        error: (e) => this.fail(e),
      });
    }
  }

  toggleRule(id: string) {
    this.openRule.set(this.openRule() === id ? null : id);
  }

  // ---------------------------------------------------------- helpers

  statusClass(s: Status): string {
    return `cs-st st-${s.toLowerCase()}`;
  }

  sevClass(s: Severity): string {
    return `cs-sev sev-${s.toLowerCase()}`;
  }

  statusLabel(s: Status): string {
    return { PASS: 'PASSED', FAIL: 'FAILED', UNKNOWN: 'UNKNOWN', NOT_APPLICABLE: 'N/A' }[s];
  }

  filterLabel(f: StatusFilter): string {
    return f === 'ALL' ? 'All' : f === 'NOT_APPLICABLE' ? 'N/A' : this.statusLabel(f)[0] + this.statusLabel(f).slice(1).toLowerCase();
  }

  private begin(label: string) {
    this.loading.set(true);
    this.error.set(null);
    this.result.set(null);
    this.openKeys.set(new Set());
    this.sourceLabel.set(label);
  }

  private show(r: ScanResult) {
    this.result.set(r);
    this.loading.set(false);
    this.statusFilter.set(r.summary.failed > 0 ? 'FAIL' : r.summary.unknown > 0 ? 'UNKNOWN' : 'ALL');
  }

  private fail(err: unknown) {
    this.loading.set(false);
    this.cmpLoading.set(false);
    const e = err as HttpErrorResponse;
    if (e?.status === 0) {
      this.error.set(
        `Cannot reach the API at ${this.api.baseUrl}. If this is the deployed site, the server may be waking up: wait a minute and refresh. On your computer, make sure the backend is running (uvicorn main:app --reload).`
      );
    } else if (e?.status === 422 && typeof e.error?.detail === 'string') {
      this.error.set(`Invalid template: ${e.error.detail}`);
    } else {
      this.error.set(`Unexpected error${e?.status ? ` (HTTP ${e.status})` : ''}. Check the backend terminal for details.`);
    }
  }
}
