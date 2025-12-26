#!/usr/bin/env python3
# =============================================================
# CCNS Project - Network Hijack Detection Dashboard (Debug Edition)
# Tests Spoofing Intensity with only last 50 alerts
# =============================================================

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px
import os, shutil, platform
from datetime import datetime

# -------- Detect OS & set correct paths --------
if platform.system() == "Windows":
    BASE = r"C:\sf_shared"
else:
    BASE = "/media/sf_sf_shared"

ALERT_FILE = os.path.join(BASE, "alerts.csv")
PROTO_FILE = os.path.join(BASE, "protocol_summary.csv")
HTTP_FILE  = os.path.join(BASE, "http_metadata.csv")
SYN_FILE   = os.path.join(BASE, "syn_activity.csv")

# -------- Initialize Dash App --------
app = dash.Dash(__name__)
app.title = "CCNS Network Hijack Detection Dashboard"

APP_STYLE = {
    'fontFamily': 'Segoe UI, Roboto, sans-serif',
    'backgroundColor': '#f4f6f9',
    'color': '#000',
    'padding': '10px',
    'minHeight': '100vh'
}

CARD_STYLE = {
    'backgroundColor': '#ffffff',
    'borderRadius': '10px',
    'boxShadow': '0 2px 8px rgba(0,0,0,0.1)',
    'padding': '15px',
    'marginBottom': '15px',
    'border': '1px solid #ddd'
}

HEADER_STYLE = {
    'textAlign': 'center',
    'background': 'linear-gradient(90deg, #0052cc, #1e90ff)',
    'color': 'white',
    'padding': '15px',
    'borderRadius': '10px',
    'marginBottom': '25px',
    'boxShadow': '0 3px 8px rgba(0,0,0,0.2)'
}

# --- Globals for caching ---
_last_figs = {'proto': None, 'time': None}
_last_mtimes = {'alerts': None, 'proto': None}

# =============================================================
# Helper functions
# =============================================================
def safe_read_csv(src_path):
    if not os.path.exists(src_path):
        return pd.DataFrame()
    try:
        temp_path = src_path + ".tmp"
        shutil.copyfile(src_path, temp_path)
        df = pd.read_csv(temp_path, low_memory=False)
        os.remove(temp_path)
        return df
    except Exception:
        return pd.DataFrame()

def file_mtime(path):
    try:
        return os.path.getmtime(path)
    except Exception:
        return None

def load_alerts():
    df = safe_read_csv(ALERT_FILE)
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["timestamp", "type", "ip_or_domain", "details"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values("timestamp").reset_index(drop=True)

def load_proto():
    df = safe_read_csv(PROTO_FILE)
    if df.empty or "protocol" not in df.columns:
        return pd.DataFrame({"protocol": [], "count": []})
    df["count"] = pd.to_numeric(df["count"], errors="coerce").fillna(0).astype(int)
    return df

# =============================================================
# Layout
# =============================================================
app.layout = html.Div([
    html.Div([
        html.H2("⚡ CCNS Project: Network Hijack Detection Dashboard"),
        html.H5("Debug Edition: Spoofing Intensity = Last 50 Alerts")
    ], style=HEADER_STYLE),

    html.Div([
        html.Div([
            html.H4("🛑 Recent Alerts"),
            dash_table.DataTable(id='alerts', page_size=8)
        ], style={**CARD_STYLE, 'width': '49%'}),
        html.Div([
            html.H4("📊 Protocol Distribution"),
            dcc.Graph(id='proto', config={'displayModeBar': False}, style={'height': '420px'})
        ], style={**CARD_STYLE, 'width': '49%'})
    ], style={'display': 'flex', 'gap': '1%'}),

    html.Div([
        html.Div([
            html.H4("📈 Spoofing Intensity (Last 50 alerts only)"),
            dcc.Graph(id='timeline', config={'displayModeBar': False}, style={'height': '420px'})
        ], style={**CARD_STYLE, 'width': '100%'})
    ]),

    dcc.Interval(id='tick', interval=5000, n_intervals=0)
], style=APP_STYLE)

# =============================================================
# Callback
# =============================================================
@app.callback(
    Output('alerts', 'data'),
    Output('proto', 'figure'),
    Output('timeline', 'figure'),
    Input('tick', 'n_intervals')
)
def refresh(n):
    alerts = load_alerts()
    proto = load_proto()
    mt_alerts = file_mtime(ALERT_FILE)
    mt_proto = file_mtime(PROTO_FILE)

    # --- Protocol Graph ---
    if mt_proto != _last_mtimes.get('proto'):
        fig_proto = px.bar(proto, x='protocol', y='count', text='count',
                           color='protocol', color_discrete_sequence=px.colors.qualitative.Safe)
        fig_proto.update_layout(height=400, yaxis=dict(fixedrange=True))
        _last_figs['proto'] = fig_proto
        _last_mtimes['proto'] = mt_proto
    else:
        fig_proto = _last_figs.get('proto') or px.bar(title="No Protocol Data")

    # --- Spoofing Intensity (Last 50 alerts only) ---
    fig_time = px.line(title="No alerts yet")
    if not alerts.empty:
        recent = alerts.tail(50).copy()
        recent["timestamp"] = pd.to_datetime(recent["timestamp"], errors="coerce")
        timeline = recent.groupby(recent["timestamp"].dt.floor('min')).size().reset_index(name="count")
        fig_time = px.line(timeline, x="timestamp", y="count", markers=True,
                           color_discrete_sequence=['#0288d1'])
        fig_time.update_layout(height=420, yaxis=dict(fixedrange=True), transition={'duration': 0})
        if n % 10 == 0:
            print(f"[DEBUG] Spoofing Intensity now plotting {len(timeline)} points (last 50 alerts)")

    return alerts.tail(25).to_dict('records'), fig_proto, fig_time

# =============================================================
# Run
# =============================================================
if __name__ == "__main__":
    print("🚀 Running debug dashboard on http://127.0.0.1:8050")
    app.run(debug=False, port=8050, use_reloader=False)
