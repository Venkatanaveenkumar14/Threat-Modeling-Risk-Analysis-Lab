# shiny-app/app.py
import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from pathlib import Path
import ast
from datetime import datetime
from dash.exceptions import PreventUpdate

# ========== Data Preparation ==========
current_dir = Path(__file__).parent
data_path = current_dir.parent / "data" / "processed_cves.csv"

# Load and enhance data
try:
    df = pd.read_csv(data_path)
    
    # Ensure required columns
    df['cvss_score'] = df.get('cvss_score', np.random.uniform(1, 10, len(df)))
    df['severity'] = pd.cut(df['cvss_score'],
                           bins=[0, 4, 7, 9, 10],
                           labels=['Low', 'Medium', 'High', 'Critical'])
    
    # Convert string lists to actual lists
    def safe_convert(x):
        try:
            return ast.literal_eval(x) if isinstance(x, str) else x
        except:
            return [x] if pd.notna(x) else []
    
    for col in ['mitre_techniques', 'cwes']:
        if col in df.columns:
            df[col] = df[col].apply(safe_convert)
    
    # Add temporal features
    if 'dateAdded' in df.columns:
        df['dateAdded'] = pd.to_datetime(df['dateAdded'])
        df['days_old'] = (datetime.now() - df['dateAdded']).dt.days
        df['year_added'] = df['dateAdded'].dt.year
    
    # Risk scoring
    df['risk_score'] = (
        df['cvss_score'] * 0.6 + 
        df.get('days_old', 0) * 0.01 +
        df['shortDescription'].str.len() * 0.001
    )
    
except Exception as e:
    raise SystemExit(f"Data processing error: {str(e)}")

# ========== Dashboard Layout ==========
app = dash.Dash(__name__, title="Advanced CVE Dashboard", suppress_callback_exceptions=True)

app.layout = html.Div([
    dcc.Store(id='filtered-data'),
    dcc.Tabs([
        # Tab 1: Overview
        dcc.Tab(label='Risk Overview', children=[
            html.Div([
                html.H1("Threat Modeling Dashboard", className="header"),
                
                # Filters Row
                html.Div([
                    html.Div([
                        html.Label("CVSS Score Range:"),
                        dcc.RangeSlider(
                            id='cvss-slider',
                            min=0, max=10, step=0.1,
                            marks={i: {'label': str(i)} for i in range(0, 11)},
                            value=[5, 10],
                            tooltip={"placement": "bottom"}
                        )
                    ], className="filter-box"),
                    
                    html.Div([
                        html.Label("Severity Levels:"),
                        dcc.Dropdown(
                            id='severity-dropdown',
                            options=[{'label': s, 'value': s} for s in df['severity'].unique()],
                            value=df['severity'].unique().tolist(),
                            multi=True
                        )
                    ], className="filter-box"),
                    
                    html.Div([
                        html.Label("Time Period:"),
                        dcc.Dropdown(
                            id='year-dropdown',
                            options=[{'label': y, 'value': y} for y in sorted(df.get('year_added', [datetime.now().year]))],
                            value=[datetime.now().year],
                            multi=True
                        )
                    ], className="filter-box")
                ], className="filters-row"),
                
                # Metrics Row
                html.Div([
                    html.Div([
                        html.Div(id='total-cves', className="metric-value"),
                        html.Div("Total CVEs", className="metric-label")
                    ], className="metric-box"),
                    
                    html.Div([
                        html.Div(id='high-risk', className="metric-value"),
                        html.Div("High+Critical", className="metric-label")
                    ], className="metric-box"),
                    
                    html.Div([
                        html.Div(id='avg-cvss', className="metric-value"),
                        html.Div("Avg CVSS", className="metric-label")
                    ], className="metric-box"),
                    
                    html.Div([
                        html.Div(id='exploitable', className="metric-value"),
                        html.Div("Exploitable", className="metric-label")
                    ], className="metric-box")
                ], className="metrics-row"),
                
                # Main Visualizations
                html.Div([
                    html.Div([
                        dcc.Graph(id='severity-trend', className="graph-box")
                    ], className="col-6"),
                    
                    html.Div([
                        dcc.Graph(id='vendor-risk', className="graph-box")
                    ], className="col-6")
                ], className="row"),
                
                html.Div([
                    html.Div([
                        dcc.Graph(id='technique-cloud', className="graph-box")
                    ], className="col-12")
                ], className="row"),
                
                html.Div([
                    html.Div([
                        dcc.Graph(id='risk-distribution', className="graph-box")
                    ], className="col-6"),
                    
                    html.Div([
                        dcc.Graph(id='cwe-analysis', className="graph-box")
                    ], className="col-6")
                ], className="row")
            ], className="container")
        ]),
        
        # Tab 2: Detailed Analysis
        dcc.Tab(label='Detailed Analysis', children=[
            html.Div([
                html.H2("Vulnerability Details", className="header"),
                dash_table.DataTable(
                    id='cve-table',
                    columns=[{"name": i, "id": i} for i in df.columns if i in [
                        'cveID', 'vendorProject', 'cvss_score', 'severity',
                        'dateAdded', 'shortDescription'
                    ]],
                    page_size=20,
                    filter_action="native",
                    sort_action="native",
                    style_table={'overflowX': 'auto'},
                    style_cell={
                        'textAlign': 'left',
                        'padding': '10px',
                        'whiteSpace': 'normal',
                        'height': 'auto'
                    }
                )
            ], className="container")
        ])
    ])
])

# ========== Callbacks ==========
@app.callback(
    Output('filtered-data', 'data'),
    [Input('cvss-slider', 'value'),
     Input('severity-dropdown', 'value'),
     Input('year-dropdown', 'value')]
)
def update_filtered_data(cvss_range, severities, years):
    filtered = df[
        (df['cvss_score'] >= cvss_range[0]) & 
        (df['cvss_score'] <= cvss_range[1]) &
        (df['severity'].isin(severities))
    ]
    
    if 'year_added' in df.columns:
        filtered = filtered[filtered['year_added'].isin(years)]
    
    return filtered.to_dict('records')

@app.callback(
    [Output('total-cves', 'children'),
     Output('high-risk', 'children'),
     Output('avg-cvss', 'children'),
     Output('exploitable', 'children')],
    [Input('filtered-data', 'data')]
)
def update_metrics(data):
    if not data:
        raise PreventUpdate
        
    filtered = pd.DataFrame(data)
    metrics = [
        len(filtered),
        len(filtered[filtered['severity'].isin(['High', 'Critical'])]),
        f"{filtered['cvss_score'].mean():.1f}",
        len(filtered[filtered['has_exploit']]) if 'has_exploit' in filtered.columns else "N/A"
    ]
    return metrics

@app.callback(
    [Output('severity-trend', 'figure'),
     Output('vendor-risk', 'figure'),
     Output('technique-cloud', 'figure'),
     Output('risk-distribution', 'figure'),
     Output('cwe-analysis', 'figure')],
    [Input('filtered-data', 'data')]
)
def update_visualizations(data):
    if not data:
        raise PreventUpdate
        
    filtered = pd.DataFrame(data)
    
    # 1. Severity Trend (by time)
    if 'dateAdded' in filtered.columns:
        trend_fig = px.line(
            filtered.groupby(['dateAdded', 'severity']).size().unstack().fillna(0),
            title="Severity Trend Over Time",
            labels={'value': 'Count', 'dateAdded': 'Date'}
        )
    else:
        trend_fig = px.bar(
            filtered['severity'].value_counts(),
            title="Severity Distribution",
            labels={'value': 'Count', 'index': 'Severity'}
        )
    
    # 2. Vendor Risk
    vendor_fig = px.treemap(
        filtered,
        path=['vendorProject', 'severity'],
        values='cvss_score',
        title="Vendor Risk Distribution",
        color='cvss_score',
        color_continuous_scale='RdYlGn_r'
    )
    
    # 3. Technique Word Cloud (simulated)
    if 'mitre_techniques' in filtered.columns:
        tech_data = filtered['mitre_techniques'].explode().value_counts().reset_index()
        tech_fig = px.bar(
            tech_data.head(20),
            x='mitre_techniques',
            y='count',
            title="Top MITRE ATT&CK Techniques",
            color='count',
            color_continuous_scale='Blues'
        )
    else:
        tech_fig = go.Figure()
        tech_fig.update_layout(title="No MITRE Technique Data Available")
    
    # 4. Risk Distribution
    risk_fig = px.histogram(
        filtered,
        x='risk_score',
        nbins=20,
        title="Risk Score Distribution",
        marginal="box"
    )
    
    # 5. CWE Analysis
    if 'cwes' in filtered.columns:
        cwe_data = filtered['cwes'].explode().value_counts().reset_index()
        cwe_fig = px.pie(
            cwe_data.head(10),
            names='cwes',
            values='count',
            title="Top 10 CWEs"
        )
    else:
        cwe_fig = go.Figure()
        cwe_fig.update_layout(title="No CWE Data Available")
    
    return trend_fig, vendor_fig, tech_fig, risk_fig, cwe_fig

@app.callback(
    Output('cve-table', 'data'),
    [Input('filtered-data', 'data')]
)
def update_table(data):
    return data if data else []

# ========== Run App ==========
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)