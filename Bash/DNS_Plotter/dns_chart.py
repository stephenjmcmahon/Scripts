import pandas as pd
import plotly.express as px

df = pd.read_csv("dns_results.csv", parse_dates=["timestamp"])
df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
df = df[df["latency_ms"].notna()]

fig = px.line(
    df,
    x="timestamp",
    y="latency_ms",
    color="hostname",
    facet_row="resolver",
    title="DNS Latency by Hostname per Resolver",
    height=900
)

fig.update_yaxes(matches=None)  # allow independent Y scales
fig.show()
