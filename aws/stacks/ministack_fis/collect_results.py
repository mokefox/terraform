#!/usr/bin/env python3
import pathlib, sys, pandas as pd, matplotlib.pyplot as plt

csv_path = pathlib.Path(__file__).parent / 'article_assets' / 'fis_rto_data.csv'
if not csv_path.is_file():
    sys.exit('❌ CSV file not found: ' + str(csv_path))

df = pd.read_csv(csv_path)
df['run'] = range(1, len(df) + 1)

print('Stats:')
print(df['rto_seconds'].describe())

plt.figure(figsize=(8,4))
plt.plot(df['run'], df['rto_seconds'], marker='o')
plt.title('RTO of ECS Task Stop (FIS + Floci)')
plt.xlabel('Run #')
plt.ylabel('RTO (seconds)')
plt.grid(True, linestyle='--', alpha=0.5)

out_png = pathlib.Path(__file__).parent / 'article_assets' / 'fis_rto_chart.png'
plt.tight_layout()
plt.savefig(out_png, dpi=150)
print('✅ Chart saved to', out_png)
