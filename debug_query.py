#!/usr/bin/env python3
"""Debug list_recent_emails function"""
import sqlite3

conn = sqlite3.connect('phishing_detection.db')
cursor = conn.cursor()

# Try the exact query from list_recent_emails
query = """
    SELECT 
        e.id,
        e.subject,
        e.sender,
        e.recipient,
        e.received_at,
        e.final_risk_score,
        e.final_threat_level,
        e.final_action,
        COUNT(a.id) as analysis_count
    FROM emails e
    LEFT JOIN agent_analyses a ON e.id = a.email_id
    GROUP BY e.id
    ORDER BY e.received_at DESC
    LIMIT 10 OFFSET 0
"""

print("Running query...")
cursor.execute(query)
results = cursor.fetchall()

print(f"Found {len(results)} results\n")

for row in results:
    print(f"ID: {row[0]}")
    print(f"Subject: {row[1]}")
    print(f"Risk Score: {row[5]}")
    print(f"Analysis Count: {row[8]}")
    print("-" * 60)

conn.close()
