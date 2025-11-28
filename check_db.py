#!/usr/bin/env python3
"""Quick script to check database contents"""
import sqlite3
import json

conn = sqlite3.connect('phishing_detection.db')
cursor = conn.cursor()

# Get the latest email (UID 29)
print('=' * 80)
print('LATEST EMAIL - FULL DATA')
print('=' * 80)
cursor.execute('''
    SELECT id, email_uid, subject, sender, recipient, body, headers, metadata,
           final_risk_score, final_threat_level, final_action, received_at
    FROM emails 
    WHERE email_uid = "29"
''')
email = cursor.fetchone()

if email:
    print(f'Email UUID: {email[0]}')
    print(f'Email UID: {email[1]}')
    print(f'Subject: {email[2]}')
    print(f'Sender: {email[3]}')
    print(f'Recipient: {email[4]}')
    print(f'Body Preview: {email[5][:100] if email[5] else "N/A"}...')
    print(f'Headers: {email[6][:100] if email[6] else "N/A"}...')
    print(f'Metadata: {email[7][:100] if email[7] else "N/A"}...')
    print(f'Final Risk Score: {email[8]}')
    print(f'Final Threat Level: {email[9]}')
    print(f'Final Action: {email[10]}')
    print(f'Received At: {email[11]}')
    
    email_uuid = email[0]
    
    print('\n' + '=' * 80)
    print(f'ALL ANALYSES FOR EMAIL UUID: {email_uuid}')
    print('=' * 80)
    
    cursor.execute('''
        SELECT agent_name, risk_score, threat_level, confidence, indicators, analysis, 
               execution_time_ms, analyzed_at
        FROM agent_analyses 
        WHERE email_id = ?
        ORDER BY analyzed_at
    ''', (email_uuid,))
    
    analyses = cursor.fetchall()
    
    for row in analyses:
        print(f'\n{"─" * 80}')
        print(f'Agent: {row[0].upper()}')
        print(f'Risk Score: {row[1]}')
        print(f'Threat Level: {row[2]}')
        print(f'Confidence: {row[3]}')
        print(f'Execution Time: {row[6]}ms')
        print(f'Analyzed At: {row[7]}')
        
        # Parse indicators JSON
        if row[4]:
            try:
                indicators = json.loads(row[4])
                print(f'Indicators: {json.dumps(indicators, indent=2)[:200]}...')
            except:
                print(f'Indicators (raw): {row[4][:200]}...')
        
        # Show analysis preview
        if row[5]:
            print(f'Analysis Preview: {row[5][:200]}...')
    
    print('\n' + '=' * 80)
    print(f'TOTAL ANALYSES: {len(analyses)}')
    print('=' * 80)
    
else:
    print('❌ Email UID 29 not found')
    
    # Show all emails
    print('\n' + '=' * 80)
    print('ALL EMAILS IN DATABASE')
    print('=' * 80)
    cursor.execute('SELECT email_uid, subject, final_risk_score, final_action FROM emails')
    all_emails = cursor.fetchall()
    for e in all_emails:
        print(f'UID: {e[0]} | Subject: {e[1]} | Risk: {e[2]} | Action: {e[3]}')

conn.close()
