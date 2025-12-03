import sqlite3

# Use the correct database file as per backend config
DB_PATH = "phishing_detection.db"

def clear_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM emails;")
    cursor.execute("DELETE FROM agent_analyses;")
    cursor.execute("DELETE FROM coordination_results;")
    conn.commit()
    conn.close()
    print("Database cleared successfully.")

if __name__ == "__main__":
    clear_database()
