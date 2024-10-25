import pandas as pd
import sys

def load_logs(file):
    try:
        return pd.read_csv(file)
    except Exception as e:
        print(f"Error loading log file: {e}")
        return None

def detect_suspicious_activity(df):
    failed_logins = df[(df['action'] == 'login') & (df['result'] == 'failed')].groupby('user_id').size()
    
    print("Users with multiple failed login attempts:")
    for user_id, count in failed_logins.items():
        if count > 3:
            print(f"User {user_id} had {count} failed login attempts.")

    location_changes = df.groupby('user_id')['location'].nunique()
    print("\nUsers with logins from multiple locations:")
    for user_id, locations in location_changes.items():
        if locations > 1:
            print(f"User {user_id} logged in from {locations} different locations.")

def main():
    if len(sys.argv) < 3 or sys.argv[1] != '--file':
        print("Usage: python log_access_control.py --file <path_to_log_file>")
        return

    file = sys.argv[2]
    df = load_logs(file)

    if df is not None:
        print("Analyzing access logs for suspicious activity...")
        detect_suspicious_activity(df)

if __name__ == "__main__":
    main()
