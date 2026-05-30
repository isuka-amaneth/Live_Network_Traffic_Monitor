import pandas as pd

# The NSL-KDD files don't include column names, so we provide them
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
    'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
    'root_shell','su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty'
]

# Load the training data
df = pd.read_csv('data/KDDTrain+.txt', names=columns)

print("Rows and columns:", df.shape)
print()
print("First 5 connections (just a few columns):")
print(df[['protocol_type','service','flag','src_bytes','dst_bytes','label']].head())
print()
print("Kinds of traffic in here (top 10):")
print(df['label'].value_counts().head(10))
print()

# Add a simple normal-vs-attack column
df['is_attack'] = (df['label'] != 'normal').astype(int)
print("Normal (0) vs attack (1):")
print(df['is_attack'].value_counts())