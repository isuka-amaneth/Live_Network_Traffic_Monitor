import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
import joblib

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

# Load both sets
train = pd.read_csv('data/KDDTrain+.txt', names=columns)
test  = pd.read_csv('data/KDDTest+.txt',  names=columns)

# Drop 'difficulty' — it's a dataset artifact, not a network feature
train = train.drop(columns=['difficulty'])
test  = test.drop(columns=['difficulty'])

# Target: 0 = normal, 1 = attack
y_train = (train['label'] != 'normal').astype(int)
y_test  = (test['label']  != 'normal').astype(int)

# Features = everything except the label
X_train = train.drop(columns=['label'])
X_test  = test.drop(columns=['label'])

# Which columns are text vs numbers
categorical = ['protocol_type', 'service', 'flag']
numeric = [c for c in X_train.columns if c not in categorical]

# One-hot encode the text columns, scale the numeric ones
preprocessor = ColumnTransformer([
    ('text', OneHotEncoder(handle_unknown='ignore'), categorical),
    ('nums', StandardScaler(), numeric),
])

# Learn the transformation from TRAINING data only, then apply to both
X_train_ready = preprocessor.fit_transform(X_train)
X_test_ready  = preprocessor.transform(X_test)

print("Before:", X_train.shape, "->  After:", X_train_ready.shape)
print("Test set after:", X_test_ready.shape)
print("Training labels:", dict(y_train.value_counts()))

# Save everything so the next step loads instantly
joblib.dump((X_train_ready, X_test_ready, y_train, y_test, preprocessor),
            'processed_data.joblib')
print("Saved -> processed_data.joblib")