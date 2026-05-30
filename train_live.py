"""
Retrain a model using ONLY features we can compute from a live packet capture.
Trained on NSL-KDD, scoring a live-extractable feature subset.
"""
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
import joblib

COLUMNS = [
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

LIVE_FEATURES = ['protocol_type', 'service', 'src_bytes', 'dst_bytes',
                 'duration', 'count', 'dst_host_count']
CATEGORICAL = ['protocol_type', 'service']
NUMERIC = ['src_bytes', 'dst_bytes', 'duration', 'count', 'dst_host_count']

train = pd.read_csv('data/KDDTrain+.txt', names=COLUMNS)
X = train[LIVE_FEATURES].copy()
y = (train['label'] != 'normal').astype(int)

pipe = Pipeline([
    ('prep', ColumnTransformer([
        ('cat', OneHotEncoder(handle_unknown='ignore'), CATEGORICAL),
        ('num', StandardScaler(), NUMERIC),
    ])),
    ('rf', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)),
])
pipe.fit(X, y)
print("Trained on:", LIVE_FEATURES)
print("Training accuracy:", round(pipe.score(X, y), 3))

joblib.dump(pipe, 'live_model.joblib')
print("Saved -> live_model.joblib")