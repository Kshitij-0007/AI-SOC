import sys
sys.path.insert(0, '.')
from src.ingestion.pipeline import run_ingestion
from src.features.pipeline import run_feature_engineering
from src.tier1_xgboost.train import train_model, save_trained_model
from src.tier1_xgboost.model_registry import register_new_version, set_active_version, get_active_version
from src.tier1_xgboost.predict import load_active_model, score_events
from src.tier1_xgboost.shap_explainer import explain_predictions
print('Full pipeline imports: OK')

# Step 1: Run ingestion
summary = run_ingestion('tests/fixtures/ingestion', 'data/processed')
print('Ingestion summary:', {k: v for k, v in summary.items() if k != 'encoder_version_used'})

# Step 2: Run feature engineering (train)
fe_summary = run_feature_engineering(
    input_parquet='data/processed/processed.parquet',
    output_dir='data/feature_store',
    mode='train'
)
print('Feature engineering train:', fe_summary['mode'], fe_summary['n_features'], 'features')

# Step 3: Run feature engineering (inference)
fe_summary_inf = run_feature_engineering(
    input_parquet='data/processed/processed.parquet',
    output_dir='data/feature_store_inf',
    mode='inference',
    encoder_path='data/feature_store/encoder_v1.joblib'
)
print('Feature engineering inference:', fe_summary_inf['mode'], fe_summary_inf['n_features'], 'features')

# Step 4: Train XGBoost model
import pandas as pd
from src.features.feature_store_io import load_feature_table
X, y = load_feature_table('data/feature_store/feature_table.parquet')
print(f'Loaded X: {X.shape}, y: {y.shape if y is not None else None}')

model, split_info = train_model(X, y, {'xgboost': {'n_estimators': 50, 'max_depth': 3, 'learning_rate': 0.1, 'tree_method': 'hist', 'random_state': 42}})
model_path = save_trained_model(model, 'models/xgboost')
print(f'Model trained: {model_path}')

# Step 5: Register version
registry = register_new_version('.', model_path, 'models/xgboost/metrics.json', 'data/feature_store/encoder_v1.joblib')
print(f'Registered version: {registry}')

# Step 6: Set active and predict
set_active_version('.', registry)
model, encoder = load_active_model('.')
X_test = X.iloc[:5]  # first 5 rows
scores = score_events(model, X_test)
print(f'Scored {len(scores)} events')
print(f'Predicted labels: {scores["predicted_label"].tolist()}')

# Step 7: SHAP explanations
explanations = explain_predictions(model, X_test, top_n=3)
print(f'SHAP explanations for {len(explanations)} rows')

print('\nComplete pipeline: SUCCESS')