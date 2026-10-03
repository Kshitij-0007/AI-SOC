"""How to start and run the ML model for the AI-SOC project."""

import sys
sys.path.insert(0, '.')

print("=== ML MODEL STARTUP GUIDE ===")
print()

print("STEP 1: Load feature table (from Module 2 feature engineering)")
print("  from src.features.feature_store_io import load_feature_table")
print("  X, y = load_feature_table('data/feature_store/feature_table.parquet')")
print()

print("STEP 2: Train the XGBoost model")
print("  from src.tier1_xgboost.train import train_model, save_trained_model")
print("  model, split_info = train_model(X, y, config)")
print("  config example: {'xgboost': {'n_estimators': 200, 'max_depth': 6, 'learning_rate': 0.1, 'tree_method': 'hist', 'random_state': 42}}")
print()

print("STEP 3: Save the trained model")
print("  from src.tier1_xgboost.train import save_trained_model")
print("  model_path = save_trained_model(model, 'models/xgboost')")
print("  Creates: models/xgboost/model.json")
print()

print("STEP 4: Register the version")
print("  from src.tier1_xgboost.model_registry import register_new_version")
print("  registry = register_new_version('.', model_path, 'models/xgboost/metrics.json', 'data/feature_store/encoder_v1.joblib')")
print("  Creates: models/xgboost/registry.json with version entries")
print()

print("STEP 5: Set as active version")
print("  from src.tier1_xgboost.model_registry import set_active_version")
print("  set_active_version('.', registry_id)")
print("  Makes this version the live model for predictions")
print()

print("STEP 6: Load active model for predictions")
print("  from src.tier1_xgboost.predict import load_active_model")
print("  model, encoder = load_active_model('.')")
print("  Validates encoder version matches model version")
print()

print("STEP 6: Score new events")
print("  from src.tier1_xgboost.predict import score_events")
print("  scores = score_events(model, X_test)")
print("  Returns: DataFrame with predicted_label, class_probabilities (JSON), confidence")
print()

print("STEP 7: SHAP explanations")
print("  from src.tier1_xgboost.shap_explainer import explain_predictions")
print("  explanations = explain_predictions(model, X, top_n=5)")
print("  Returns: List of top-5 SHAP features per row")