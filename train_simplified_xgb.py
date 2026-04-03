import os
import gc
import datetime
import yaml
import numpy as np
import pandas as pd
import xgboost as xgb
import joblib
import json
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score
import matplotlib.pyplot as plt

# ===================================================================
# CONFIGURATION
# ===================================================================

SEED = 42
DATA_DIR = r"c:\Users\rajj2\OneDrive\Desktop\FraudDetection"

# Extracted Top 30 Features from the original XGB95 validation model
TOP_30_RAW_FEATURES = [
    'V257', 'V258', 'V188', 'V70', 'C4', 'V294', 'C8', 'C14', 'addr2', 
    'V156', 'C7', 'V187', 'V283', 'C1', 'V91', 'V142', 'V30', 'card6', 
    'C10', 'V162', 'C5', 'V62', 'C13', 'card3', 'M4', 'C11', 'V289', 
    'V281', 'id_17'
]
# Note: 'card3_FE' was also in the top 30, but it's a derived feature. 
# It will be constructed at runtime per fold from 'card3'.

# Differentiating which tables contain which features to optimize loading
TRANSACTION_FEATS = [
    'V257', 'V258', 'V188', 'V70', 'C4', 'V294', 'C8', 'C14', 'addr2', 
    'V156', 'C7', 'V187', 'V283', 'C1', 'V91', 'V142', 'V30', 'card6', 
    'C10', 'V162', 'C5', 'V62', 'C13', 'card3', 'M4', 'C11', 'V289', 
    'V281'
]
IDENTITY_FEATS = ['id_17']

CATEGORICAL_FEATS = ['card6', 'M4', 'id_17']


# ===================================================================
# MODULAR FUNCTIONS
# ===================================================================

def set_seed(seed):
    """Ensure reproducibility by fixing seeds."""
    np.random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)

def load_data(data_dir):
    """
    Load train and test data using strictly ONLY the columns we need.
    This saves massive amounts of memory and time.
    """
    print("Loading data...")
    
    # 1. TRAIN SET
    train_trx_cols = ['TransactionID', 'TransactionDT', 'isFraud'] + TRANSACTION_FEATS
    X_train = pd.read_csv(
        os.path.join(data_dir, 'train_transaction.csv'),
        index_col='TransactionID', 
        usecols=train_trx_cols
    )
    
    train_id_cols = ['TransactionID'] + IDENTITY_FEATS
    train_id = pd.read_csv(
        os.path.join(data_dir, 'train_identity.csv'),
        index_col='TransactionID',
        usecols=train_id_cols
    )
    X_train = X_train.merge(train_id, how='left', left_index=True, right_index=True)
    
    # Target and removal
    y_train = X_train['isFraud'].copy()
    X_train.drop(columns=['isFraud'], inplace=True)
    del train_id; gc.collect()

    # 2. TEST SET
    test_trx_cols = ['TransactionID', 'TransactionDT'] + TRANSACTION_FEATS
    X_test = pd.read_csv(
        os.path.join(data_dir, 'test_transaction.csv'),
        index_col='TransactionID',
        usecols=test_trx_cols
    )
    
    # The test_identity column names differ (id-17 vs id_17). 
    # We must alias the column names accordingly.
    test_id_cols_aliased = ['TransactionID'] + [f.replace('_', '-') for f in IDENTITY_FEATS]
    test_id = pd.read_csv(
        os.path.join(data_dir, 'test_identity.csv'),
        index_col='TransactionID',
        usecols=test_id_cols_aliased
    )
    # Rename to match train set
    fix = {o: n for o, n in zip(test_id_cols_aliased, ['TransactionID'] + IDENTITY_FEATS)}
    test_id.rename(columns=fix, inplace=True)
    
    X_test = X_test.merge(test_id, how='left', left_index=True, right_index=True)
    del test_id; gc.collect()

    print(f"Loaded Train Shape: {X_train.shape}")
    print(f"Loaded Test Shape: {X_test.shape}")
    
    return X_train, X_test, y_train


def preprocess_data(X_train, X_test):
    """
    Basic preprocessing such as creating time groupings and label encoding categoricals.
    We purposely AVOID filling NaNs as XGBoost handles them natively and elegantly.
    """
    print("Preprocessing data...")
    
    # Extract Months for GroupKFold validation strategy
    START_DATE = datetime.datetime.strptime('2017-11-30', '%Y-%m-%d')
    for df in [X_train, X_test]:
        dt_m = df['TransactionDT'].apply(lambda x: (START_DATE + datetime.timedelta(seconds=x)))
        df['DT_M'] = (dt_m.dt.year - 2017) * 12 + dt_m.dt.month 

    # Label Encode Categorical Variables safely
    cat_mappings = {}
    for col in CATEGORICAL_FEATS:
        # Convert everything to string first to handle distinct types and nan
        X_train[col] = X_train[col].astype(str).replace('nan', np.nan)
        X_test[col]  = X_test[col].astype(str).replace('nan', np.nan)
        
        # Factorize across both to ensure consistent encoding mappings
        combined = pd.concat([X_train[col], X_test[col]])
        labels, uniques = pd.factorize(combined, use_na_sentinel=True)
        
        # Store mapping
        cat_mappings[col] = {str(k): float(v) for v, k in enumerate(uniques)}
        
        # We restore np.nan instead of using -1, so XGBoost handles missingness
        combined_float = labels.astype(float)
        combined_float[combined_float == -1] = np.nan
        
        X_train[col] = combined_float[:len(X_train)]
        X_test[col]  = combined_float[len(X_train):]
        
    return X_train, X_test, cat_mappings


def compute_frequency_encoding_fold(train_df, valid_df, test_df, col='card3'):
    """
    Computes frequency encoding safely INSIDE the fold.
    This strictly prevents data leakage by only using the active training subset's distribution.
    """
    # Calculate target frequencies from the train set ONLY
    freq_dict = train_df[col].value_counts(dropna=True, normalize=True).to_dict()
    
    new_col = f"{col}_FE"
    # Map the frequencies
    train_fe = train_df[col].map(freq_dict).astype('float32')
    valid_fe = valid_df[col].map(freq_dict).astype('float32')
    # Use the active fold's frequencies to estimate the test set
    test_fe = test_df[col].map(freq_dict).astype('float32')
    
    return train_fe, valid_fe, test_fe


def train_and_evaluate(X_train, y_train, X_test):
    """
    Train XGBoost using KFold validation, computing frequency encodings iteratively,
    and evaluating ROC-AUC natively.
    """
    print("Beginning Cross-Validation and Training...")
    
    oof = np.zeros(len(X_train))
    preds = np.zeros(len(X_test))
    feature_importances = pd.DataFrame()
    
    # We drop metadata columns from the actual model's training columns
    model_features = TOP_30_RAW_FEATURES + ['card3_FE']
    
    skf = GroupKFold(n_splits=6)
    for i, (idxT, idxV) in enumerate(skf.split(X_train, y_train, groups=X_train['DT_M'])):
        month = X_train.iloc[idxV]['DT_M'].iloc[0]
        print(f"\n--- Fold {i+1} | Withholding Month {month} ---")
        
        # Sliced Data
        X_tr = X_train.iloc[idxT].copy()
        y_tr = y_train.iloc[idxT]
        X_va = X_train.iloc[idxV].copy()
        y_va = y_train.iloc[idxV]
        
        # 1. Leakage-Free Frequency Encoding Computation inside the Fold
        X_tr['card3_FE'], X_va['card3_FE'], cur_test_fe = compute_frequency_encoding_fold(
            X_tr, X_va, X_test, col='card3'
        )
        # Apply the current fold's test FE
        X_test_cur = X_test.copy()
        X_test_cur['card3_FE'] = cur_test_fe
        
        # 2. XGBoost Model Training
        clf = xgb.XGBClassifier(
            n_estimators=5000,
            max_depth=12,
            learning_rate=0.02,
            subsample=0.8,
            colsample_bytree=0.4,
            early_stopping_rounds=200,
            eval_metric='auc',
            tree_method='hist',
            use_label_encoder=False,
            random_state=SEED  # Seed set for reproducibility
            # Note: We omit missing=-1, so XGBoost uses standard dense/sparse NaN handling
        )    
            
        clf.fit(
            X_tr[model_features], y_tr, 
            eval_set=[(X_va[model_features], y_va)],
            verbose=250
        )
        
        # 3. Model Evaluation Predictions
        oof[idxV] += clf.predict_proba(X_va[model_features])[:, 1]
        preds += clf.predict_proba(X_test_cur[model_features])[:, 1] / skf.n_splits
        
        # Accumulate Importances
        imp_df = pd.DataFrame()
        imp_df['Feature'] = model_features
        imp_df['Value'] = clf.feature_importances_
        imp_df['Fold'] = i + 1
        feature_importances = pd.concat([feature_importances, imp_df], axis=0)
        
        del clf, X_tr, X_va, X_test_cur
        gc.collect()

    fold_auc = roc_auc_score(y_train, oof)
    print("="*40)
    print(f"Final OOF Cross-Validation ROC-AUC: {fold_auc:.5f}")
    print("="*40)
    
    return oof, preds, feature_importances


def plot_feature_importances(feature_importances):
    """Averages block importances across folds and plots them."""
    # Group by feature and sort
    mean_imp = feature_importances.groupby('Feature')['Value'].mean().sort_values(ascending=False).reset_index()
    
    plt.figure(figsize=(12, 8))
    plt.barh(mean_imp['Feature'][::-1], mean_imp['Value'][::-1])
    plt.title('Simplified XGBoost Model - Top Feature Importances')
    plt.xlabel('Importance')
    plt.tight_layout()
    plt.savefig('simplified_feature_importances.png')
    plt.show()

# ===================================================================
# MAIN PIPELINE 
# ===================================================================

def main():
    set_seed(SEED)
    
    # 1. Loading
    X_train, X_test, y_train = load_data(DATA_DIR)
    
    # 2. Base Preprocessing
    X_train, X_test, cat_mappings = preprocess_data(X_train, X_test)
    
    # 3. Training, Leak-free Fold extraction, and Evaluation
    oof, preds, importances = train_and_evaluate(X_train, y_train, X_test)
    
    # 4. Report & Visualize
    plot_feature_importances(importances)
    
    # 5. Saving Results
    print("Saving predicted targets...")
    out_df = pd.DataFrame({
        'TransactionID': X_test.index,
        'isFraud': preds
    })
    out_df.to_csv('simplified_submission.csv', index=False)
    
    # 6. Saving Final Production Model & Artifacts
    print("Training final production model on ALL data...")
    clf_final = xgb.XGBClassifier(
        n_estimators=1500,  # Lower than 5000 since there is no early stopping out of fold
        max_depth=12,
        learning_rate=0.02,
        subsample=0.8,
        colsample_bytree=0.4,
        eval_metric='auc',
        tree_method='hist',
        use_label_encoder=False,
        random_state=SEED
    )
    
    # Create the global Frequency Encoding dict for the entire train set
    freq_dict = X_train['card3'].value_counts(dropna=True, normalize=True).to_dict()
    X_train['card3_FE'] = X_train['card3'].map(freq_dict).astype('float32')
    
    model_features = TOP_30_RAW_FEATURES + ['card3_FE']
    clf_final.fit(X_train[model_features], y_train, verbose=250)
    
    import os
    os.makedirs("model", exist_ok=True)
    
    print("Saving fraud_model.pkl and setup artifacts...")
    joblib.dump(clf_final, "model/fraud_model.pkl")
    
    with open("model/preproc_artifacts.json", "w") as f:
        json.dump({
            "categorical_mappings": cat_mappings,
            "card3_fe_mapping": {str(k): float(v) for k, v in freq_dict.items()}
        }, f, indent=4)
        
    print("Pipeline Complete! Output saved to 'simplified_submission.csv' and 'model/' folder.")

if __name__ == "__main__":
    main()
