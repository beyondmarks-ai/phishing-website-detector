# Training Summary

- Selected model: `random_forest`
- Dataset mode: `raw_url`
- Threshold: `0.5`
- Training rows: `19999`
- Test rows: `5000`
- Feature count: `34`

## Data Sources

- `data\phiusiil_raw_url_training_20k_app_labels.csv`

## Model Comparison

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| logistic_regression | 0.9938 | 1.0000 | 0.9854 | 0.9926 | 0.9971 |
| random_forest | 0.9950 | 0.9981 | 0.9901 | 0.9941 | 0.9978 |
| xgboost | 0.9944 | 0.9971 | 0.9896 | 0.9934 | 0.9981 |

## Feature Order

`url_length`, `hostname_length`, `path_length`, `query_length`, `subdomain_count`, `dot_count`, `hyphen_count`, `underscore_count`, `slash_count`, `question_mark_count`, `equals_count`, `at_symbol_present`, `https_scheme`, `ip_address_host`, `digit_ratio`, `url_entropy`, `suspicious_tld`, `shortener_domain`, `phishing_keyword_count_url`, `brand_in_subdomain`, `dns_resolves`, `ssl_available`, `ssl_days_remaining`, `domain_age_days`, `page_fetch_success`, `form_count`, `password_field_count`, `iframe_count`, `script_count`, `external_link_ratio`, `title_brand_mismatch`, `phishing_keyword_count_content`, `stemmed_keyword_count_content`, `reputation_blacklist_hit`
