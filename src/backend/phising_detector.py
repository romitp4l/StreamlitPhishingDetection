import numpy as np
import pandas as pd
from sklearn.calibration import LabelEncoder
from scipy.stats import pearsonr
from sklearn.discriminant_analysis import StandardScaler
from sklearn.ensemble import AdaBoostClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split
from src.backend.utils import age_of_domain, count_dot_url, count_http_url, count_https_url, count_hyphen_url, count_tilde, count_underline_url, registration_length, verify_ssl_certificate

# Data Processing
def data_processing(data):
    # Drop URL
    data.drop(columns=['url'],inplace=True)
    
    # Add Encoder
    encoder = LabelEncoder()
    data['type'] = encoder.fit_transform(data['type'])
    
    # Removing Outlier
    Q1 = data['regis_length'].quantile(0.25)
    Q3 = data['regis_length'].quantile(0.75)
    IQR = Q3 - Q1
    Lower = Q1 - 1.5*IQR
    Upper = Q3 + 1.5*IQR
    Lower_array = np.where(data['regis_length']<=Lower)[0]
    Upper_array = np.where(data['regis_length']>=Upper)[0]
    data.drop(index=Lower_array,inplace=True)
    data = data.reset_index(drop=True)
    data.drop(index=Upper_array,inplace=True)
    data = data.reset_index(drop=True)
    
    # Feature Selection
    copydf = data.copy()
    copydf.drop(columns=['type'],inplace=True)
    features = list(copydf.columns)
    Pearson_feature = []
    for feature in features:
        correlation_coefficient,p_value = pearsonr(copydf[feature],data['type'])
        if abs(correlation_coefficient)>0.1 and p_value <0.05:
            print(f'{feature} :{correlation_coefficient}')
            Pearson_feature.append(feature)
    Pearson_feature.append('type')
    data = data[Pearson_feature]
    
    # Standardization
    copydf = data.copy()
    Scaler = StandardScaler()
    copydf = Scaler.fit_transform(copydf)
    copydf = pd.DataFrame(copydf,columns=[Pearson_feature])
    data['domain_age'] = copydf['domain_age']
    data['regis_length'] = copydf['regis_length']
    
    return data, Scaler

# Data Prediction
def predict_phishing(mode,url, data, Scaler):
    
    # Data Training
    x = data.drop(columns=['type'])
    y = data['type']
    x_train,x_test,y_train,y_test = train_test_split(x,y,random_state=42,test_size=0.3)
    
    # Data Prediction
    url_data = {
        'count_http': count_http_url(url),
        'count_https': count_https_url(url),
        'countdot':count_dot_url(url),
        'count-': count_hyphen_url(url),
        'count_': count_underline_url(url),
        'counttilde': count_tilde(url),
        'domain_age': age_of_domain(url),
        'regis_length': registration_length(url),
        'SSL_certificate': verify_ssl_certificate(url)
    }

    url_df = pd.DataFrame(url_data, index=[0])

    copydf = data.copy()
    mean_dict = {}
    for i, mean_value in enumerate(Scaler.mean_):
       feature_name = copydf.columns[i]
       mean_dict[feature_name] = mean_value

    std_dict = {}
    for i, std_value in enumerate(Scaler.scale_):
        feature_name = copydf.columns[i]
        std_dict[feature_name] = std_value

    url_df['domain_age'] = (url_df['domain_age'] - mean_dict[('domain_age')]) / std_dict[('domain_age')]
    url_df['regis_length'] = (url_df['regis_length'] - mean_dict[('regis_length')]) / std_dict[('regis_length')]

    if (mode=='RFC'):
      RF = RandomForestClassifier(n_estimators=100,max_features='log2')
      RF.fit(x_train,y_train)
      RF_pred = RF.predict(url_df)
      return RF_pred[0]
  
    elif (mode=='GBC'):
      GBC = GradientBoostingClassifier()
      GBC.fit(x_train,y_train)
      GBC_pred = GBC.predict(url_df)
      return GBC_pred[0]
  
    elif (mode=='ABC'):
      ABC = AdaBoostClassifier()
      ABC.fit(x_train,y_train)
      ABC_pred = ABC.predict(url_df)
      return ABC_pred[0]