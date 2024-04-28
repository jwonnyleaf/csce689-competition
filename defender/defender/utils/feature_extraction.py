import pefile
import ember
import numpy as np
def extract_features(data):
    extractor = ember.PEFeatureExtractor()
    features = extractor.feature_vector(data)
    features = np.array(features).reshape(1, -1)
    pe = pefile.PE(data=data)
    return features, list(pe.header)

    