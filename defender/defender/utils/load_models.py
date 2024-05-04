import joblib, os, torch
from defender.utils.malconv import MalConvPlus, AttentionRCNN
def load_rf(model_path):
    model = joblib.load(model_path)
    return model

def load_malconv(model_path):
    embed_dim = 8
    max_len = 4096
    out_channels = 128
    window_size = 32
    dropout = 0.5
    if torch.cuda.is_available():
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")
    
    model = MalConvPlus(embed_dim, max_len, out_channels, window_size, device, dropout)
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    model.to(device)
    model.eval()
    return model
def load_attn(model_path):
    embed_dim = 8
    max_len = 4096
    out_channels = 128
    window_size = 32
    module = torch.nn.RNN
    hidden_size = 128
    num_layers = 8
    bidirectional = True
    attn_size = 128
    residual = True
    dropout = 0.5
    if torch.cuda.is_available():
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")

    model = AttentionRCNN(embed_dim, out_channels, window_size, module, hidden_size, num_layers, bidirectional, attn_size, residual, device, dropout).to(device)
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    model.to(device)
    model.eval()
    return model

model_loader = {
    "RF": load_rf,
    "Malconv": load_malconv,
    "AttnRCNN": load_attn
}

def load_model(model_name, model_path):
    loader = model_loader.get(model_name, None)
    if loader :
        model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), model_path)
        return loader(model_path)
    else:
        print(f"No such model : {model_name}")

if __name__ == '__main__' :
    rf = load_model("RF", "../models/rf_ember_subset.joblib")
    print("RF loaded successfully")
    malconv = load_model("Malconv", "../models/malconv_v2.pt")
    print("Malconv loaded successfully")
    attn = load_model("AttnRCNN", "../models/attn_merge.pt")
    print("Malconv loaded successfully")
