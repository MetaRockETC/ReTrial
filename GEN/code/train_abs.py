import argparse
import torch
import numpy as np
import warnings
import torch
import torch.nn.functional as F
from utils_abs import load_data
from models import GCN, myGAT, GEN
import os



warnings.filterwarnings('ignore')

# Training settings
parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', default=True, help='debug mode')
parser.add_argument('--base', type=str, default='gat', choices=['gcn', 'sgc', 'gat', 'appnp', 'sage'])
parser.add_argument('--seed', type=int, default=9, help='random seed')
parser.add_argument('--lr', type=float, default=5e-4, help='learning rate')
parser.add_argument('--weight_decay', type=float, default=5e-4, help='weight decay (L2 loss on parameters)')
parser.add_argument('--slope', type=float, default=0.05)
parser.add_argument('--edge-feats', type=int, default=64)
# parser.add_argument('--hidden', type=int, default=16, help='hidden size')
parser.add_argument('--dropout', type=float, default=0.5, help='dropout rate')
parser.add_argument('--activation', type=str, default='relu', choices=['relu', 'leaky_relu', 'elu'])
parser.add_argument('--num_heads', type=int, default=8, help='number of heads in GAT')
parser.add_argument('--num-layers', type=int, default=1)
parser.add_argument('--hidden-dim', type=int, default=64, help='dimension of the node hidden state. default is 64.')
parser.add_argument('--dataset', type=str, default='CTU', choices=['IMDB', 'CAMPUS_MTA_1800', 'CTU', 'CAMPUS_MTA', 'CAMPUS_MTA_d1', 'CAMPUS_MTA_d2', 'CAMPUS_MTA_d3',
                                                                          'CTU_d1', 'CTU_d2', 'CTU_d3', 'USTC', 'CTU_1800', 'USTC_1800', 'USTC_bin_1800', 'USTC_bin'])
parser.add_argument('--epoch', type=int, default=200, help='number of epochs to train the base model')
parser.add_argument('--patience', type=int, default=20)
parser.add_argument('--iters', type=int, default=10, help='number of iterations to train the GEN')
parser.add_argument('--k', type=int, default=3, help='k of knn graph')
parser.add_argument('--threshold', type=float, default=.98, help='threshold for adjacency matrix')
parser.add_argument('--tolerance', type=float, default=.01, help='tolerance to stop EM algorithm')
parser.add_argument('--gpu', type=str, default='cuda:0', help='select which gpu you want')
parser.add_argument('--testset', type=str, default='CTU_test', help='select which gpu you want')
                    
args = parser.parse_args()
device = torch.device(args.gpu if torch.cuda.is_available() else "cpu")
print(args)

torch.manual_seed(args.seed)
torch.cuda.manual_seed(args.seed)
np.random.seed(args.seed)

os.makedirs('checkpoint', exist_ok=True)

if args.base == 'gcn':
    data = load_data("/home/zjj/code/electricity/GEN/data", args.dataset, device)
    base_model_args = {"num_feature": data.num_feature, "num_class":data.num_class,
                "hidden_size": args.hidden, "dropout":args.dropout, "activation": args.activation}
    base_model = GCN(**base_model_args)
elif args.base == 'gat':
    data = load_data("/home/zjj/code/electricity/GEN/data", args.dataset, device)
    #
    test_data  = load_data("/home/zjj/code/electricity/GEN/data", args.testset, device)
    #
    in_dims = data.in_dims
    num_classes = data.num_classes
    num_edges = data.num_edges
    heads = [args.num_heads] * args.num_layers + [1]
    base_model = myGAT(args.edge_feats, num_edges*2+1, in_dims, args.hidden_dim, num_classes, args.num_layers, heads, F.elu, args.dropout, args.dropout, args.slope, True, 0.05, device=device)
    base_model.to(device)
model = GEN(base_model, args, device)
#
model.fit(data, test_data, device)
#
