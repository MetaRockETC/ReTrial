import torch
import torch.nn as nn
from torch_geometric.nn import GCNConv
import torch.nn.functional as F
import torch.optim as optim
import time
from copy import deepcopy
import numpy as np
from collections import Counter
from sklearn.cluster import KMeans
from sklearn.metrics import  roc_auc_score, f1_score, classification_report
from sklearn.metrics.pairwise import cosine_similarity as cos
import pickle as pkl
import scipy
from utils import compute_accuracy, sparse_mx_to_sparse_tensor, prob_to_adj, get_homophily
from pytorchtools import EarlyStopping
from scipy.sparse import csr_matrix
import dgl
from dgl.nn.pytorch import GraphConv
import scipy.sparse as sp
import dgl.function as fn
from dgl.nn.pytorch import edge_softmax, GATConv
from layers import myGATConv
import pandas as pd
from torch.optim.lr_scheduler import LambdaLR
import json

"""
Backbone GNN Model
Parameters
----------
feature:
    feature of nodes (torch.Tensor)
adj:
    adjacency matrix (torch.Tensor)

Returns
----------
x1:
    node embedding of hidden layer (torch.Tensor)
"""
class GCN(nn.Module):
    def __init__(self, num_feature, num_class, hidden_size, dropout=0.5, activation="relu"):
        super(GCN, self).__init__()
        self.conv1 = GCNConv(num_feature, hidden_size)
        self.conv2 = GCNConv(hidden_size, num_class)

        self.dropout = dropout
        assert activation in ["relu", "leaky_relu", "elu"]
        self.activation = getattr(F, activation)

    def forward(self, feature, adj):
        x1 = self.activation(self.conv1(feature, adj))
        x1 = F.dropout(x1, p=self.dropout, training=self.training)
        x2 = self.conv2(x1, adj)
        return x1, F.log_softmax(x2, dim=1)

"""
Backbone GAT Model
Parameters
----------
feature:
    feature of nodes (torch.Tensor)
adj:
    adjacency matrix (torch.Tensor)

Returns
----------
x1:
    node embedding of hidden layer (torch.Tensor)
"""

class myGAT(nn.Module):
    def __init__(self,
                 edge_dim,
                 num_etypes,
                 in_dims,
                 num_hidden,
                 num_classes,
                 num_layers,
                 heads,
                 activation,
                 feat_drop,
                 attn_drop,
                 negative_slope,
                 residual,
                 alpha,
                 device):
        super(myGAT, self).__init__()
        self.num_layers = num_layers
        self.gat_layers = nn.ModuleList()
        self.activation = activation
        self.fc_list = nn.ModuleList([nn.Linear(in_dim, num_hidden, bias=True) for in_dim in in_dims])
        for fc in self.fc_list:
            nn.init.xavier_normal_(fc.weight, gain=1.414)
        # input projection (no residual)
        self.gat_layers.append(myGATConv(edge_dim, num_etypes,
            num_hidden, num_hidden, heads[0],
            feat_drop, attn_drop, negative_slope, False, self.activation, alpha=alpha))
        # hidden layers
        for l in range(1, num_layers):
            # due to multi-head, the in_dim = num_hidden * num_heads
            self.gat_layers.append(myGATConv(edge_dim, num_etypes,
                num_hidden * heads[l-1], num_hidden, heads[l],
                feat_drop, attn_drop, negative_slope, residual, self.activation, alpha=alpha))
        # output projection
        self.gat_layers.append(myGATConv(edge_dim, num_etypes,
            num_hidden * heads[-2], num_classes, heads[-1],
            feat_drop, attn_drop, negative_slope, residual, None, alpha=alpha))
        self.epsilon = torch.FloatTensor([1e-12]).to(device)

    def forward(self, blocks, features_list, input_nodes):

        hs = []        
        h = []
        for fc, feature in zip(self.fc_list, features_list):
            h.append(fc(feature))
        h = torch.cat(h, 0)
        h = h[input_nodes]
        
        res_attn = None
        for l in range(self.num_layers):
            h, res_attn = self.gat_layers[l](blocks[l], h, res_attn=res_attn)
            h = h.flatten(1)
            hs.append(h)
        # output projection
        logits, _ = self.gat_layers[-1](blocks[-1], h, res_attn=None)
        logits = logits.mean(1)
        # This is an equivalent replacement for tf.l2_normalize, see https://www.tensorflow.org/versions/r1.15/api_docs/python/tf/math/l2_normalize for more information.
        logits = logits / (torch.max(torch.norm(logits, dim=1, keepdim=True), self.epsilon))
        hs.append(F.log_softmax(logits,1))
        return hs



"""
Parameters
----------
base_model:
    backbone GNN model in GEN
args:
    configs
device:
    "cpu" or "cuda"
"""
class GEN:
    def __init__(self, base_model, args, device):
        self.args = args
        self.device = device
        self.base_model = base_model.to(device)

        self.iteration = 0
        self.num_class = 0
        self.num_node = 0

        self.best_auc_val = 0
        self.best_graph = None
        self.hidden_output = None

        self.output = None
        self.weights = None

    def to_json(self, g, data, g_path):
        graph  = dict()
        graph['node_id'] = g.nodes().numpy().tolist()
        edge_info = g.edges(form='all')
        graph['source_id'] = edge_info[0].numpy().tolist()
        graph['target_id'] = edge_info[1].numpy().tolist()
        graph['edge_id'] = edge_info[2].numpy().tolist()
        graph['label'] = data.y.cpu().numpy().tolist()

        with open(g_path, 'w') as json_file:
            json_file.write(json.dumps(graph, indent=4))

    def fit(self, data, test_data, device):
        """
        Parameters
        ----------
        data
            x:
                node feature (torch.Tensor)
            adjs:
                adjacency matrixes (torch.Tensor)
            y:
                node label (torch.Tensor)
            idx_train:
                node indices of trainset (list)
            idx_val:
                node indices of valset (list)
            idx_test:
                node indices of testset (list)
        """
        args = self.args
        self.num_class = data.num_class
        self.num_node = 1200
        self.sampler = dgl.dataloading.MultiLayerNeighborSampler([16,8])
        adjs = data.adjs
        #
        test_adjs = test_data.adjs
        #
        homophilies = data.homophilies
        data.x[0] = torch.cat((data.x[0], test_data.x[0]), dim=0).to(device)
        data.y = torch.cat((data.y, test_data.y), dim=0).to(device)
        data.idx_train = np.arange(0, 1000)
        data.idx_val = np.arange(1000, 1200)
        # perturbation_adjs = [csr_matrix(np.load(f'/home/zjj/code/RETA/GEN/data/CAMPUS_MTA_1800/campus_mta_{i}_0.15.npz', allow_pickle=True)['adj_data']) for i in range(5)]
        #test_adjs = perturbation_adjs
        adjs = [sp.bmat([[adjs[i], None], [None, test_adjs[i]]]).tocsc().tocsr() for i in range(len(adjs))]
        
        # Graph Construction
        # self.g = dgl.DGLGraph()
        # for i, adj in enumerate(adjs+[scipy.sparse.eye(adjs[0].shape[0])]):
        #     rows, cols = adj.nonzero()
        #     e_type = i * torch.ones(rows.shape[0],1)
        #     self.g = dgl.add_edges(self.g, rows, cols, {'e': e_type})
        # print(self.g)
        # dgl.save_graphs(f'../data/modified_graph/{args.dataset}_before.dgl', [self.g], labels={'label':data.y})
        #test_adjs = perturbation_adjs
        # Test Graph
        # self.test_g = dgl.DGLGraph()
        # for i, adj in enumerate(test_adjs+[scipy.sparse.eye(test_adjs[0].shape[0])]):
        #     rows, cols = adj.nonzero()
        #     e_type = i * torch.ones(rows.shape[0],1)
        #     self.test_g = dgl.add_edges(self.test_g, rows, cols, {'e': e_type})
        # print(self.test_g)
        
        #estimator = EstimateAdj(data)
        estimators = []
        for i, adj in enumerate(adjs):
            estimators.append(EstimateAdj(data))
        visual_loss = []
        visual_auc = []
        visual_f1 = []
        visual_loss_train = []
        visual_auc_train = []
        visual_f1_train = []
        # Train Model
        t_total = time.time()
        for iteration in range(args.iters):
            start = time.time()

            loss, auc, f1, g, loss_train, auc_train, f1_train = self.train_base_model(data, adjs, iteration)
            visual_loss.append(loss)
            visual_auc.append(auc)
            visual_f1.append(f1)
            visual_loss_train.append(loss_train)
            visual_auc_train.append(auc_train)
            visual_f1_train.append(f1_train)
            if iteration == 0:
                self.to_json(g, data, f'../graph/{args.dataset}.json')
                print("Base model metrics")
            self.test(data, g)
            for i, adj in enumerate(adjs):
                estimators[i].reset_obs()
                estimators[i].update_obs(self.knn(torch.cat(data.x, 0)))
                estimators[i].update_obs(self.knn(self.hidden_output))
                estimators[i].update_obs(self.knn(self.output))
                
                self.iteration += 1
                alpha, beta, O, Q, iterations = estimators[i].EM(homophilies[i], adj, self.output.max(1)[1].detach().cpu().numpy(), args.tolerance)
                adjs[i] = prob_to_adj(Q, args.threshold)
                homophilies[i] = get_homophily(data.y.cpu(), adjs[i].todense())
            self.to_json(g, data, f'../graph/{args.dataset}_{iteration}.json')
        #print(list(zip(visual_auc, visual_f1, visual_loss)))
        #df = pd.DataFrame(list(zip(visual_auc, visual_f1, visual_loss)), columns=['auc', 'f1', 'loss'])
        #df.to_csv(f'/home/zjj/code/RETA/GEN/code/new_{args.dataset}_val50.csv', index=False)
        #df1 = pd.DataFrame(list(zip(visual_auc_train, visual_f1_train, visual_loss_train)), columns=['auc', 'f1', 'loss'])
        #df1.to_csv(f'/home/zjj/code/RETA/GEN/code/new_{args.dataset}_train50.csv', index=False)
        print("***********************************************************************************************")
        print("Optimization Finished!")
        print("Total time:{:.4f}s".format(time.time() - t_total),
            "Best validation auc:{:.4f}".format(self.best_auc_val),
            "EM iterations:{:04d}\n".format(iterations))

        for i, adj in enumerate(self.best_graph):
            with open('{}/{}_{}_adj.p'.format('../data', i, args.dataset), 'wb') as f:
                pkl.dump((adj.todense(), data.y.cpu().numpy()), f)
                print("Save!")
        f.close()

    def knn(self, feature):
        adj = np.zeros((self.num_node, self.num_node), dtype=np.int64)
        dist = cos(feature.detach().cpu().numpy())
        col = np.argpartition(dist, -(self.args.k + 1), axis=1)[:,-(self.args.k + 1):].flatten()
        adj[np.arange(self.num_node).repeat(self.args.k + 1), col] = 1
        return adj

    def evaluate(self, x, y, model, dataloader, device):
            model.eval()
            correct_predictions = 0
            batch_auc = 0
            batch_f1 = 0
            total_output = []
            total_predicted_y = []
            total_y = []
            with torch.no_grad():
                epoch_loss = 0
                sample_number = 0
                for input_nodes, output_nodes, blocks in dataloader:
                    blocks = [block.to(device) for block in blocks]
                    # print(output_nodes.cpu().numpy(), blocks[1].num_src_nodes(), blocks[1].num_edges())
                    hs = model(blocks, x, input_nodes)
                    output = hs[-1]
                    
                    loss = F.nll_loss(output, y[output_nodes])
                    epoch_loss += loss.item() * len(output_nodes)
                    sample_number += len(output_nodes)

                    total_output.append(torch.exp(output).cpu().numpy())
                    total_predicted_y.append(output.max(1)[1].cpu().numpy())
                    total_y.append(F.one_hot(y[output_nodes],len(y.unique())).cpu().numpy())

            total_output = np.concatenate(total_output)
            total_predicted_y = np.concatenate(total_predicted_y)
            total_y = np.concatenate(total_y)

            f1 = f1_score(np.argmax(total_y, axis=1), total_predicted_y, average='macro')
            auc= roc_auc_score(total_y, total_output)
            
            # auc = batch_auc / len(dataloader)
            # f1 = batch_f1 / len(dataloader)
            report = classification_report(np.argmax(total_y, axis=1), total_predicted_y, digits=4)
            loss = epoch_loss / sample_number
            return loss, auc, f1, report


    def train_base_model(self, data, adjs, iteration):
        best_auc_val = 0
        optimizer = optim.Adam(self.base_model.parameters(), lr=self.args.lr, weight_decay=self.args.weight_decay)
        #scheduler = LambdaLR(optimizer, lr_lambda=lambda epoch: 0.95 ** epoch)
        device = self.device
        g = dgl.DGLGraph()
        for i, adj in enumerate(adjs+[scipy.sparse.eye(adjs[0].shape[0])]):
            rows, cols = adj.nonzero()
            e_type = i * torch.ones(rows.shape[0],1)
            g = dgl.add_edges(g, rows, cols, {'e': e_type})
        print(g)

        # dataloader
        graph_dataloader = dgl.dataloading.NodeDataLoader(
            g, np.arange(self.num_node), self.sampler,
            batch_size=1024,
            shuffle=False,
            drop_last=False,
            num_workers=4)

        train_dataloader = dgl.dataloading.NodeDataLoader(
            g, data.idx_train, self.sampler,
            batch_size=1024,
            shuffle=True,
            drop_last=False,
            num_workers=4)

        val_dataloader = dgl.dataloading.NodeDataLoader(
            g, data.idx_val, self.sampler,
            batch_size=1024,
            shuffle=True,
            drop_last=False,
            num_workers=4)

        t = time.time()
        f1 = []
        auc = []
        loss = []
        train_f1 = []
        train_auc = []
        train_loss = []
        early_stopping = EarlyStopping(patience=self.args.patience, verbose=True, save_path='checkpoint/checkpoint_{}_{}.pt'.format(self.args.dataset, self.args.num_layers))
        for epoch in range(self.args.epoch):

            self.base_model.train()
            optimizer.zero_grad()

            for input_nodes, output_nodes, blocks in train_dataloader:
                blocks = [block.to(device) for block in blocks]
                hs = self.base_model(blocks, data.x, input_nodes)
                output = hs[-1]

                loss_train = F.nll_loss(output, data.y[output_nodes])
                optimizer.zero_grad()
                
                loss_train.backward()
                optimizer.step()
                #scheduler.step()
           
            loss_train, auc_train, f1_train, _ = self.evaluate(data.x, data.y, self.base_model, train_dataloader, device)
            loss_val, auc_val, f1_val, report = self.evaluate(data.x, data.y, self.base_model, val_dataloader, device)
            loss.append(loss_val)
            auc.append(auc_val)
            f1.append(f1_val)
            train_loss.append(loss_train)
            train_auc.append(auc_train)
            train_f1.append(f1_train)
            #acc_train = compute_accuracy(output, data.y[output_nodes])
            print('Epoch {:04d}'.format(epoch+1),
                    'loss_train:{:.4f}'.format(loss_train),
                    'auc_train:{:.4f}'.format(auc_train),
                    'f1_train:{:.4f}'.format(f1_train),
                    'loss_val:{:.4f}'.format(loss_val),
                    'auc_val:{:.4f}'.format(auc_val),
                    'f1_val:{:.4f}'.format(f1_val),
                    'time:{:.4f}s'.format(time.time()-t))
            #print(report)
            # evaluate valset performance (deactivate dropout)
            if auc_val > best_auc_val:
                best_auc_val = auc_val
                if auc_val > self.best_auc_val:
                    self.best_auc_val = auc_val
                    self.best_graph = adjs
                    # acquire better embeddings
                    hidden_output = []

                    output = []
                    with torch.no_grad():                 
                        for input_nodes, output_nodes, blocks in graph_dataloader:
                            blocks = [block.to(device) for block in blocks]
                            hs = self.base_model(blocks, data.x, input_nodes)
                            hidden_output.append(hs[0][:len(output_nodes)])
                            output.append(hs[-1][:len(output_nodes)])
                    self.hidden_output = torch.cat(hidden_output)
                    self.output = torch.cat(output)
                    self.weights = deepcopy(self.base_model.state_dict())
                    if self.args.debug:
                        print('=== Saving current graph/base_model, best_auc_val:%.4f' % self.best_auc_val.item())
            
            early_stopping(loss_val, self.base_model)
            if early_stopping.early_stop:
                print('Early stopping!')
                break

        print('Iteration {:04d}'.format(iteration),
            'auc_val:{:.4f}'.format(best_auc_val.item()))
        return loss, auc, f1, g, train_loss, train_auc, train_f1

    def test(self, data, g):
        device = self.device
        """`
        Evaluate the performance on testset.
        """

        # sampler =  self.sampler = dgl.dataloading.MultiLayerFullNeighborSampler(2)
        test_dataloader = dgl.dataloading.NodeDataLoader(
            g, data.idx_val, self.sampler,
            batch_size=1024,
            shuffle=False,
            drop_last=False,
            num_workers=4)
        
        print("=== Testing ===")
        print("Picking the best model according to validation performance")
        
        self.base_model.load_state_dict(self.weights)
        self.base_model.eval()

        loss_test, auc_test, f1_test, report = self.evaluate(data.x, data.y, self.base_model, test_dataloader, device=device)
        # total_output = []
        # total_predicted_y = []
        # total_y = []
        # with torch.no_grad():
        #     for input_nodes, output_nodes, blocks in test_dataloader:
        #             blocks = [block.to(device) for block in blocks]
        #             hs = self.base_model(blocks, data.x, input_nodes)
        #             output = hs[-1]
        #             loss_test = F.nll_loss(output, data.y[output_nodes])
        #             total_output.append(torch.exp(output).cpu().numpy())
        #             total_predicted_y.append(output.max(1)[1].cpu().numpy())
        #             total_y.append(F.one_hot(data.y[output_nodes],len(data.y.unique())).cpu().numpy())
        # hidden_output, output = self.base_model(data.x, self.best_graph)
        # loss_test = F.nll_loss(output[data.idx_val], data.y[data.idx_val])
        # f1_test = f1_score(np.argmax(total_y, axis=1), total_predicted_y, average='macro')
        # auc_test= roc_auc_score(total_y, total_output)
        # report = classification_report(np.argmax(total_y, axis=1), total_predicted_y, digits=4)

        print("Testset results: ",
            "loss={:.4f}".format(loss_test),
            "auc={:.4f}".format(auc_test),
            "f1={:.4f}".format(f1_test))
        
        print("Testset Report: \n",
              report)
"""
Provide adjacency matrix estimation implementation based on the Expectation-Maximization(EM) algorithm.
Parameters
----------
E:
    The actual observed number of edges between every pair of nodes (numpy.array)
"""
class EstimateAdj():
    def __init__(self, data):
        self.num_class = data.num_class
        self.num_node = 1200
        self.idx_train = data.idx_train
        self.label = data.y.cpu().numpy()
        self.output = None
        self.iterations = 0

        self.homophilies = data.homophilies

    def reset_obs(self):
        self.N = 0
        self.E = np.zeros((self.num_node, self.num_node), dtype=np.int64)

    def update_obs(self, output):
        self.E += output
        self.N += 1

    def revise_pred(self):
        for j in range(len(self.idx_train)):
            self.output[self.idx_train[j]] = self.label[self.idx_train[j]]

    def E_step(self, Q):
        """
        Run the Expectation(E) step of the EM algorithm.
        Parameters
        ----------
        Q:
            The current estimation that each edge is actually present (numpy.array)
        
        Returns
        ----------
        alpha:
            The estimation of true-positive rate (float)
        beta：
            The estimation of false-positive rate (float)
        O:
            The estimation of network model parameters (numpy.array)
        """
        # Temporary variables to hold the numerators and denominators of alpha and beta
        an = Q * self.E
        an = np.triu(an, 1).sum()
        bn = (1 - Q) * self.E
        bn = np.triu(bn, 1).sum()
        ad = Q * self.N
        ad = np.triu(ad, 1).sum()
        bd = (1 - Q) * self.N
        bd = np.triu(bd, 1).sum()

        # Calculate alpha, beta
        alpha = an * 1. / (ad)
        beta = bn * 1. / (bd)

        O = np.zeros((self.num_class, self.num_class))

        n = []
        counter = Counter(self.output)
        for i in range(self.num_class):
            n.append(counter[i])

        a = self.output.repeat(self.num_node).reshape(self.num_node, -1)
        for j in range(self.num_class):
            c = (a == j)
            for i in range(j + 1):
                b = (a == i)
                O[i,j] = np.triu((b&c.T) * Q, 1).sum()
                if i == j:
                    O[j,j] = 2. / (n[j] * (n[j] - 1)) * O[j,j]
                else:
                    O[i,j] = 1. / (n[i] * n[j]) * O[i,j]
        return (alpha, beta, O)

    def M_step(self, alpha, beta, O):
        """
        Run the Maximization(M) step of the EM algorithm.
        """
        O += O.T - np.diag(O.diagonal())

        row = self.output.repeat(self.num_node)
        col = np.tile(self.output, self.num_node)
        tmp = O[row,col].reshape(self.num_node, -1)

        p1 = tmp * np.power(alpha, self.E) * np.power(1 - alpha, self.N - self.E)
        p2 = (1 - tmp) * np.power(beta, self.E) * np.power(1 - beta, self.N - self.E)
        Q = p1 * 1. / (p1 + p2 * 1.)
        return Q

    def EM(self, homophily, adj, output, tolerance=.000001):
        """
        Run the complete EM algorithm.
        Parameters
        ----------
        tolerance:
            Determine the tolerance in the variantions of alpha, beta and O, which is acceptable to stop iterating (float)
        seed:
            seed for np.random.seed (int)

        Returns
        ----------
        iterations:
            The number of iterations to achieve the tolerance on the parameters (int)
        """
        # Record previous values to confirm convergence
        alpha_p = 0
        beta_p = 0

        self.output = output
        self.revise_pred()

        # Do an initial E-step with random alpha, beta and O
        # Beta must be smaller than alpha
        beta, alpha = np.sort(np.random.rand(2))
        O = np.triu(np.random.rand(self.num_class, self.num_class))
        
        # Calculate initial Q
        Q = self.M_step(alpha, beta, O)

        while abs(alpha_p - alpha) > tolerance or abs(beta_p - beta) > tolerance:
            alpha_p = alpha
            beta_p = beta
            alpha, beta, O = self.E_step(Q)
            Q = self.M_step(alpha, beta, O)
            self.iterations += 1

        if homophily > 0.5:
            Q += adj
        return (alpha, beta, O, Q, self.iterations)
