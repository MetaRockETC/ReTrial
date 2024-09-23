import pandas as pd
import torch
import os
from collections import Counter
from tqdm import tqdm
import numpy as np
from collections import Counter, defaultdict
from dtaidistance import dtw
from sklearn.preprocessing import StandardScaler
# from fastdtw import fastdtw
from scipy.spatial.distance import euclidean, jaccard
from sklearn.neighbors import kneighbors_graph
import warnings
import logging

warnings.simplefilter("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  - %(name)s - %(levelname)s - %(message)s",
    filename="./log/process_test.log",
    filemode="w",
)
logger = logging.getLogger(__name__)

edge_type = {
    "dstIPPort": 0,
    "Fingerprint": 1,
    "hostName": 2,
}

label_flag = {
    "CTU" : "/ctu_normal/",
    "CTU_test" : "/ctu_normal/",
    "CTU_d1" : "/ctu_normal_d1/",
    "CTU_d2" : "/ctu_normal_d2/",
    "CTU_d3" : "/ctu_normal_d3/",
    "CAMPUS_MTA" : "/campus_mta/",
    "CAMPUS_MTA_d1" : "/campus_mta_d1/",
    "CAMPUS_MTA_d2" : "/campus_mta_d2/",
    "CAMPUS_MTA_d3" : "/campus_mta_d3/",
}

label_flag_ustc = {
    "Shifu" : '0', 
    "Neris" : '1',
    "Htbot" : '2',
    "Tinba" : '3',
    "Nsis-ay" : '4',
    "Virut" : '5',
    "Zeus" : '6',
    "Miuref" : '7',
    "Geodo" : '8',
    "Cridex" : '9',
}
label_flag_ustc_bin = {
    "Weibo-1" : '0',
    "Weibo-2" : '0',
    "Weibo-3" : '0',
    "Weibo-4" : '0',
    "SMB-1" : '0',
    "SMB-2" : '0',
    "BitTorrent" : '0',
    "Facetime" : '0',
    "FTP" : '0',
    "Gmail" : '0',
    "MySQL" : '0',
    "Outlook" : '0',
    "Skype" : '0',
    "WorldOfWarcraft" : '0',
    "Shifu" : '1', 
    "Neris" : '1',
    "Htbot" : '1',
    "Tinba" : '1',
    "Nsis-ay" : '1',
    "Virut" : '1',
    "Zeus" : '1',
    "Miuref" : '1',
    "Geodo" : '1',
    "Cridex" : '1',
}

def create_file_dict(directory):
    file_dict = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_dict[file] = file_path
    return file_dict


def pdMerge(df1, df2, dataset):
    sampled_df1 = df1.sample(n=100, random_state=116, replace=False)
    sampled_df2 = df2.sample(n=100, random_state=116, replace=False)
    merged = pd.concat([sampled_df1, sampled_df2])
    output = f"data/sampled_{dataset}.csv"
    merged.to_csv(output, index=False)
    return output


def linkGenerateWrapper(func):
    def wrapper(path, dataset):
        logger.info("Strating link generation")
        func(path, dataset)
        logger.info("Link generation completed")

    return wrapper


def loopWrapper(func):
    def wrapper(df, f, key, type):
        logger.info(f"Strating generate {key} link")
        _, link_num, max_link, which_link = func(df, f, key, type)
        logger.info(
            f"generate {link_num} {key} links, maximum link is {max_link}, which is {which_link}"
        )
        return _, link_num, max_link, which_link

    return wrapper


def nodeFilter(path, dataset):
    logger.info(f"Starting process {dataset} dataset")
    df = pd.read_csv(path)
    filtered = pd.DataFrame()
    filtered = df[df.iloc[:, -1] != 0]
    dstIPPort = []
    fingerprints = []
    for ip, port in zip(filtered["dstIP"], filtered["dstPort"]):
        dstIPPort.append(ip + str(port))
    filtered.insert(6, "dstIPPort", dstIPPort)
    for ja3, ja3s in zip(filtered["JA3"], filtered["JA3S"]):
        dstIPPort.append(ja3 + ja3s)

    filtered.insert(7, "fingerprints", fingerprints)
    return filtered


def nodeGenerate(path, dataset):
    logger.info("Strating node generation")
    df = pd.read_csv(path)
    logger.info(f"total number of nodes :{len(df)}")
    if 'USTC' not in dataset:
        attr = np.concatenate([df.iloc[:, 8:15], df.iloc[:, 17:]], axis=1)
        scaler = StandardScaler()
        scaled_attr = scaler.fit_transform(attr)
        row_strings = [",".join(map(str, row)) for row in scaled_attr]
    else:
        attr = np.array(df.iloc[:, 32:-1])
        row_strings = [",".join(map(str, row)) for row in attr]
    df = pd.DataFrame(row_strings)
    df.insert(0, "name", "name")
    df.insert(1, "0", 0)
    df.to_csv(f"./GEN/data/{dataset}/node.dat", sep="\t", header=False)
    logger.info("Node generation completed")


@linkGenerateWrapper
def linkGenerate(path, dataset):
    df = pd.read_csv(path)
    with open(f"./GEN/data/{dataset}/link.dat", "w") as f:
        if 'USTC' not in dataset:
            for key in edge_type.keys():
                link, link_num, max_link, which_link = linkCampareloop(
                    df, f, key=key, type=edge_type[key]
                )
        else:
            link, link_num, max_link, which_link = linkCampareloop(
                    df, f, key='dstIPPort', type=edge_type['dstIPPort']
                )
        
        # dtw jaccard
        logger.info("Strating get recordLayer")
        data = []
        for _, row in df.iterrows():
            if 'USTC' not in dataset:
                recordLayer = row.iloc[-20:].values
            else:
                recordLayer = row.iloc[12:32].values
            data.append(recordLayer)
        logger.info("Got recordLayer")
        
        logger.info("Strating compute knn-dtw graph")
        _dtw = kneighbors_graph(
            data, n_neighbors=3, mode="connectivity", metric=DTW, n_jobs=-1
        )
        logger.info("knn-dtw graph done")
        
        logger.info("Strating compute knn-jaccard graph")
        _jaccard = kneighbors_graph(
            data, n_neighbors=3, mode="connectivity", metric=jaccard, n_jobs=-1
        )
        logger.info("knn-jaccard graph done")
        
        logger.info(f"Strating generate DTW link")
        for i, node in enumerate(_dtw.toarray()):
            for j, neighbor in enumerate(node):
                if neighbor == 1.0:
                    dtw_link = [i, j, 3, 1.0]
                    converted = [str(element) for element in dtw_link]
                    dtw_link = "\t".join(converted)
                    f.write(dtw_link + "\n")

        logger.info(f"Strating generate Jaccard link")
        for i, node in enumerate(_jaccard.toarray()):
            for j, neighbor in enumerate(node):
                if neighbor == 1.0:
                    jaccard_link = [i, j, 4, 1.0]
                    converted = [str(element) for element in jaccard_link]
                    jaccard_link = "\t".join(converted)
                    f.write(jaccard_link + "\n")


def DTW(a, b):
    distance = dtw.distance_fast(a, b, use_pruning=True)
    return distance


@loopWrapper
def linkCampareloop(df, f, key, type):
    link_num = 1
    max_link = 0
    which_link = None
    link = pd.DataFrame()
    for i in range(len(df)):
        value = df.loc[i, key]
        indexes = df.index[df[f"{key}"] == value].tolist()
        if indexes:
            if len(indexes) > max_link:
                max_link = len(indexes)
                which_link = value
            for j in indexes:
                if j == i:
                    continue
                link = [i, j, type, 1.0]
                converted = [str(element) for element in link]
                link = "\t".join(converted)
                f.write(link + "\n")
                link_num += 1
    return link, link_num, max_link, which_link


def labelGenerate(path, dataset):
    if 'USTC' not in dataset:
        df = pd.read_csv(path)
        benign, malicious = df.iloc[:100], df.iloc[100:]
        train_benign, train_malicious = benign.sample(frac=0.7, replace=False, random_state=116), malicious.sample(frac=0.7, replace=False, random_state=116)
        train = pd.concat([train_benign, train_malicious])
        test = df.drop(train.index)
        label_train = pd.DataFrame({
            'index': train.index,
            'name': 'name',
            'type': 0,
            'label': train['fileName'].apply(lambda x: 0 if label_flag[dataset] in x else 1)
        })
        label_test = pd.DataFrame({
            'index': test.index,
            'name': 'name',
            'type': 0,
            'label': test['fileName'].apply(lambda x: 0 if label_flag[dataset] in x else 1)
        })
    else:
        df = pd.read_csv(path)
        train = df.sample(frac=0.7, replace=False, random_state=116)
        test = df.drop(train.index)
        label_train = pd.DataFrame({
            'index': train.index,
            'name': 'name',
            'type': 0,
            'label': train['file'].apply(lambda x: label_flag_ustc_bin[x.split('/')[-1].split('.')[0]])
        })
        label_test = pd.DataFrame({
            'index': test.index,
            'name': 'name',
            'type': 0,
            'label': test['file'].apply(lambda x: label_flag_ustc_bin[x.split('/')[-1].split('.')[0]])
        })
    label_train.to_csv(f"./GEN/data/{dataset}/label.dat", index=False, header=None, sep='\t')
    label_test.to_csv(f"./GEN/data/{dataset}/label.dat.test", index=False, header=None, sep='\t')

if __name__ == "__main__":
    datasets = [
        "CTU",
        "CTU_test",
        #"CAMPUS_MTA",
        #"CTU_d1",
        #"CTU_d2",
        #"CTU_d3",
        #"CAMPUS_MTA_d1",
        #"CAMPUS_MTA_d2",
        #"CAMPUS_MTA_d3",
        #"USTC",
        #"USTC_d1",
        #"USTC_d2",
        #"USTC_d3",
        #"USTC_bin",
        #"USTC_bin_d1",
        #"USTC_bin_d2",
        #"USTC_bin_d3",
        #"CTU_1800",
        #"CAMPUS_MTA_1800",
        #"USTC_1800",
        #"USTC_bin_1800"
    ]
    path_dict = create_file_dict("./data/processed")
    for dataset in datasets:
        directory = "./GEN/data/" + dataset
        if not os.path.exists(directory):
            os.makedirs(directory)
        if dataset in ["CTU", "CTU_test""]:
            benign, mal = path_dict[f"ctu_normal.csv"], path_dict[f"ctu.csv"]
            output = pdMerge(
                nodeFilter(benign, dataset), nodeFilter(mal, dataset), dataset
            )
            nodeGenerate(output, dataset)
            linkGenerate(output, dataset)
            labelGenerate(output, dataset)
            
        elif dataset in ["CAMPUS_MTA", "CAMPUS_MTA_d1", "CAMPUS_MTA_d2", "CAMPUS_MTA_d3"]:
            if "d1" in dataset:
                benign, mal = path_dict["campus_d1.csv"], path_dict["mta_d1.csv"]
            elif "d2" in dataset:
                benign, mal = path_dict["campus_d2.csv"], path_dict["mta_d2.csv"]
            elif "d3" in dataset:
                benign, mal = path_dict["campus_d3.csv"], path_dict["mta_d3.csv"]
            else:
                benign, mal = path_dict["campus.csv"], path_dict["mta.csv"]
            output = pdMerge(
                nodeFilter(benign, dataset), nodeFilter(mal, dataset), dataset
            )
            nodeGenerate(output, dataset)
            linkGenerate(output, dataset)
            labelGenerate(output, dataset)
            