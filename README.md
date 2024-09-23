# ReTrial

## Environment Settings

* python == 3.8.18
* torch == 1.6.0
* pcapplusplus == 21.0.5



## Parameter Settings

- k: k of knn graph
- threshold: threshold for adjacency matrix
- tolerance: tolerance to stop EM algorithm
- iter: number of iterations to train the GEN
- base: backbone GNNs
- seed: random seed
- lr: learning rate
- weight_decay: weight decay (L2 loss on parameters)
- hidden: embedding dimension
- dropout: dropout rate
- activation: activation function selection
- dataset: str in ['CTU', 'MTA']
- testset: str in ['CTU', 'MTA_test']
- epoch: number of epochs to train the base model



## Basic Usage

~~~
./GetFeatureTool -r $PcapDir$ -o $OutputFile$ -d $DropPacketRate$

./GetFeature -r data/raw/ctu_normal/ -o data/processed/ctu_normal.csv -d 0

python process.py

cd GEN/code/

nohup python train.py > ../log/test.log 2>&1 &
~~~
