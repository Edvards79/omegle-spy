# omegle-spy
Distributed system to Downlaod random people's Omegle chats
## How it works
Omegle stores chat logs publicly at http://l.omegle.com/<key>.png, where key is a padded hex number with 5-10 digits (e.g. http://l.omegle.com/00000.png). Omegle-spy Master constantly generates keys and downloads images of chats and stores them in a pool. Worker then requests a batch of these images and converts them to text format and sends them back to the master, where it saves these chat logs. Unlimited number of workers can connect to a single master.
## How to use
Master and worker and meant to be installed on seperate machines for performance gains, but can also run on the same PC.
##### Installation
```
git clone https://github.com/Edvards79/omegle-spy.git
cd omegle-spy/master
pip install -r requirements.txt
cd ../worker
pip install -r requirements.txt
```
##### Configuration
By default it is configured to run on the localhost. That can be changed in `config.ini` files.
