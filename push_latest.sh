# Run from dfs-PLK/

docker build -t storagenode -f storagenode/Dockerfile .
docker tag storagenode fenchelfen/storagenode:amazon
docker push fenchelfen/storagenode:amazon

docker build -t namenode -f namenode/Dockerfile .
docker tag namenode fenchelfen/namenode:amazon
docker push fenchelfen/namenode:amazon
