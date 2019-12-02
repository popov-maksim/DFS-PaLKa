service redis-server restart
cat /var/log/redis/redis-server.log
python3 src/storage_node.py &> new.log
