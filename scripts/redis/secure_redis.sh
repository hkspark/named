redis_conf=/etc/redis/redis.conf

cp $redis_conf ${redis_conf}.bak

sed -i "s/0.0.0.0/127.0.0.1/" $redis_conf
sed -i "s/protected-mode no/protected-mode yes/" $redis_conf 
sed -i "s/enable-protected-configs yes/enable-protected-configs no/" $redis_conf
sed -i "s/# rename-command/rename-command/" $redis_conf

for command in EVAL EVALSHA SCRIPT; do
    if ! grep -q "rename-command $command" $redis_conf; then
        echo "rename-command $command \"\"" | tee -a $redis_conf
    fi
done

read -sp "Enter a Password: " password
if ! grep -q "requirepass" $redis_conf; then
    echo "requirepass $password" >> $redis_conf
fi


systemctl restart redis-server
