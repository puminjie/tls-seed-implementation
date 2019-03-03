# The simple experiment with the vanila client (without tls-ec)
# The first argument the origin server's IP address
# The second argument the root directory of the logs
# The third argument is the location of the origin server (kor / jpn / usa)

export LD_LIBRARY_PATH=${HOME}/edge/boringssl/lib64_x86_64

mkdir -p $2
CURR=`date +%Y-%m-%d_%s`
DIRECTORY=$2/${CURR}_vanila_${3}
mkdir -p ${DIRECTORY}

for i in {1..100}
do
  echo $i
  ./vanila $1 5555 1 ${DIRECTORY}/vanila_${3}_${i}.csv
  sleep 1
done
#./client 108.177.125.105 5555 1 test
