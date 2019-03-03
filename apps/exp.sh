# The simple experiment with the vanila client (without tls-ec)
# The first argument the origin server's IP address
# The second argument the root directory of the logs
# The third argument is the location of the origin server (kor / jpn / usa)

export LD_LIBRARY_PATH=${HOME}/edge/boringssl/lib64_x86_64

mkdir -p $2
CURR=`date +%Y-%m-%d_%s`
DIRECTORY=$2/${CURR}
mkdir -p ${DIRECTORY}/1
mkdir -p ${DIRECTORY}/2
mkdir -p ${DIRECTORY}/3
mkdir -p ${DIRECTORY}/4

# Client - RPi3 (Simple AP) - Origin
for i in {1..100}
do
  ./vanila $1 5554 1 ${DIRECTORY}/1/simple_ap_${3}_${i}.csv
done

# Client - RPi3 (Without TLS-EC) - Origin
for i in {1..100}
do
  ./vanila $1 5555 1 ${DIRECTORY}/2/vanila_${3}_${i}.csv
done

# Client - RPi3 (With TLS-EC) - Origin
for i in {1..100}
do
  ./client $1 5555 1 ${DIRECTORY}/3/tlsec_${3}_${i}.csv
done

# Client - RPi3 (With TLS-EC + Overclock) - Origin
for i in {1..100}
do
  ./client $1 5555 1 ${DIRECTORY}/4/overclock_${3}_${i}.csv
done

#./client 108.177.125.105 5555 1 test
