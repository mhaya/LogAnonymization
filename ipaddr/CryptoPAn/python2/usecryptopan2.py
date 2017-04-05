
import sys
sys.path.append(".")
import array
import cryptopan

argvs = sys.argv
 
f = open(argvs[1])
line = f.readline() 

key = array.array('B',range(32))
obj = cryptopan2.CryptoPAn(key)

while line:
    tmp = line.split(",")
    tmp[1] = str(obj.anonymize(int(tmp[1]),4,32))
    tmp[2] = str(obj.anonymize(int(tmp[2]),4,32))
    print(tmp[0]+","+tmp[1]+","+tmp[2]+","+tmp[3]+","+tmp[4]+","+tmp[5].strip())
    line = f.readline() 
    
f.close()
