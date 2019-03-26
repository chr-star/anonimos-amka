#'Use: python anonymizer.py -i <inputfile> -o <outputfile> -d <dictionary file> -c <comma separated column list>'

import pandas as pd
import numpy as np
import hashlib
import json
import sys
import string
import argparse
from secrets import token_hex

if sys.version_info < (3, 6):
   import sha3

def anonymize(inFile, outFile, cols, dict_file):
   df=pd.read_csv(inFile)
   pat_dict={}
   inv_pat_dict={}
   for pid in df.PatID.unique():
       hashedpid=hashlib.sha3_512(pid.encode()).hexdigest()
       pat_dict[hashedpid]=pid
       inv_pat_dict[pid]=hashedpid

   doc_dict={}
   inv_doc_dict={}
   for did in df.DocID.unique():
       hasheddid=hashlib.sha3_512(did.encode()).hexdigest()
       doc_dict[hasheddid]=did
       inv_doc_dict[did]=hasheddid

   df.PatID=df.PatID.apply(lambda x: hashlib.sha3_512(x.encode()).hexdigest())
   df.DocID=df.DocID.apply(lambda x: hashlib.sha3_512(x.encode()).hexdigest())

   df.to_csv(outFile, index=False)

   all_dicts={}
   all_dicts['patients']=pat_dict
   all_dicts['inv_patients']=inv_pat_dict
   all_dicts['doctors']=doc_dict
   all_dicts['inv_doctors']=inv_doc_dict

   with open(dict_file, 'w') as f:
       json.dump(all_dicts, f)


def anonymize_with_secret(inFile, outFile, cols, dict_file, secret):
   df=pd.read_csv(inFile)
   pat_dict={}
   inv_pat_dict={}
   for pid in df.PatID.unique():
       spid=secret+str(pid)
       hashedpid=hashlib.sha3_512(spid.encode()).hexdigest()
       pat_dict[hashedpid]=pid
       inv_pat_dict[pid]=hashedpid

   doc_dict={}
   inv_doc_dict={}
   for did in df.DocID.unique():
       sdid=secret+str(did)
       hasheddid=hashlib.sha3_512(sdid.encode()).hexdigest()
       doc_dict[hasheddid]=did
       inv_doc_dict[did]=hasheddid

   df.PatID=df.PatID.apply(lambda x: hashlib.sha3_512((secret+str(x)).encode()).hexdigest())
   df.DocID=df.DocID.apply(lambda x: hashlib.sha3_512((secret+str(x)).encode()).hexdigest())

   df.to_csv(outFile, index=False)

   all_dicts={}
   all_dicts['secret']=secret
   all_dicts['patients']=pat_dict
   all_dicts['inv_patients']=inv_pat_dict
   all_dicts['doctors']=doc_dict
   all_dicts['inv_doctors']=inv_doc_dict

   with open(dict_file, 'w') as f:
       json.dump(all_dicts, f)



def main():
   #orisma tou argparse ws ap
   ap = argparse.ArgumentParser(description = "This a script to ")

   #orizontai ta arguments to argparse
   ap.add_argument("-i", "--input", required=True, help="Path to input file")
   ap.add_argument("-o", "--output", required=True, help="Path to output file")
   ap.add_argument("-d", "--dfile", required=True, help="Path to dictionary file")
   ap.add_argument("-c", "--cols", required=True, help="comma seperated values for column lists")

   args = ap.parse_args()

   #columns = arg.split(',')
   secret=token_hex(64)
   anonymize_with_secret(args.input, args.output, args.cols, args.dfile, secret)

if __name__ == "__main__":
   main()
