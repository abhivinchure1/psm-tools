import os
import pandas as pd
import time
from  os import path
from apigroups.client.apis import MonitoringV1Api, ObjstoreV1Api
from apigroups.client import configuration, api_client
from apigroups.client.models import MonitoringArchiveRequest, ApiObjectMeta, MonitoringArchiveRequestSpec, MonitoringArchiveQuery, SearchTextRequirement
from utils.filesystem_utils import saveBinary
import warnings
from dateutil.parser import parse
import argparse 

#Author: Abhishek Vinchure
#Email abhishekv@pensando.io


#Provides the top contacted destinations
def get_top_contacted(data, name):
    top_contacted = pd.DataFrame()
    data1 = pd.DataFrame(data)
    top_contacted_dest = data1["dip"].value_counts()
    top_contacted["Top Contacted Destinations by Frequency"] = top_contacted_dest

    print(top_contacted.head(10), file=open(name, "a"))

#Provides Top talkers i.e. <source, destination> IPs (or workloads) by:
#Number of bytes transferred (sent, received, sent+received)
#Number of sessions (allowed, denied, allowed+denied)
def get_top_talkers(data, name):
    data1 = pd.DataFrame(data)
    unique_ip_pairs = data1[["sip","dip", "iflowbytes","rflowbytes", "act"]]
    unique_ip_pairs["total bytes"] = unique_ip_pairs["iflowbytes"] + unique_ip_pairs["rflowbytes"]
    unique_ip_pairs["unique IP pairs"] = "<" + unique_ip_pairs["sip"] + ", " + unique_ip_pairs["dip"] + ">" 
    unique_ip_pairs = unique_ip_pairs.sort_values(by = ["total bytes"], ascending = False).drop_duplicates(subset = ["sip", "dip"])
    unique_ip_pairs = unique_ip_pairs.drop(columns = ["sip", "dip", "iflowbytes", "rflowbytes"])
    unique_ip_pairs["unique IP pairs"] = unique_ip_pairs["unique IP pairs"] + " with " + unique_ip_pairs["total bytes"].astype(str) + " total bytes" 
    unique_ip_pairs = unique_ip_pairs.drop(columns = ["total bytes"]).rename(columns = {"unique IP pairs" : "Unique IP Pairs by Total Bytes Transferred"})
    unique_ip_pairs = unique_ip_pairs.iloc[1: , :]
    print(unique_ip_pairs.reset_index().head(10).drop(columns = "index"), file=open(name, "a"))
#Provide encryption posture per VPC i.e. its percentage of IPSec protected sessions.
def get_ipsec_percentage(data, name):
    data1 = pd.DataFrame(data)
    ipsec = data1["isipsecprotected"]
    count = 0
    for i in ipsec:
        if i == True:
            count += 1
    percentage = (count/(data1["isipsecprotected"].size))*100
    percentage = str(percentage)
    print("The percentage of ipsec protected sessions is", percentage, "out of a total of", data1["isipsecprotected"].size, "sessions" , file=open(name, "a"))
    
#Provide encryption posture per protocol.
def get_ipsec_percentage_by_protocol(data, name):
    protocols = pd.DataFrame(data)
    icmp_true = 0
    num_icmp = 0
    tcp_true = 0
    num_tcp = 0
    udp_true = 0
    num_udp = 0
    num_others = 0
    others_true = 0
    for i, row in protocols.iterrows():
        if row['proto'] == "ICMP":
            num_icmp += 1
            if row["isipsecprotected"] == True:
                icmp_true += 1
        if row['proto'] == "TCP":
            num_tcp += 1
            if row["isipsecprotected"] == True:
                tcp_true += 1
        if row['proto'] == "UDP":
            num_udp += 1
            if row["isipsecprotected"] == True:
                udp_true += 1
        if row['proto'] != "ICMP" and row['proto'] != "TCP" and row['proto'] != "UDP":
            num_others += 1
            if row["isipsecprotected"] == True:
                others_true += 1
    prop_icmp = (icmp_true/num_icmp) * 100
    prop_tcp = (tcp_true/num_tcp) * 100
    prop_udp = (udp_true/num_udp) * 100
    prop_others = (others_true/num_others) * 100

    print("The percentage of ipsec protected sessions matching ICMP protocol is", prop_icmp, "out of", num_icmp, "ICMP sessions", file=open(name, "a"))
    print("The percentage of ipsec protected sessions matching TCP protocol is", prop_tcp, "out of", num_tcp, "TCP sessions", file=open(name, "a"))
    print("The percentage of ipsec protected sessions matching UDP protocol is", prop_udp, "out of", num_udp, "UDP sessions", file=open(name, "a"))
    print("The percentage of ipsec protected sessions matching other protocols is", prop_others, "out of", num_others, "other sessions", file=open(name, "a"))

#Takes in the downloaded file and processes for data calculations using pandas
def enter_processing(file, name):
    data = pd.read_csv("temp.csv", names = ["svrf","dvrf","sip","dip","ts","sport","dport","proto","act","dir","ruleid","sessionid","sessionstate","icmptype","icmpid","icmpcode","appid","alg","iflowbytes","rflowbytes","count", "ipsecruleid", "vnid", "isipsecprotected"])
    
    print("***********************IPSEC PERCENTAGE BY SESSIONS***********************", file=open(name, "a"))
    get_ipsec_percentage(data, name)
    print("***********************IPSEC PERCENTAGE BY PROTOCOL***********************", file=open(name, "a"))
    get_ipsec_percentage_by_protocol(data, name)
    print("***********************TOP CONTACTED DESTINATIONS***********************", file=open(name, "a"))
    get_top_contacted(data, name)
    print("***********************TOP TALKERS***********************", file=open(name, "a"))
    get_top_talkers(data, name)

    

#Sends an archive req to PSM, gets the file and then downloads to local directory. Main processing is done here

def main(args, config):
    client = api_client.ApiClient(config)
    monitoring_api_instance = MonitoringV1Api(client)
    objstore_api_instance = ObjstoreV1Api(client)
 
    get_name = args.requestName
    #Example query - start time: '2021-07-21T01:00:00.00Z'
    #Example query - end time: '2021-07-21T23:59:59.00Z'
    get_start_time = args.startTime
    get_end_time = args.endTime
    name = get_name
    body = MonitoringArchiveRequest(
        meta = ApiObjectMeta(name=name),
        spec = MonitoringArchiveRequestSpec(
            query=MonitoringArchiveQuery(
                #'1970-01-01T00:00:00.00Z'
                end_time = parse(get_end_time),
                start_time= parse(get_start_time),
                tenants= ['default']
            ),
            type="firewalllogs",
        )
    )
    response = monitoring_api_instance.add_archive_request("default", body)
    # after request is ready
    time.sleep(15)
    response = monitoring_api_instance.get_archive_request("default",name)
    filename = response.status.uri.split("/")[-1]
    tenant = "default"
    namespace = response.status.uri.split("/")[-2]

    obj_response = objstore_api_instance.get_download_file(tenant, namespace, filename)

    download_path = "./temp.csv.gz"
    saveBinary(download_path, obj_response.data)


    if path.exists(download_path):
        os.system("gunzip temp.csv.gz")
        file = "temp.csv"

        enter_processing(file, args.fileName)
        print("Your traffic report can be found on", args.fileName, "in your local directory!")
    else:
        print("File does not exist")


parser = argparse.ArgumentParser()
parser.add_argument("-a", "--requestName", dest =  "requestName", metavar = '', required = True, help = 'name of archive request')
parser.add_argument("-s", "--startTime", dest =  "startTime", metavar = '', required = True, help = 'user can specify the start time for their query. Example format "2021-07-21T01:00:00.00Z"')
parser.add_argument("-e", "--endTime", dest =  "endTime", metavar = '', required = True, help = 'user can specify the end time for their query. Example format "2021-07-21T23:59:59.00Z"')
parser.add_argument("-f", "--fileName", dest =  "fileName", metavar = '', required = True, help = 'user can specify the file that they want the report to be on')
args = parser.parse_args() 
if __name__=="__main__":
    warnings.simplefilter("ignore")
    HOME = os.environ['HOME']
    configuration_main = configuration.Configuration(
    psm_config_path=HOME+"/.psm/config.json",
    interactive_mode=True
      
)
    configuration_main.verify_ssl = False   
    main(args, configuration_main)
