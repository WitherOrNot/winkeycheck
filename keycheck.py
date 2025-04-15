from base64 import b64encode
from binascii import unhexlify
from random import randbytes
from licensing_stuff.keycutter import ProductKeyDecoder
from licensing_stuff.pkeyconfig import PKeyConfig
from requests import post
import datetime
from html import escape
from uuid import uuid4
import xml.etree.ElementTree as ET
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# construct this with elementtree if you REALLY care
REQ_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <soap:Body>
        <RequestSecurityToken
            xmlns="http://schemas.xmlsoap.org/ws/2004/04/security/trust">
            <TokenType>PKC</TokenType>
            <RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType>
            <UseKey>
                <Values xsi:nil="1"/>
            </UseKey>
            <Claims>
                <Values
                    xmlns:q1="http://schemas.xmlsoap.org/ws/2004/04/security/trust" soapenc:arrayType="q1:TokenEntry[3]">
                    <TokenEntry>
                        <Name>ProductKey</Name>
                        <Value>{pkey}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKeyType</Name>
                        <Value>msft:rm/algorithm/pkey/2009</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKeyActConfigId</Name>
                        <Value>{act_config_id}</Value>
                    </TokenEntry>
                </Values>
            </Claims>
        </RequestSecurityToken>
    </soap:Body>
</soap:Envelope>
"""

def encode_key_data(group, serial, security, upgrade):
    act_hash = upgrade & 1
    act_hash |= (serial & ((1 << 30) - 1)) << 1
    act_hash |= (group & ((1 << 20) - 1)) << 31
    act_hash |= (security & ((1 << 53) - 1)) << 51
    
    return b64encode(act_hash.to_bytes(13, "little")).decode()

def query_key(pkey, pkc):
    if "N" not in pkey:
        return "N/A", "Product key is not PKEY2009.", False
    
    pkey_data = ProductKeyDecoder(pkey)
    
    try:
        skuid = pkc.config_for_group(pkey_data.group).config_id[1:-1]
    except:
        return "", "Product key not compatible with provided pkeyconfig", False
    
    act_data = encode_key_data(pkey_data.group, pkey_data.serial, pkey_data.security, pkey_data.upgrade)
    act_config_id = f"msft2009:{skuid}&{act_data}"
    
    req_data = {
        "pkey": pkey,
        "act_config_id": escape(act_config_id)
    }
    payload = REQ_TEMPLATE.format(**req_data)
    
    resp = post(f"https://activation.sls.microsoft.com/slpkc/SLCertifyProduct.asmx", data=payload, verify=False, headers={
        "Accept": "text/*",
        "Content-Type": "text/xml; charset=utf-8",
        "User-Agent": "SLSSoapClient",
        "SOAPAction": "http://microsoft.com/SL/ProductCertificationService/IssueToken"
    })
    
    data = ET.fromstring(resp.text)
    
    if data.find("./{*}Body/{*}Fault") is None:
        return "0x0", "", True
    else:
        return data.find("./{*}Body/{*}Fault/{*}detail/{*}HRESULT").text, data.find("./{*}Body/{*}Fault/{*}detail/{*}Messages/{*}Message").text, False

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Product key checker")
    sp = p.add_subparsers(title="Modes", dest="mode")
    
    pkp = sp.add_parser("pkey", help="test single product key")
    pkp.add_argument("product_key", type=str, help="Product key")
    
    batchp = sp.add_parser("batch", help="test multiple product keys in a file")
    batchp.add_argument("input_file", type=argparse.FileType("r", encoding="utf-8"), help="input file with one product key per line")
    batchp.add_argument("--out", "-o", type=argparse.FileType("w", encoding="utf-8"), nargs="?", default="out.txt", help="output path of key checking log")
    
    p.add_argument("--pkeyconfig", "-p", type=argparse.FileType("r", encoding="utf-8-sig"), nargs="?", default="pkeyconfig.xrm-ms", help="Required pkeyconfig.xrm-ms file")
    
    args = p.parse_args()
    
    pkc = PKeyConfig(ET.fromstring(args.pkeyconfig.read()))
    
    if args.mode == "pkey":
        pkey = args.product_key
        
        response, message, success = query_key(pkey, pkc)
        
        print(f"Key: {pkey}")
        
        if success:
            print(f"Status: Online-valid")
        else:
            print(f"Status: Invalid")
            print(f"Error: {response}")
            print(f"Message: {message}")
    elif args.mode == "batch":
        valid_keys = []
        total = 0
        
        while True:
            pkey = args.input_file.readline().strip()
            
            if pkey == "":
                break
            
            response, message, success = query_key(pkey, pkc)
            args.out.write(f"Key: {pkey}\n")
            
            if success:
                args.out.write(f"Status: Online-valid\n")
                valid_keys.append(pkey)
            else:
                args.out.write(f"Status: Invalid\n")
                args.out.write(f"Error: {response}\n")
                args.out.write(f"Message: {message}\n")
            
            args.out.write("\n")
            total += 1
        
        print(f"{len(valid_keys)}/{total} keys are valid")
        args.out.write(f"{len(valid_keys)}/{total} keys are valid\n")
        
        if valid_keys:
            print(f"Valid keys:")
            
            for vkey in valid_keys:
                print(vkey)
    else:
        p.print_help()
