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

PUB_LICENSE = '<?xml version="1.0" encoding="utf-8"?><rg:licenseGroup xmlns:rg="urn:mpeg:mpeg21:2003:01-REL-R-NS"><r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS" licenseId="{add96a1a-5ae7-425d-935d-3b6effd43a92}" xmlns:sx="urn:mpeg:mpeg21:2003:01-REL-SX-NS" xmlns:mx="urn:mpeg:mpeg21:2003:01-REL-MX-NS" xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2" xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><r:title>Windows(R) Publishing License (Public)</r:title><r:grant><r:forAll varName="productId"><r:anXmlExpression>/sl:productId/sl:pid</r:anXmlExpression></r:forAll><r:forAll varName="binding"></r:forAll><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName="application"><r:anXmlExpression>editionId[@value="" or @value="EnterpriseS"]</r:anXmlExpression></r:forAll><r:forAll varName="appid"><r:propertyPossessor><tm:application varRef="application"/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:propertyPossessor></r:forAll><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>17FgQIuX2S7YIVn8PIeN+qANo4/TUbV8CH5TzbXwmWo4WVI4npVqI4NNhRVsP0ICgMpql1jgAm75dZDBPTzRTCj+Ni0DXIvk6Whlo/ClK/fpZUO3ORQ9VmBE3cXeQQAehgVlUUIzOmG4EeP1i91PCGf5O7I4ayYS2FeQUj+6hyk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><sl:runSoftware/><sl:appId varRef="appid"/><r:allConditions><r:allConditions><sl:productPolicies xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2"><sl:priority>500</sl:priority><sl:policyInt name="Security-SPP-Reserved-Store-Token-Required" attributes="override-only">0</sl:policyInt><sl:policyInt name="Kernel-NonGenuineNotificationType" attributes="override-only">2</sl:policyInt><sl:policyStr name="Security-SPP-Reserved-Windows-Version-V2" attributes="override-only">10.0</sl:policyStr><sl:policyInt name="Security-SPP-WriteWauMarker">1</sl:policyInt><sl:policyStr name="Security-SPP-Reserved-Family" attributes="override-only">EnterpriseS</sl:policyStr></sl:productPolicies><sl:proxyExecutionKey xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2"></sl:proxyExecutionKey><sl:externalValidator xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2"><sl:type>msft:sl/externalValidator/generic</sl:type><sl:data Algorithm="msft:rm/algorithm/flags/1.0">DAAAAAEAAAAFAAAA</sl:data></sl:externalValidator></r:allConditions><mx:renderer><sl:binding varRef="binding"/><sl:productId varRef="productId"/></mx:renderer></r:allConditions></r:grant><r:allConditions><sl:businessRules xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2"></sl:businessRules></r:allConditions></r:grant><r:issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.microsoft.com/xrml/lwc14n"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference><Transforms><Transform Algorithm="urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform"/><Transform Algorithm="http://www.microsoft.com/xrml/lwc14n"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>ivMENCvkqJvb41ZNgue9GpfjWDI=</DigestValue></Reference></SignedInfo><SignatureValue>exwwz6jLpaJ0u1KEEDOCFDXwUAEwI8jUpcamyUkFyqbuYBVCinoihNCtgZAvXcQ+N35MNSXLKXlXpttYE0M2O8dZWR/Frxt38RWxCQj/4heGIwPqQJ7KUZtOdBvytjA6XSvv6uqq1aNAaSWyb7l7jkXc14ycfvxILMVqYdmkIw6BQNZ8/R/anl4VQjAeBdg/+DrcxoHvVT1pVe5PJkrPFRi2B7+0P0oWBljataVjwqDnxYfcJq7lkErHsl78sH2rWPOP/carliYgFNTyEc8437MN5xkNJmeQpsAyTpfE+H7r74WXsk59aU7NoUxteOBRzUNZCgCp2Trr09awd5k2Pg==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2016-01-01T00:00:00Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS"><tm:infoTables xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><tm:infoList tag="#global"><tm:infoStr name="licenseType">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name="licenseVersion">2.0</tm:infoStr><tm:infoStr name="licensorUrl">http://licensing.microsoft.com</tm:infoStr><tm:infoStr name="licenseCategory">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name="productSkuId">{cce9d2de-98ee-4ce2-8113-222620c64a27}</tm:infoStr><tm:infoStr name="privateCertificateId">{38c2c1c2-f73e-4fb2-bb44-d8a52fdcbc51}</tm:infoStr><tm:infoStr name="applicationId">{55c92734-d682-4d71-983e-d6ec3f16059f}</tm:infoStr><tm:infoStr name="productName">Windows(R), EnterpriseS edition</tm:infoStr><tm:infoStr name="Family">EnterpriseS</tm:infoStr><tm:infoStr name="productAuthor">Microsoft Corporation</tm:infoStr><tm:infoStr name="productDescription">Windows(R) Operating System</tm:infoStr><tm:infoStr name="clientIssuanceCertificateId">{4961cc30-d690-43be-910c-8e2db01fc5ad}</tm:infoStr><tm:infoStr name="hwid:ootGrace">0</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license><r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS" licenseId="{38c2c1c2-f73e-4fb2-bb44-d8a52fdcbc51}" xmlns:sx="urn:mpeg:mpeg21:2003:01-REL-SX-NS" xmlns:mx="urn:mpeg:mpeg21:2003:01-REL-MX-NS" xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2" xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><r:title>Windows(R) Publishing License (Private)</r:title><r:grant><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName="anyRight"></r:forAll><r:forAll varName="appid"></r:forAll><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>17FgQIuX2S7YIVn8PIeN+qANo4/TUbV8CH5TzbXwmWo4WVI4npVqI4NNhRVsP0ICgMpql1jgAm75dZDBPTzRTCj+Ni0DXIvk6Whlo/ClK/fpZUO3ORQ9VmBE3cXeQQAehgVlUUIzOmG4EeP1i91PCGf5O7I4ayYS2FeQUj+6hyk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><tm:decryptContent/><tm:symmetricKey><tm:AESKeyValue size="16">AAAAAAAAAAAAAAAAAAAAAA==</tm:AESKeyValue></tm:symmetricKey><r:prerequisiteRight><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>17FgQIuX2S7YIVn8PIeN+qANo4/TUbV8CH5TzbXwmWo4WVI4npVqI4NNhRVsP0ICgMpql1jgAm75dZDBPTzRTCj+Ni0DXIvk6Whlo/ClK/fpZUO3ORQ9VmBE3cXeQQAehgVlUUIzOmG4EeP1i91PCGf5O7I4ayYS2FeQUj+6hyk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:right varRef="anyRight"/><sl:appId varRef="appid"/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><RSAKeyValue><Modulus>v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:prerequisiteRight></r:grant></r:grant><r:issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.microsoft.com/xrml/lwc14n"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference><Transforms><Transform Algorithm="urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform"/><Transform Algorithm="http://www.microsoft.com/xrml/lwc14n"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>hXPflMtQRYrmAY85A44Ewqbfedo=</DigestValue></Reference></SignedInfo><SignatureValue>qOP09nDXmVv1Ne9vEruoSNoV4mzBW371vp1E+uW8jTTC9BqESCaDyK38KhFsxyjz2UqKoelnaFDBTdbVN8VTzJIQCI5sSjMjWzBP31OUHOYDLUGQO7qpRDYwcGRQPsGsQwmNbyTPgq0m4wYcEU4FRj9LIi8B8saMo9xKAO4JNOB/lS8eScHcoUJAdAOoO4MZXfaqZmT90RrMPGPUIY3uTdjtiwL0B46bRdFNYwFuItdHdTUmXOPbXVWogPScSj3JYI9yhdcxjgyb9SxknG0UID9ogTI7HirsfuMvhWkyCSGtV1N4Rr9+c2oiDpWcYeaY4cWcTuSrb+S7vhA10jaJug==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2016-01-01T00:00:00Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS"><tm:infoTables xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><tm:infoList tag="#global"><tm:infoStr name="licenseType">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name="licenseVersion">2.0</tm:infoStr><tm:infoStr name="licensorUrl">http://licensing.microsoft.com</tm:infoStr><tm:infoStr name="licenseCategory">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name="publicCertificateId">{add96a1a-5ae7-425d-935d-3b6effd43a92}</tm:infoStr><tm:infoStr name="clientIssuanceCertificateId">{4961cc30-d690-43be-910c-8e2db01fc5ad}</tm:infoStr><tm:infoStr name="hwid:ootGrace">0</tm:infoStr><tm:infoStr name="win:branding">125</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license></rg:licenseGroup>'

# construct this with elementtree if you REALLY care
ATO_REQ_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <soap:Body>
        <RequestSecurityToken
            xmlns="http://schemas.xmlsoap.org/ws/2004/04/security/trust">
            <TokenType>ProductActivation</TokenType>
            <RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType>
            <UseKey>
                <Values
                    xmlns:q1="http://schemas.xmlsoap.org/ws/2004/04/security/trust" soapenc:arrayType="q1:TokenEntry[1]">
                    <TokenEntry>
                        <Name>PublishLicense</Name>
                        <Value>{plxml}</Value>
                    </TokenEntry>
                </Values>
            </UseKey>
            <Claims>
                <Values
                    xmlns:q1="http://schemas.xmlsoap.org/ws/2004/04/security/trust" soapenc:arrayType="q1:TokenEntry[14]">
                    <TokenEntry>
                        <Name>BindingType</Name>
                        <Value>msft:rm/algorithm/hwid/4.0</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>Binding</Name>
                        <Value>{binding}</Value>
                    </TokenEntry>
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
                    <TokenEntry>
                        <Name>otherInfoPublic.licenseCategory</Name>
                        <Value>msft:sl/EUL/ACTIVATED/PUBLIC</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPrivate.licenseCategory</Name>
                        <Value>msft:sl/EUL/ACTIVATED/PRIVATE</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPublic.sysprepAction</Name>
                        <Value>rearm</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPrivate.sysprepAction</Name>
                        <Value>rearm</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ClientInformation</Name>
                        <Value>SystemUILanguageId=1033;UserUILanguageId=1033;GeoId=244</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ClientSystemTime</Name>
                        <Value>{systime}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ClientSystemTimeUtc</Name>
                        <Value>{utctime}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPublic.secureStoreId</Name>
                        <Value>{secure_store_id}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPrivate.secureStoreId</Name>
                        <Value>{secure_store_id}</Value>
                    </TokenEntry>
                </Values>
            </Claims>
        </RequestSecurityToken>
    </soap:Body>
</soap:Envelope>
"""

# construct this with elementtree if you REALLY care
PKC_REQ_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
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

def format_timestamp(dt):
    return dt.isoformat(timespec="seconds") + "Z"

def generate_binding():
    binding = unhexlify("2A0000000100020001000100000000000000010001000100")
    binding += randbytes(18)
    
    return b64encode(binding).decode()

def encode_key_data(group, serial, security, upgrade):
    act_hash = upgrade & 1
    act_hash |= (serial & ((1 << 30) - 1)) << 1
    act_hash |= (group & ((1 << 20) - 1)) << 31
    act_hash |= (security & ((1 << 53) - 1)) << 51
    
    return b64encode(act_hash.to_bytes(13, "little")).decode()

def consume_key(pkey, pl_data, pkc, config_ext="Retail"):
    if "N" not in pkey:
        return "N/A", "Product key is not PKEY2009.", False
    
    pkey_data = ProductKeyDecoder(pkey)
    
    try:
        skuid = pkc.config_for_group(pkey_data.group).config_id[1:-1]
    except:
        return "N/A", "Product key not compatible with provided pkeyconfig", False
    
    act_data = encode_key_data(pkey_data.group, pkey_data.serial, pkey_data.security, pkey_data.upgrade)
    act_config_id = f"msft2009:{skuid}&{act_data}"
    
    req_data = {
        "plxml": escape(pl_data),
        "binding": generate_binding(),
        "pkey": pkey,
        "act_config_id": escape(act_config_id),
        "systime": format_timestamp(datetime.datetime.now(datetime.UTC)),
        "utctime": format_timestamp(datetime.datetime.now(datetime.UTC)),
        "secure_store_id": str(uuid4())
    }
    payload = ATO_REQ_TEMPLATE.format(**req_data)
    
    resp = post(f"https://activation.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension={config_ext}", data=payload, verify=False, headers={
        "Accept": "text/*",
        "Content-Type": "text/xml; charset=utf-8",
        "User-Agent": "SLSSoapClient",
        "SOAPAction": "http://microsoft.com/SL/ProductActivationService/IssueToken"
    })
    
    data = ET.fromstring(resp.text)
    
    if data.find("./{*}Body/{*}Fault") is None:
        return "0x0", "", True
    else:
        return data.find("./{*}Body/{*}Fault/{*}detail/{*}HRESULT").text, data.find("./{*}Body/{*}Fault/{*}detail/{*}Messages/{*}Message").text, False

def query_key(pkey, pkc):
    if "N" not in pkey:
        return "N/A", "Product key is not PKEY2009.", False
    
    pkey_data = ProductKeyDecoder(pkey)
    
    try:
        skuid = pkc.config_for_group(pkey_data.group).config_id[1:-1]
    except:
        return "N/A", "Product key not compatible with provided pkeyconfig.", False
    
    act_data = encode_key_data(pkey_data.group, pkey_data.serial, pkey_data.security, pkey_data.upgrade)
    act_config_id = f"msft2009:{skuid}&{act_data}"
    
    req_data = {
        "pkey": pkey,
        "act_config_id": escape(act_config_id)
    }
    payload = PKC_REQ_TEMPLATE.format(**req_data)
    
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
    
    pkp = sp.add_parser("pkey", help="Test single product key")
    pkp.add_argument("product_key", type=str, help="Product key")
    
    batchp = sp.add_parser("batch", help="Test multiple product keys in a file")
    batchp.add_argument("input_file", type=argparse.FileType("r", encoding="utf-8"), help="Input file with one product key per line")
    batchp.add_argument("--out", "-o", type=argparse.FileType("w", encoding="utf-8"), nargs="?", default="out.txt", help="Output path of key checking log")
    
    p.add_argument("--pkeyconfig", "-p", type=argparse.FileType("r", encoding="utf-8-sig"), nargs="?", default="pkeyconfig.xrm-ms", help="Required pkeyconfig.xrm-ms file")
    p.add_argument("--consume", "-c", action="store_true", help="Consumes product key activation if specified")
    
    args = p.parse_args()
    
    pkc = PKeyConfig(ET.fromstring(args.pkeyconfig.read()))
    
    if args.mode == "pkey":
        pkey = args.product_key
        
        if args.consume:
            response, message, success = consume_key(pkey, PUB_LICENSE, pkc)
        else:
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
            
            if args.consume:
                response, message, success = consume_key(pkey, PUB_LICENSE, pkc)
            else:
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
