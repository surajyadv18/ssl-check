import socket
import ssl
import boto3
from datetime import datetime

# Function to get SSL expiry date
def ssl_expiry_date(domainname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=domainname,
    )
    conn.settimeout(3.0)  # 3-second timeout for Lambda runtime limits
    conn.connect((domainname, 443))
    ssl_info = conn.getpeercert()
    return datetime.strptime(ssl_info['notAfter'], ssl_date_fmt).date()

# Function to calculate remaining validity
def ssl_valid_time_remaining(domainname):
    expires = ssl_expiry_date(domainname)
    return (expires - datetime.utcnow().date()).days

# Function to send SNS alerts
def sns_Alert(dName, eDays, sslStatus):
    sslStat = f'{dName} SSL certificate will expire in {eDays} days!!'
    snsSub = f'{dName} SSL Certificate Expiry {sslStatus} alert'
    print(sslStat)
    print(snsSub)
    sns_client = boto3.client('sns')
    response = sns_client.publish(
        TargetArn="arn:aws:sns:us-east-1:293809981450:SSL-Expiry",  # Replace with your SNS ARN
        Message=sslStat,
        Subject=snsSub
    )
    return response

# Main Lambda handler
def lambda_handler(event, context):
    domains = ['www.google.com']  # Add more domains as needed
    for domain in domains:
        print(f"Checking domain: {domain}")
        try:
            days_left = ssl_valid_time_remaining(domain)
            print(f"{domain} SSL certificate expires in {days_left} days.")

            # Updated Alert thresholds
            if days_left < 30:  
                sns_Alert(domain, days_left, 'Critical')
            elif 30 <= days_left <= 46:  
                sns_Alert(domain, days_left, 'Warning')
            else: 
                print(f"SSL certificate for {domain} is fine (more than 46 days remaining).")
        except Exception as e:
            print(f"Error checking SSL for {domain}: {e}")
