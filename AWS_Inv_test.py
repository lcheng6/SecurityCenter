import AWSInv
import sys
import json

aws_api = AWSInv.AWSInventory();

aws_api.set_aws_region('us-west-gov-1')
aws_api.aws_ec2_inventory()

aws_linux_hosts = aws_api.get_linux_hosts()