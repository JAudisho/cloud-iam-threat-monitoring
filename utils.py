import boto3

def send_alert(message, topic_arn):
    sns = boto3.client("sns")
    sns.publish(TopicArn=topic_arn, Message=message, Subject="Cloud IAM Alert")
